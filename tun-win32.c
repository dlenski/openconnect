/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2015 Intel Corporation.
 *
 * Author: David Woodhouse <dwmw2@infradead.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include <config.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
#include <iphlpapi.h>

#include <errno.h>
#include <stdio.h>

#include <openconnect-internal.h>

/*
 * TAP-Windows support inspired by http://i3.cs.berkeley.edu/ with
 * permission.
 */
#define _TAP_IOCTL(nr) CTL_CODE(FILE_DEVICE_UNKNOWN, nr, METHOD_BUFFERED, \
				FILE_ANY_ACCESS)

#define TAP_IOCTL_GET_MAC               _TAP_IOCTL(1)
#define TAP_IOCTL_GET_VERSION           _TAP_IOCTL(2)
#define TAP_IOCTL_GET_MTU               _TAP_IOCTL(3)
#define TAP_IOCTL_GET_INFO              _TAP_IOCTL(4)
#define TAP_IOCTL_CONFIG_POINT_TO_POINT _TAP_IOCTL(5)
#define TAP_IOCTL_SET_MEDIA_STATUS      _TAP_IOCTL(6)
#define TAP_IOCTL_CONFIG_DHCP_MASQ      _TAP_IOCTL(7)
#define TAP_IOCTL_GET_LOG_LINE          _TAP_IOCTL(8)
#define TAP_IOCTL_CONFIG_DHCP_SET_OPT   _TAP_IOCTL(9)
#define TAP_IOCTL_CONFIG_TUN            _TAP_IOCTL(10)

#define TAP_COMPONENT_ID "tap0901"

#define DEVTEMPLATE "\\\\.\\Global\\%s.tap"

#define NETDEV_GUID "{4D36E972-E325-11CE-BFC1-08002BE10318}"
#define CONTROL_KEY "SYSTEM\\CurrentControlSet\\Control\\"

#define ADAPTERS_KEY CONTROL_KEY "Class\\" NETDEV_GUID
#define CONNECTIONS_KEY CONTROL_KEY "Network\\" NETDEV_GUID

typedef intptr_t (tap_callback)(struct openconnect_info *vpninfo, char *idx, char *name);

static intptr_t search_taps(struct openconnect_info *vpninfo, tap_callback *cb, int all)
{
	LONG status;
	HKEY adapters_key, hkey;
	DWORD len, type;
	char buf[40];
	wchar_t name[40];
	char keyname[strlen(CONNECTIONS_KEY) + sizeof(buf) + 1 + strlen("\\Connection")];
	int i = 0, found = 0;
	intptr_t ret = -1;
	struct oc_text_buf *namebuf = buf_alloc();

	status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, ADAPTERS_KEY, 0,
			       KEY_READ, &adapters_key);
	if (status) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error accessing registry key for network adapters\n"));
		return -EIO;
	}
	while (1) {
		len = sizeof(buf);
		status = RegEnumKeyExA(adapters_key, i++, buf, &len,
				       NULL, NULL, NULL, NULL);
		if (status) {
			if (status != ERROR_NO_MORE_ITEMS)
				ret = -1;
			break;
		}

		snprintf(keyname, sizeof(keyname), "%s\\%s",
			 ADAPTERS_KEY, buf);

		status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, keyname, 0,
				       KEY_QUERY_VALUE, &hkey);
		if (status)
			continue;

		len = sizeof(buf);
		status = RegQueryValueExA(hkey, "ComponentId", NULL, &type,
					  (unsigned char *)buf, &len);
		if (status || type != REG_SZ || strcmp(buf, TAP_COMPONENT_ID)) {
			RegCloseKey(hkey);
			continue;
		}

		len = sizeof(buf);
		status = RegQueryValueExA(hkey, "NetCfgInstanceId", NULL,
					  &type, (unsigned char *)buf, &len);
		RegCloseKey(hkey);
		if (status || type != REG_SZ)
			continue;

		snprintf(keyname, sizeof(keyname), "%s\\%s\\Connection",
			 CONNECTIONS_KEY, buf);

		status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, keyname, 0,
				       KEY_QUERY_VALUE, &hkey);
		if (status)
			continue;

		len = sizeof(name);
		status = RegQueryValueExW(hkey, L"Name", NULL, &type,
					 (unsigned char *)name, &len);
		RegCloseKey(hkey);
		if (status || type != REG_SZ)
			continue;

		buf_truncate(namebuf);
		buf_append_from_utf16le(namebuf, name);
		if (buf_error(namebuf)) {
			ret = buf_free(namebuf);
			namebuf = NULL;
			break;
		}

		found++;

		if (vpninfo->ifname && strcmp(namebuf->data, vpninfo->ifname)) {
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Ignoring non-matching TAP interface \"%s\"\n"),
				     namebuf->data);
			continue;
		}

		ret = cb(vpninfo, buf, namebuf->data);
		if (!all)
			break;
	}

	RegCloseKey(adapters_key);
	buf_free(namebuf);

	if (!found)
		vpn_progress(vpninfo, PRG_ERR,
			     _("No Windows-TAP adapters found. Is the driver installed?\n"));

	return ret;
}

static int get_adapter_index(struct openconnect_info *vpninfo, char *guid)
{
	struct oc_text_buf *buf = buf_alloc();
	IP_ADAPTER_INFO *adapter;
	void *adapters_buf;
	ULONG idx;
	DWORD status;
	int ret = -EINVAL;

	vpninfo->tun_idx = -1;

	buf_append_utf16le(buf, "\\device\\tcpip_");
	buf_append_utf16le(buf, guid);
	if (buf_error(buf)) {
		/* If we didn't manage to malloc for this, we're never
		 * going to manage for GetAdaptersInfo(). Give up. */
		return buf_free(buf);
	}

	status = GetAdapterIndex((void *)buf->data, &idx);
	buf_free(buf);
	if (status == NO_ERROR) {
		vpninfo->tun_idx = idx;
		return 0;
	} else {
		char *errstr = openconnect__win32_strerror(status);
		vpn_progress(vpninfo, PRG_INFO,
			     _("GetAdapterIndex() failed: %s\nFalling back to GetAdaptersInfo()\n"),
			     errstr);
		free(errstr);
	}
	idx = 0;
	status = GetAdaptersInfo(NULL, &idx);
	if (status != ERROR_BUFFER_OVERFLOW)
		return -EIO;
	adapters_buf = malloc(idx);
	if (!adapters_buf)
		return -ENOMEM;
	status = GetAdaptersInfo(adapters_buf, &idx);
	if (status != NO_ERROR) {
		char *errstr = openconnect__win32_strerror(status);
		vpn_progress(vpninfo, PRG_ERR, _("GetAdaptersInfo() failed: %s\n"), errstr);
		free(errstr);
		free(adapters_buf);
		return -EIO;
	}

	for (adapter = adapters_buf; adapter; adapter = adapter->Next) {
		if (!strcmp(adapter->AdapterName, guid)) {
			vpninfo->tun_idx = adapter->Index;
			ret = 0;
			break;
		}
	}

	free(adapters_buf);
	return ret;
}

static intptr_t open_tun(struct openconnect_info *vpninfo, char *guid, char *name)
{
	char devname[80];
	HANDLE tun_fh;
	ULONG data[3];
	DWORD len;

	snprintf(devname, sizeof(devname), DEVTEMPLATE, guid);
	tun_fh = CreateFileA(devname, GENERIC_WRITE|GENERIC_READ, 0, 0,
			     OPEN_EXISTING,
			     FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
			     0);
	if (tun_fh == INVALID_HANDLE_VALUE) {
		vpn_progress(vpninfo, PRG_ERR, _("Failed to open %s\n"),
			     devname);
		return -1;

	}
	vpn_progress(vpninfo, PRG_DEBUG, _("Opened tun device %s\n"), name);

	if (!DeviceIoControl(tun_fh, TAP_IOCTL_GET_VERSION,
			     data, sizeof(&data), data, sizeof(data),
			     &len, NULL)) {
		char *errstr = openconnect__win32_strerror(GetLastError());

		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to obtain TAP driver version: %s\n"), errstr);
		free(errstr);
		return -1;
	}
	if (data[0] < 9 || (data[0] == 9 && data[1] < 9)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error: TAP-Windows driver v9.9 or greater is required (found %ld.%ld)\n"),
			     data[0], data[1]);
		return -1;
	}
	vpn_progress(vpninfo, PRG_DEBUG, "TAP-Windows driver v%ld.%ld (%ld)\n",
		     data[0], data[1], data[2]);

	data[0] = inet_addr(vpninfo->ip_info.addr);
	/* Set network and mask both to 0.0.0.0. It's not about routing;
	 * it just ensures that the TAP driver fakes ARP responses for
	 * *everything* we throw at it, and we can just configure them
	 * as on-link routes. */
	data[1] = 0;
	data[2] = 0;

	if (!DeviceIoControl(tun_fh, TAP_IOCTL_CONFIG_TUN,
			     data, sizeof(data), data, sizeof(data),
			     &len, NULL)) {
		char *errstr = openconnect__win32_strerror(GetLastError());

		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to set TAP IP addresses: %s\n"), errstr);
		free(errstr);
		return -1;
	}

	data[0] = 1;
	if (!DeviceIoControl(tun_fh, TAP_IOCTL_SET_MEDIA_STATUS,
			     data, sizeof(data[0]), data, sizeof(data[0]),
			     &len, NULL)) {
		char *errstr = openconnect__win32_strerror(GetLastError());

		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to set TAP media status: %s\n"), errstr);
		free(errstr);
		return -1;
	}

	if (!vpninfo->ifname)
		vpninfo->ifname = strdup(name);

	get_adapter_index(vpninfo, guid);

	return (intptr_t)tun_fh;
}

intptr_t os_setup_tun(struct openconnect_info *vpninfo)
{
	return search_taps(vpninfo, open_tun, 0);
}

int os_read_tun(struct openconnect_info *vpninfo, struct pkt *pkt)
{
	DWORD pkt_size;

 reread:
	if (!vpninfo->tun_rd_pending &&
	    !ReadFile(vpninfo->tun_fh, pkt->data, pkt->len, &pkt_size,
		      &vpninfo->tun_rd_overlap)) {
		DWORD err = GetLastError();

		if (err == ERROR_IO_PENDING)
			vpninfo->tun_rd_pending = 1;
		else if (err == ERROR_OPERATION_ABORTED) {
			vpninfo->quit_reason = "TAP device aborted";
			vpn_progress(vpninfo, PRG_ERR,
				     _("TAP device aborted connectivity. Disconnecting.\n"));
			return -1;
		} else {
			char *errstr = openconnect__win32_strerror(err);
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to read from TAP device: %s\n"),
				     errstr);
			free(errstr);
		}
		return -1;
	} else if (!GetOverlappedResult(vpninfo->tun_fh,
					&vpninfo->tun_rd_overlap, &pkt_size,
					FALSE)) {
		DWORD err = GetLastError();

		if (err != ERROR_IO_INCOMPLETE) {
			char *errstr = openconnect__win32_strerror(err);
			vpninfo->tun_rd_pending = 0;
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to complete read from TAP device: %s\n"),
				     errstr);
			free(errstr);
			goto reread;
		}
		return -1;
	}

	/* Either a straight ReadFile() or a subsequent GetOverlappedResult()
	   succeeded... */
	vpninfo->tun_rd_pending = 0;
	pkt->len = pkt_size;
	return 0;
}

int os_write_tun(struct openconnect_info *vpninfo, struct pkt *pkt)
{
	DWORD pkt_size = 0;
	DWORD err;
	char *errstr;

	if (WriteFile(vpninfo->tun_fh, pkt->data, pkt->len, &pkt_size, &vpninfo->tun_wr_overlap)) {
		vpn_progress(vpninfo, PRG_TRACE,
			     _("Wrote %ld bytes to tun\n"), pkt_size);
		return 0;
	}

	err = GetLastError();
	if (err == ERROR_IO_PENDING) {
		/* Theoretically we should let the mainloop handle this blocking,
		   but that's non-trivial and it doesn't ever seem to happen in
		   practice anyway. */
		vpn_progress(vpninfo, PRG_TRACE,
			     _("Waiting for tun write...\n"));
		if (GetOverlappedResult(vpninfo->tun_fh, &vpninfo->tun_wr_overlap, &pkt_size, TRUE)) {
			vpn_progress(vpninfo, PRG_TRACE,
				     _("Wrote %ld bytes to tun after waiting\n"), pkt_size);
			return 0;
		}
		err = GetLastError();
	}
	errstr = openconnect__win32_strerror(err);
	vpn_progress(vpninfo, PRG_ERR,
		     _("Failed to write to TAP device: %s\n"), errstr);
	free(errstr);
	return -1;
}

void os_shutdown_tun(struct openconnect_info *vpninfo)
{
	script_config_tun(vpninfo, "disconnect");
	CloseHandle(vpninfo->tun_fh);
	vpninfo->tun_fh = NULL;
	CloseHandle(vpninfo->tun_rd_overlap.hEvent);
	vpninfo->tun_rd_overlap.hEvent = NULL;
}

int openconnect_setup_tun_fd(struct openconnect_info *vpninfo, intptr_t tun_fd)
{
	ULONG data;
	DWORD len;

	/* Toggle media status so that network location awareness picks up all the configuration
	   that occurred and properly assigns the network so the user can adjust firewall
	   settings. */
	for (data = 0; data <= 1; data++) {
		if (!DeviceIoControl((HANDLE)tun_fd, TAP_IOCTL_SET_MEDIA_STATUS,
					&data, sizeof(data), &data, sizeof(data), &len, NULL)) {
			char *errstr = openconnect__win32_strerror(GetLastError());

			vpn_progress(vpninfo, PRG_ERR,
					_("Failed to set TAP media status: %s\n"), errstr);
			free(errstr);
			return -1;
		}
	}

	vpninfo->tun_fh = (HANDLE)tun_fd;
	vpninfo->tun_rd_overlap.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	monitor_read_fd(vpninfo, tun);

	return 0;
}

int openconnect_setup_tun_script(struct openconnect_info *vpninfo,
				 const char *tun_script)
{
	vpn_progress(vpninfo, PRG_ERR,
		     _("Spawning tunnel scripts is not yet supported on Windows\n"));
	return -1;
}
