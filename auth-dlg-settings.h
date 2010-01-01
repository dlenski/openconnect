/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2010 Intel Corporation.
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
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to:
 *
 *   Free Software Foundation, Inc.
 *   51 Franklin Street, Fifth Floor,
 *   Boston, MA 02110-1301 USA
 */
#ifndef __OPENCONNECT_AUTH_DLG_SETTINGS_H
#define __OPENCONNECT_AUTH_DLG_SETTINGS_H

#define NM_DBUS_SERVICE_OPENCONNECT    "org.freedesktop.NetworkManager.openconnect"
#define NM_DBUS_INTERFACE_OPENCONNECT  "org.freedesktop.NetworkManager.openconnect"
#define NM_DBUS_PATH_OPENCONNECT       "/org/freedesktop/NetworkManager/openconnect"

#define NM_OPENCONNECT_KEY_GATEWAY "gateway"
#define NM_OPENCONNECT_KEY_COOKIE "cookie"
#define NM_OPENCONNECT_KEY_GWCERT "gwcert"
#define NM_OPENCONNECT_KEY_AUTHTYPE "authtype"
#define NM_OPENCONNECT_KEY_USERCERT "usercert"
#define NM_OPENCONNECT_KEY_CACERT "cacert"
#define NM_OPENCONNECT_KEY_PRIVKEY "userkey"
#define NM_OPENCONNECT_KEY_USERNAME "username"
#define NM_OPENCONNECT_KEY_XMLCONFIG "xmlconfig"

#define NM_OPENCONNECT_AUTHTYPE_CERT "cert"
#define NM_OPENCONNECT_AUTHTYPE_CERT_TPM "cert-tpm"
#define NM_OPENCONNECT_AUTHTYPE_PASSWORD "password"

#endif /* __OPENCONNECT_AUTH_DLG_SETTINGS_H */
