/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2013 Kevin Cernekee <cernekee@gmail.com>
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

package com.example;

import java.io.*;
import java.util.*;
import org.infradead.libopenconnect.LibOpenConnect;

public final class LibTest {

	private static void die(String msg) {
		System.out.println(msg);
		System.exit(1);
	}

	private static String getline() {
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		try {
			String line = br.readLine();
			return line;
		} catch (IOException e) {
			die("\nI/O error");
		}
		return "";
	}

	private static class TestLib extends LibOpenConnect {
		@Override
		public int onValidatePeerCert(String msg) {
			System.out.println("cert warning: " + msg);
			System.out.println("cert SHA1: " + getCertSHA1());
			System.out.println("cert details: " + getCertDetails());

			byte der[] = getCertDER();
			System.out.println("DER is " + der.length + " bytes long");

			System.out.print("\nAccept this certificate? [n] ");
			String s = getline();
			if (s.startsWith("y") || s.startsWith("Y")) {
				return 0;
			} else {
				return -1;
			}
		}

		@Override
		public int onWriteNewConfig(byte[] buf) {
			System.out.println("NEW_CONFIG: " + buf.length + " bytes");
			return 0;
		}

		@Override
		public void onProtectSocket(int fd) {
			System.out.println("PROTECT_FD: " + fd);
		}

		private void printChoices(FormOpt fo) {
			for (FormChoice fc : fo.choices) {
				System.out.println("--->FormChoice: ");
				System.out.println("    +-name: " + fc.name);
				System.out.println("    +-label: " + fc.label);
				System.out.println("    +-authType: " + fc.authType);
				System.out.println("    +-overrideName: " + fc.overrideName);
				System.out.println("    +-overrideLabel: " + fc.overrideLabel);
			}
		}

		private String authgroup;
		private boolean lastFormEmpty;

		@Override
		public int onProcessAuthForm(LibOpenConnect.AuthForm authForm) {
			boolean empty = true;

			System.out.println("\nAuthForm:");
			System.out.println("+-banner: " + authForm.banner);
			System.out.println("+-message: " + authForm.message);
			System.out.println("+-error: " + authForm.error);
			System.out.println("+-authID: " + authForm.authID);
			System.out.println("+-method: " + authForm.method);
			System.out.println("+-action: " + authForm.action);

			if (authgroup == null && authForm.authgroupOpt != null) {
				FormOpt fo = authForm.authgroupOpt;

				printChoices(fo);
				System.out.print("\n" + fo.label + " ");
				String value = getline();
				fo.value = value;
				authgroup = value;
				return OC_FORM_RESULT_NEWGROUP;
			}

			for (FormOpt fo : authForm.opts) {
				System.out.println("->FormOpt: ");
				System.out.println("  +-type: " + fo.type);
				System.out.println("  +-name: " + fo.name);
				System.out.println("  +-label: " + fo.label);
				System.out.println("  +-flags: " + fo.flags);

				if ((fo.flags & OC_FORM_OPT_IGNORE) != 0) {
					continue;
				}

				if (fo.type == OC_FORM_OPT_SELECT) {
					if (fo == authForm.authgroupOpt && authgroup != null) {
						fo.value = authgroup;
						continue;
					}
					printChoices(fo);
				}

				if (fo.type == OC_FORM_OPT_TEXT ||
				    fo.type == OC_FORM_OPT_PASSWORD ||
				    fo.type == OC_FORM_OPT_SELECT) {
					System.out.print("\n" + fo.label + " ");
					String value = getline();
					fo.value = value;
					empty = false;
				}
			}
			System.out.println("");

			if (lastFormEmpty && empty) {
				return OC_FORM_RESULT_CANCELLED;
			}
			lastFormEmpty = empty;

			return OC_FORM_RESULT_OK;
		}

		@Override
		public void onProgress(int level, String msg) {
			switch (level) {
			case LibOpenConnect.PRG_TRACE:
				System.out.print("TRACE: " + msg);
				break;
			case LibOpenConnect.PRG_DEBUG:
				System.out.print("DEBUG: " + msg);
				break;
			case LibOpenConnect.PRG_INFO:
				System.out.print("INFO:  " + msg);
				break;
			case LibOpenConnect.PRG_ERR:
				System.out.print("ERROR: " + msg);
				break;
			}
		}
	}

	private static void printList(String pfx, List<String> ss) {
		System.out.print(pfx + ":");

		if (ss.size() == 0) {
			System.out.println(" <empty>");
			return;
		}
		for (String s : ss) {
			System.out.print(" " + s);
		}
		System.out.println("");
	}

	private static void printIPInfo(LibOpenConnect.IPInfo ip) {
		System.out.println("\nIPInfo:");
		System.out.println("+-IPv4: " + ip.addr + " / " + ip.netmask);
		System.out.println("+-IPv6: " + ip.addr6 + " / " + ip.netmask6);
		System.out.println("+-Domain: " + ip.domain);
		System.out.println("+-proxy.pac: " + ip.proxyPac);
		System.out.println("+-MTU: " + ip.MTU);
		printList("+-DNS", ip.DNS);
		printList("+-NBNS", ip.NBNS);
		printList("+-Split DNS", ip.splitDNS);
		printList("+-Split includes", ip.splitIncludes);
		printList("+-Split excludes", ip.splitExcludes);
		System.out.println("");
	}

	public static void main(String argv[]) {
		System.loadLibrary("openconnect-wrapper");
		LibOpenConnect lib = new TestLib();

		if (argv.length != 1)
			die("usage: LibTest <server_name>");

		System.out.println("OpenConnect version: " + lib.getVersion());
		System.out.println("  PKCS=" + lib.hasPKCS11Support() +
				   ", TSS=" + lib.hasTSSBlobSupport() +
				   ", STOKEN=" + lib.hasStokenSupport() +
				   ", OATH=" + lib.hasOATHSupport());
		lib.setReportedOS("win");
		lib.setLogLevel(lib.PRG_DEBUG);
		//lib.setTokenMode(LibOpenConnect.OC_TOKEN_MODE_STOKEN, null);
		if (new File("csd.sh").exists()) {
			lib.setCSDWrapper("csd.sh", null, null);
		}
		lib.parseURL(argv[0]);

		int ret = lib.obtainCookie();
		if (ret < 0)
			die("obtainCookie() returned error");
		else if (ret > 0)
			die("Aborted by user");

		String cookie = lib.getCookie();
		if (cookie.length() > 40) {
			System.out.println("Cookie: " + cookie.substring(0, 40) + "...");
		} else {
			System.out.println("Cookie: " + cookie);
		}

		if (lib.makeCSTPConnection() != 0)
			die("Error establishing VPN link");

		printIPInfo(lib.getIPInfo());

		if (lib.setupTunDevice("/etc/vpnc/vpnc-script", null) != 0 &&
		    lib.setupTunScript("ocproxy") != 0)
			die("Error setting up tunnel");

		if (lib.setupDTLS(60) != 0)
			die("Error setting up DTLS");

		lib.mainloop(300, LibOpenConnect.RECONNECT_INTERVAL_MIN);
	}
}
