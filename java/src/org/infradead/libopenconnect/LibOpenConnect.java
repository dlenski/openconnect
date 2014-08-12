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
 */

package org.infradead.libopenconnect;

import java.util.ArrayList;
import java.util.HashMap;

public abstract class LibOpenConnect {

	/* constants */

	public static final int OC_FORM_OPT_TEXT = 1;
	public static final int OC_FORM_OPT_PASSWORD = 2;
	public static final int OC_FORM_OPT_SELECT = 3;
	public static final int OC_FORM_OPT_HIDDEN = 4;
	public static final int OC_FORM_OPT_TOKEN = 5;

	public static final int OC_FORM_OPT_IGNORE = 0x0001;
	public static final int OC_FORM_OPT_NUMERIC = 0x0002;

	public static final int OC_TOKEN_MODE_NONE = 0;
	public static final int OC_TOKEN_MODE_STOKEN = 1;
	public static final int OC_TOKEN_MODE_TOTP = 2;

	public static final int OC_FORM_RESULT_ERR = -1;
	public static final int OC_FORM_RESULT_OK = 0;
	public static final int OC_FORM_RESULT_CANCELLED = 1;
	public static final int OC_FORM_RESULT_NEWGROUP = 2;

	public static final int PRG_ERR = 0;
	public static final int PRG_INFO = 1;
	public static final int PRG_DEBUG = 2;
	public static final int PRG_TRACE = 3;

	public static final int RECONNECT_INTERVAL_MIN = 10;
	public static final int RECONNECT_INTERVAL_MAX = 100;

	/* required callbacks */

	public abstract int onProcessAuthForm(AuthForm authForm);
	public abstract void onProgress(int level, String msg);

	/* optional callbacks */

	public int onValidatePeerCert(String msg) { return 0; }
	public int onWriteNewConfig(byte[] buf) { return 0; }
	public void onProtectSocket(int fd) { }
	public void onStatsUpdate(VPNStats stats) { }
	public int onTokenLock() { return 0; }
	public int onTokenUnlock(String newToken) { return 0; }

	/* create/destroy library instances */

	public LibOpenConnect() {
		libctx = init("OpenConnect VPN Agent (Java)");
	}

	public synchronized void destroy() {
		if (libctx != 0) {
			free();
			libctx = 0;
		}
	}

	/* async requests (safe to call from any thread) */

	public void cancel() {
		synchronized (asyncLock) {
			if (!canceled) {
				doCancel();
				canceled = true;
			}
		}
	}

	public boolean isCanceled() {
		synchronized (asyncLock) {
			return canceled;
		}
	}

	public native void pause();
	public native void requestStats();
	public native void setLogLevel(int level);

	/* control operations */

	public synchronized native int parseURL(String url);
	public synchronized native int obtainCookie();
	public synchronized native void clearCookie();
	public synchronized native void resetSSL();
	public synchronized native int makeCSTPConnection();
	public synchronized native int setupTunDevice(String vpncScript, String IFName);
	public synchronized native int setupTunScript(String tunScript);
	public synchronized native int setupTunFD(int tunFD);
	public synchronized native int setupDTLS(int attemptPeriod);
	public synchronized native int mainloop(int reconnectTimeout, int reconnectInterval);

	/* connection settings */

	public synchronized native int passphraseFromFSID();
	public synchronized native void setCertExpiryWarning(int seconds);
	public synchronized native void setDPD(int minSeconds);
	public synchronized native int setProxyAuth(String methods);
	public synchronized native int setHTTPProxy(String proxy);
	public synchronized native void setXMLSHA1(String hash);
	public synchronized native void setHostname(String hostname);
	public synchronized native void setUrlpath(String urlpath);
	public synchronized native void setCAFile(String caFile);
	public synchronized native void setReportedOS(String os);
	public synchronized native void setMobileInfo(String mobilePlatformVersion,
						      String mobileDeviceType,
						      String mobileDeviceUniqueID);
	public synchronized native int setTokenMode(int tokenMode, String tokenString);
	public synchronized native void setCSDWrapper(String wrapper, String TMPDIR, String PATH);
	public synchronized native void setXMLPost(boolean isEnabled);
	public synchronized native void setClientCert(String cert, String sslKey);
	public synchronized native void setServerCertSHA1(String hash);
	public synchronized native void setReqMTU(int mtu);
	public synchronized native void setPFS(boolean isEnabled);

	/* connection info */

	public synchronized native String getHostname();
	public synchronized native String getUrlpath();
	public synchronized native int getPort();
	public synchronized native String getCookie();
	public synchronized native String getIFName();
	public synchronized native IPInfo getIPInfo();

	/* certificate info */

	public synchronized native String getCertSHA1();
	public synchronized native String getCertDetails();
	public synchronized native byte[] getCertDER();

	/* library info */

	public static native String getVersion();
	public static native boolean hasPKCS11Support();
	public static native boolean hasTSSBlobSupport();
	public static native boolean hasStokenSupport();
	public static native boolean hasOATHSupport();

	/* public data structures */

	public static class FormOpt {
		public int type;
		public String name;
		public String label;
		public long flags;
		public ArrayList<FormChoice> choices = new ArrayList<FormChoice>();
		public String value;
		public Object userData;

		/* FormOpt internals (called from JNI) */

		void addChoice(FormChoice fc) {
			this.choices.add(fc);
		}
	};

	public static class FormChoice {
		public String name;
		public String label;
		public String authType;
		public String overrideName;
		public String overrideLabel;
		public Object userData;
	};

	public static class AuthForm {
		public String banner;
		public String message;
		public String error;
		public String authID;
		public String method;
		public String action;
		public ArrayList<FormOpt> opts = new ArrayList<FormOpt>();
		public FormOpt authgroupOpt;
		public int authgroupSelection;
		public Object userData;

		/* AuthForm internals (called from JNI) */

		FormOpt addOpt(boolean isAuthgroup) {
			FormOpt fo = new FormOpt();
			opts.add(fo);
			if (isAuthgroup) {
				authgroupOpt = fo;
			}
			return fo;
		}

		String getOptValue(String name) {
			for (FormOpt fo : opts) {
				if (fo.name.equals(name)) {
					return fo.value;
				}
			}
			return null;
		}
	}

	public static class IPInfo {
		public String addr;
		public String netmask;
		public String addr6;
		public String netmask6;
		public ArrayList<String> DNS = new ArrayList<String>();
		public ArrayList<String> NBNS = new ArrayList<String>();
		public String domain;
		public String proxyPac;
		public int MTU;

		public ArrayList<String> splitDNS = new ArrayList<String>();
		public ArrayList<String> splitIncludes = new ArrayList<String>();
		public ArrayList<String> splitExcludes = new ArrayList<String>();
		public HashMap<String,String> CSTPOptions = new HashMap<String,String>();
		public HashMap<String,String> DTLSOptions = new HashMap<String,String>();
		public Object userData;

		/* IPInfo internals (called from JNI) */

		void addDNS(String arg) { DNS.add(arg); }
		void addNBNS(String arg) { NBNS.add(arg); }
		void addSplitDNS(String arg) { splitDNS.add(arg); }
		void addSplitInclude(String arg) { splitIncludes.add(arg); }
		void addSplitExclude(String arg) { splitExcludes.add(arg); }
		void addCSTPOption(String key, String value) { CSTPOptions.put(key, value); }
		void addDTLSOption(String key, String value) { DTLSOptions.put(key, value); }
	}

	public static class VPNStats {
		public long txPkts;
		public long txBytes;
		public long rxPkts;
		public long rxBytes;
		public Object userData;
	};

	/* Optional storage for caller's data */

	public Object userData;

	/* LibOpenConnect internals */

	long libctx;
	boolean canceled = false;
	Object asyncLock = new Object();

	static synchronized native void globalInit();
	static {
		globalInit();
	}

	synchronized native long init(String useragent);
	synchronized native void free();
	native void doCancel();
}
