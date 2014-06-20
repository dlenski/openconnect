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

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#include <jni.h>
#include "openconnect.h"

struct libctx {
	JNIEnv *jenv;
	jobject jobj;
	jobject async_lock;
	struct openconnect_info *vpninfo;
	OPENCONNECT_X509 *cert;
	int cmd_fd;
	int loglevel;
};

static void throw_excep(JNIEnv *jenv, const char *exc, int line)
{
	jclass excep;
	char msg[64];

	snprintf(msg, 64, "%s:%d", __FILE__, line);

	(*jenv)->ExceptionClear(jenv);
	excep = (*jenv)->FindClass(jenv, exc);
	if (excep)
		(*jenv)->ThrowNew(jenv, excep, msg);
}

#define OOM(jenv)	do { throw_excep(jenv, "java/lang/OutOfMemoryError", __LINE__); } while (0)

static struct libctx *getctx(JNIEnv *jenv, jobject jobj)
{
	jclass jcls = (*jenv)->GetObjectClass(jenv, jobj);
	jfieldID jfld = (*jenv)->GetFieldID(jenv, jcls, "libctx", "J");
	if (!jfld)
		return NULL;
	return (void *)(unsigned long)(*jenv)->GetLongField(jenv, jobj, jfld);
}

/*
 * GetMethodID() and GetFieldID() and NewStringUTF() will automatically throw exceptions on error
 */
static jmethodID get_obj_mid(struct libctx *ctx, jobject jobj, const char *name, const char *sig)
{
	jclass jcls = (*ctx->jenv)->GetObjectClass(ctx->jenv, jobj);
	jmethodID mid = (*ctx->jenv)->GetMethodID(ctx->jenv, jcls, name, sig);
	return mid;
}

static jstring dup_to_jstring(JNIEnv *jenv, const char *in)
{
	/*
	 * Many implementations of NewStringUTF() will return NULL on
	 * NULL input, but that isn't guaranteed:
	 * http://gcc.gnu.org/bugzilla/show_bug.cgi?id=35979
	 */
	return in ? (*jenv)->NewStringUTF(jenv, in) : NULL;
}

static int dup_to_cstring(JNIEnv *jenv, jstring in, char **out)
{
	const char *tmp;

	if (in == NULL) {
		*out = NULL;
		return 0;
	}

	tmp = (*jenv)->GetStringUTFChars(jenv, in, NULL);
	if (!tmp) {
		OOM(jenv);
		return -1;
	}

	*out = strdup(tmp);
	(*jenv)->ReleaseStringUTFChars(jenv, in, tmp);

	if (!*out) {
		OOM(jenv);
		return -1;
	}
	return 0;
}

static int set_int(struct libctx *ctx, jobject jobj, const char *name, int value)
{
	jclass jcls = (*ctx->jenv)->GetObjectClass(ctx->jenv, jobj);
	jfieldID jfld = (*ctx->jenv)->GetFieldID(ctx->jenv, jcls, name, "I");

	if (!jfld)
		return -1;
	(*ctx->jenv)->SetIntField(ctx->jenv, jobj, jfld, value);
	return 0;
}

static int set_long(struct libctx *ctx, jobject jobj, const char *name, uint64_t value)
{
	jclass jcls = (*ctx->jenv)->GetObjectClass(ctx->jenv, jobj);
	jfieldID jfld = (*ctx->jenv)->GetFieldID(ctx->jenv, jcls, name, "J");

	if (!jfld)
		return -1;
	(*ctx->jenv)->SetLongField(ctx->jenv, jobj, jfld, (jlong)value);
	return 0;
}

static int set_string(struct libctx *ctx, jobject jobj, const char *name, const char *value)
{
	jclass jcls = (*ctx->jenv)->GetObjectClass(ctx->jenv, jobj);
	jfieldID jfld = (*ctx->jenv)->GetFieldID(ctx->jenv, jcls, name, "Ljava/lang/String;");
	jstring jarg;

	if (!jfld)
		return -1;

	jarg = dup_to_jstring(ctx->jenv, value);
	if (value && !jarg)
		return -1;
	(*ctx->jenv)->SetObjectField(ctx->jenv, jobj, jfld, jarg);
	return 0;
}

static int add_string(struct libctx *ctx, jclass jcls, jobject jobj,
		      const char *name, const char *value)
{
	jmethodID mid = (*ctx->jenv)->GetMethodID(ctx->jenv, jcls, name, "(Ljava/lang/String;)V");
	jstring jarg;

	if (!value)
		return 0;

	if (!mid)
		return -1;
	jarg = dup_to_jstring(ctx->jenv, value);
	if (!jarg)
		return -1;

	(*ctx->jenv)->CallVoidMethod(ctx->jenv, jobj, mid, jarg);
	(*ctx->jenv)->DeleteLocalRef(ctx->jenv, jarg);

	return 0;
}

static int add_string_pair(struct libctx *ctx, jclass jcls, jobject jobj,
		      const char *name, const char *key, const char *value)
{
	jmethodID mid = (*ctx->jenv)->GetMethodID(ctx->jenv, jcls, name, "(Ljava/lang/String;Ljava/lang/String;)V");
	jstring jarg0, jarg1;

	if (!key || !value)
		return -1;

	if (!mid)
		return -1;

	jarg0 = dup_to_jstring(ctx->jenv, key);
	if (!jarg0)
		return -1;

	jarg1 = dup_to_jstring(ctx->jenv, value);
	if (!jarg1) {
		(*ctx->jenv)->DeleteLocalRef(ctx->jenv, jarg0);
		return -1;
	}

	(*ctx->jenv)->CallVoidMethod(ctx->jenv, jobj, mid, jarg0, jarg1);

	(*ctx->jenv)->DeleteLocalRef(ctx->jenv, jarg1);
	(*ctx->jenv)->DeleteLocalRef(ctx->jenv, jarg0);

	return 0;
}

static int validate_peer_cert_cb(void *privdata, OPENCONNECT_X509 *cert, const char *reason)
{
	struct libctx *ctx = privdata;
	jstring jreason;
	int ret = -1;
	jmethodID mid;

	if ((*ctx->jenv)->PushLocalFrame(ctx->jenv, 256) < 0)
		return -1;

	jreason = dup_to_jstring(ctx->jenv, reason);
	if (!jreason)
		goto out;

	ctx->cert = cert;
	mid = get_obj_mid(ctx, ctx->jobj, "onValidatePeerCert", "(Ljava/lang/String;)I");
	if (mid)
		ret = (*ctx->jenv)->CallIntMethod(ctx->jenv, ctx->jobj, mid, jreason);

out:
	(*ctx->jenv)->PopLocalFrame(ctx->jenv, NULL);
	return ret;
}

static int write_new_config_cb(void *privdata, char *buf, int buflen)
{
	struct libctx *ctx = privdata;
	jmethodID mid;
	jbyteArray jbuf;
	int ret = -1;

	if ((*ctx->jenv)->PushLocalFrame(ctx->jenv, 256) < 0)
		return -1;

	mid = get_obj_mid(ctx, ctx->jobj, "onWriteNewConfig", "([B)I");
	if (!mid)
		goto out;

	jbuf = (*ctx->jenv)->NewByteArray(ctx->jenv, buflen);
	if (!jbuf)
		goto out;
	(*ctx->jenv)->SetByteArrayRegion(ctx->jenv, jbuf, 0, buflen, (jbyte *)buf);

	ret = (*ctx->jenv)->CallIntMethod(ctx->jenv, ctx->jobj, mid, jbuf);

out:
	(*ctx->jenv)->PopLocalFrame(ctx->jenv, NULL);
	return ret;
}

static void protect_socket_cb(void *privdata, int fd)
{
	struct libctx *ctx = privdata;
	jmethodID mid;

	if ((*ctx->jenv)->PushLocalFrame(ctx->jenv, 256) < 0)
		return;

	mid = get_obj_mid(ctx, ctx->jobj, "onProtectSocket", "(I)V");
	if (mid)
		(*ctx->jenv)->CallVoidMethod(ctx->jenv, ctx->jobj, mid, fd);

	(*ctx->jenv)->PopLocalFrame(ctx->jenv, NULL);
}

static void stats_cb(void *privdata, const struct oc_stats *stats)
{
	struct libctx *ctx = privdata;
	jmethodID mid;
	jclass jcls;
	jobject jobj = NULL;

	if ((*ctx->jenv)->PushLocalFrame(ctx->jenv, 256) < 0)
		return;

	jcls = (*ctx->jenv)->FindClass(ctx->jenv, "org/infradead/libopenconnect/LibOpenConnect$VPNStats");
	if (jcls == NULL)
		goto out;

	mid = (*ctx->jenv)->GetMethodID(ctx->jenv, jcls, "<init>", "()V");
	if (!mid)
		goto out;
	jobj = (*ctx->jenv)->NewObject(ctx->jenv, jcls, mid);
	if (!jobj)
		goto out;

	if (set_long(ctx, jobj, "txPkts", stats->tx_pkts) ||
	    set_long(ctx, jobj, "txBytes", stats->tx_bytes) ||
	    set_long(ctx, jobj, "rxPkts", stats->rx_pkts) ||
	    set_long(ctx, jobj, "rxBytes", stats->rx_bytes))
		goto out;

	mid = get_obj_mid(ctx, ctx->jobj, "onStatsUpdate",
			  "(Lorg/infradead/libopenconnect/LibOpenConnect$VPNStats;)V");
	if (mid)
		(*ctx->jenv)->CallVoidMethod(ctx->jenv, ctx->jobj, mid, jobj);

out:
	(*ctx->jenv)->PopLocalFrame(ctx->jenv, NULL);
}

static jobject new_auth_form(struct libctx *ctx, struct oc_auth_form *form)
{
	jmethodID mid;
	jclass jcls;
	jobject jobj = NULL;

	jcls = (*ctx->jenv)->FindClass(ctx->jenv, "org/infradead/libopenconnect/LibOpenConnect$AuthForm");
	if (jcls == NULL)
		return NULL;

	mid = (*ctx->jenv)->GetMethodID(ctx->jenv, jcls, "<init>", "()V");
	if (!mid)
		return NULL;
	jobj = (*ctx->jenv)->NewObject(ctx->jenv, jcls, mid);
	if (!jobj)
		return NULL;

	if (set_string(ctx, jobj, "banner", form->banner) ||
	    set_string(ctx, jobj, "message", form->message) ||
	    set_string(ctx, jobj, "error", form->error) ||
	    set_string(ctx, jobj, "authID", form->auth_id) ||
	    set_string(ctx, jobj, "method", form->method) ||
	    set_string(ctx, jobj, "action", form->action) ||
	    set_int(ctx, jobj, "authgroupSelection", form->authgroup_selection)) {
		return NULL;
	}

	return jobj;
}

static jobject new_form_choice(struct libctx *ctx, struct oc_choice *choice)
{
	jmethodID mid;
	jclass jcls;
	jobject jobj = NULL;

	jcls = (*ctx->jenv)->FindClass(ctx->jenv,
				       "org/infradead/libopenconnect/LibOpenConnect$FormChoice");
	if (jcls == NULL)
		return NULL;

	mid = (*ctx->jenv)->GetMethodID(ctx->jenv, jcls, "<init>", "()V");
	if (!mid)
		return NULL;
	jobj = (*ctx->jenv)->NewObject(ctx->jenv, jcls, mid);
	if (!jobj)
		return NULL;

	if (set_string(ctx, jobj, "name", choice->name) ||
	    set_string(ctx, jobj, "label", choice->label) ||
	    set_string(ctx, jobj, "authType", choice->auth_type) ||
	    set_string(ctx, jobj, "overrideName", choice->override_name) ||
	    set_string(ctx, jobj, "overrideLabel", choice->override_label)) {
		return NULL;
	}

	return jobj;
}

static int populate_select_choices(struct libctx *ctx, jobject jopt, struct oc_form_opt_select *opt)
{
	jmethodID mid;
	int i;

	mid = get_obj_mid(ctx, jopt, "addChoice",
			  "(Lorg/infradead/libopenconnect/LibOpenConnect$FormChoice;)V");
	if (!mid)
		return -1;

	for (i = 0; i < opt->nr_choices; i++) {
		jobject jformchoice = new_form_choice(ctx, opt->choices[i]);
		if (!jformchoice)
			return -1;
		(*ctx->jenv)->CallVoidMethod(ctx->jenv, jopt, mid, jformchoice);
	}
	return 0;
}

static int add_form_option(struct libctx *ctx, jobject jform, struct oc_form_opt *opt, int is_authgroup)
{
	jmethodID addOpt;
	jobject jopt;

	addOpt = get_obj_mid(ctx, jform, "addOpt",
		"(Z)Lorg/infradead/libopenconnect/LibOpenConnect$FormOpt;");
	if (!addOpt)
		return -1;

	jopt = (*ctx->jenv)->CallObjectMethod(ctx->jenv, jform, addOpt, is_authgroup);
	if (jopt == NULL)
		return -1;

	if (set_int(ctx, jopt, "type", opt->type) ||
	    set_string(ctx, jopt, "name", opt->name) ||
	    set_string(ctx, jopt, "label", opt->label) ||
	    set_string(ctx, jopt, "value", opt->value) ||
	    set_long(ctx, jopt, "flags", opt->flags))
		return -1;

	if (opt->type == OC_FORM_OPT_SELECT &&
	    populate_select_choices(ctx, jopt, (struct oc_form_opt_select *)opt))
		return -1;

	return 0;
}

static char *lookup_choice_name(struct oc_form_opt_select *opt, const char *name)
{
	int i;

	/* opt->value is NOT a caller-allocated string for OC_FORM_OPT_SELECT */
	for (i = 0; i < opt->nr_choices; i++)
		if (!strcmp(opt->choices[i]->name, name))
			return opt->choices[i]->name;
	return NULL;
}

static int process_auth_form_cb(void *privdata, struct oc_auth_form *form)
{
	struct libctx *ctx = privdata;
	jobject jform;
	jmethodID callback, getOptValue;
	struct oc_form_opt *opt;
	jint ret;

	if ((*ctx->jenv)->PushLocalFrame(ctx->jenv, 256) < 0)
		return -1;

	/* create and populate new AuthForm object and option/choice lists */

	jform = new_auth_form(ctx, form);
	if (!jform)
		goto err;

	getOptValue = get_obj_mid(ctx, jform, "getOptValue", "(Ljava/lang/String;)Ljava/lang/String;");
	if (!getOptValue)
		goto err;

	for (opt = form->opts; opt; opt = opt->next) {
		int is_authgroup = opt == (void *)form->authgroup_opt;
		if (add_form_option(ctx, jform, opt, is_authgroup) < 0)
			goto err;
	}

	/* invoke onProcessAuthForm callback */

	callback = get_obj_mid(ctx, ctx->jobj, "onProcessAuthForm",
			       "(Lorg/infradead/libopenconnect/LibOpenConnect$AuthForm;)I");
	if (!callback)
		goto err;

	ret = (*ctx->jenv)->CallIntMethod(ctx->jenv, ctx->jobj, callback, jform);

	/* copy any populated form fields back into the C structs */

	for (opt = form->opts; opt; opt = opt->next) {
		jstring jname, jvalue;

		jname = dup_to_jstring(ctx->jenv, opt->name);
		if (!jname)
			goto err;

		jvalue = (*ctx->jenv)->CallObjectMethod(ctx->jenv, jform, getOptValue, jname);
		if (jvalue) {
			const char *tmp = (*ctx->jenv)->GetStringUTFChars(ctx->jenv, jvalue, NULL);
			if (!tmp)
				goto err;

			if (opt->type == OC_FORM_OPT_SELECT)
				opt->value = lookup_choice_name((void *)opt, tmp);
			else {
				free(opt->value);
				opt->value = strdup(tmp);
				if (!opt->value)
					OOM(ctx->jenv);
			}
			(*ctx->jenv)->ReleaseStringUTFChars(ctx->jenv, jvalue, tmp);
		}
	}

	(*ctx->jenv)->PopLocalFrame(ctx->jenv, NULL);
	return ret;

err:
	(*ctx->jenv)->PopLocalFrame(ctx->jenv, NULL);
	return -1;
}

static void progress_cb(void *privdata, int level, const char *fmt, ...)
{
	struct libctx *ctx = privdata;
	va_list ap;
	char *msg;
	jstring jmsg;
	int ret, loglevel;
	jmethodID mid;

	(*ctx->jenv)->MonitorEnter(ctx->jenv, ctx->async_lock);
	loglevel = ctx->loglevel;
	(*ctx->jenv)->MonitorExit(ctx->jenv, ctx->async_lock);

	if (level > loglevel)
		return;

	va_start(ap, fmt);
	ret = vasprintf(&msg, fmt, ap);
	va_end(ap);

	if (ret < 0) {
		OOM(ctx->jenv);
		return;
	}

	if ((*ctx->jenv)->PushLocalFrame(ctx->jenv, 256) < 0)
		return;

	jmsg = dup_to_jstring(ctx->jenv, msg);
	free(msg);
	if (!jmsg)
		goto out;

	mid = get_obj_mid(ctx, ctx->jobj, "onProgress", "(ILjava/lang/String;)V");
	if (mid)
		(*ctx->jenv)->CallVoidMethod(ctx->jenv, ctx->jobj, mid, level, jmsg);

out:
	(*ctx->jenv)->PopLocalFrame(ctx->jenv, NULL);
}

/* Library init/uninit */

static jobject init_async_lock(struct libctx *ctx)
{
	jclass jcls = (*ctx->jenv)->GetObjectClass(ctx->jenv, ctx->jobj);
	jfieldID jfld = (*ctx->jenv)->GetFieldID(ctx->jenv, jcls, "asyncLock", "Ljava/lang/Object;");
	jobject jobj = (*ctx->jenv)->GetObjectField(ctx->jenv, ctx->jobj, jfld);

	if (jobj)
		jobj = (*ctx->jenv)->NewGlobalRef(ctx->jenv, jobj);
	return jobj;
}

JNIEXPORT jlong JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_init(
	JNIEnv *jenv, jobject jobj, jstring juseragent)
{
	char *useragent;
	struct libctx *ctx = calloc(1, sizeof(*ctx));

	if (!ctx)
		goto bad;

	ctx->jenv = jenv;
	ctx->jobj = (*jenv)->NewGlobalRef(jenv, jobj);
	if (!ctx->jobj)
		goto bad_free_ctx;
	ctx->async_lock = init_async_lock(ctx);
	if (!ctx->async_lock)
		goto bad_delete_obj_ref;

	useragent = (char *)(*jenv)->GetStringUTFChars(jenv, juseragent, NULL);
	if (!useragent)
		goto bad_delete_ref;
	ctx->vpninfo = openconnect_vpninfo_new(useragent, validate_peer_cert_cb,
					       write_new_config_cb, process_auth_form_cb,
					       progress_cb, ctx);
	(*jenv)->ReleaseStringUTFChars(jenv, juseragent, useragent);

	if (!ctx->vpninfo)
		goto bad_delete_ref;

	openconnect_set_protect_socket_handler(ctx->vpninfo, protect_socket_cb);
	openconnect_set_stats_handler(ctx->vpninfo, stats_cb);

	ctx->cmd_fd = openconnect_setup_cmd_pipe(ctx->vpninfo);
	if (ctx->cmd_fd < 0)
		goto bad_free_vpninfo;

	ctx->loglevel = PRG_DEBUG;

	return (jlong)(unsigned long)ctx;

bad_free_vpninfo:
	openconnect_vpninfo_free(ctx->vpninfo);
bad_delete_ref:
	(*jenv)->DeleteGlobalRef(jenv, ctx->async_lock);
bad_delete_obj_ref:
	(*jenv)->DeleteGlobalRef(jenv, ctx->jobj);
bad_free_ctx:
	free(ctx);
bad:
	OOM(jenv);
	return 0;
}

JNIEXPORT void JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_free(
	JNIEnv *jenv, jobject jobj)
{
	struct libctx *ctx = getctx(jenv, jobj);

	if (!ctx)
		return;
	openconnect_vpninfo_free(ctx->vpninfo);
	(*jenv)->DeleteGlobalRef(jenv, ctx->async_lock);
	(*jenv)->DeleteGlobalRef(jenv, ctx->jobj);
	free(ctx);
}

static void write_cmd_pipe(JNIEnv *jenv, jobject jobj, char cmd)
{
	struct libctx *ctx = getctx(jenv, jobj);

	if (!ctx)
		return;
	if (write(ctx->cmd_fd, &cmd, 1) < 0) {
		/* probably dead already */
	}
}

JNIEXPORT void JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_doCancel(
	JNIEnv *jenv, jobject jobj)
{
	write_cmd_pipe(jenv, jobj, OC_CMD_CANCEL);
}

JNIEXPORT void JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_pause(
	JNIEnv *jenv, jobject jobj)
{
	write_cmd_pipe(jenv, jobj, OC_CMD_PAUSE);
}

JNIEXPORT void JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_requestStats(
	JNIEnv *jenv, jobject jobj)
{
	write_cmd_pipe(jenv, jobj, OC_CMD_STATS);
}

JNIEXPORT void JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_globalInit(
	JNIEnv *jenv, jclass jcls)
{
	openconnect_init_ssl();
}

JNIEXPORT jint JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_obtainCookie(
	JNIEnv *jenv, jobject jobj)
{
	struct libctx *ctx = getctx(jenv, jobj);
	int ret;

	if (!ctx)
		return 0;
	ctx->cert = NULL;
	ret = openconnect_obtain_cookie(ctx->vpninfo);
	if (ret == 0)
		ctx->cert = openconnect_get_peer_cert(ctx->vpninfo);
	return ret;
}

/* special handling: caller-allocated buffer */
JNIEXPORT jstring JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_getCertSHA1(
	JNIEnv *jenv, jobject jobj)
{
	struct libctx *ctx = getctx(jenv, jobj);
	char buf[41];
	jstring jresult = NULL;

	if (!ctx || !ctx->cert)
		return NULL;
	if (openconnect_get_cert_sha1(ctx->vpninfo, ctx->cert, buf))
		return NULL;
	jresult = dup_to_jstring(ctx->jenv, buf);
	if (!jresult)
		OOM(ctx->jenv);
	return jresult;
}

/* special handling: callee-allocated, caller-freed string */
JNIEXPORT jstring JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_getCertDetails(
	JNIEnv *jenv, jobject jobj)
{
	struct libctx *ctx = getctx(jenv, jobj);
	char *buf = NULL;
	jstring jresult = NULL;

	if (!ctx || !ctx->cert)
		return NULL;
	buf = openconnect_get_cert_details(ctx->vpninfo, ctx->cert);
	if (!buf)
		return NULL;

	jresult = dup_to_jstring(ctx->jenv, buf);
	if (!jresult)
		OOM(ctx->jenv);

	free(buf);
	return jresult;
}

/* special handling: callee-allocated, caller-freed binary buffer */
JNIEXPORT jbyteArray JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_getCertDER(
	JNIEnv *jenv, jobject jobj)
{
	struct libctx *ctx = getctx(jenv, jobj);
	unsigned char *buf = NULL;
	int ret;
	jbyteArray jresult = NULL;

	if (!ctx || !ctx->cert)
		return NULL;
	ret = openconnect_get_cert_DER(ctx->vpninfo, ctx->cert, &buf);
	if (ret < 0)
		return NULL;

	jresult = (*ctx->jenv)->NewByteArray(ctx->jenv, ret);
	if (jresult)
		(*ctx->jenv)->SetByteArrayRegion(ctx->jenv, jresult, 0, ret, (jbyte *) buf);

	free(buf);
	return jresult;
}

/* special handling: two string arguments */
JNIEXPORT void JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_setClientCert(
	JNIEnv *jenv, jobject jobj, jstring jcert, jstring jsslkey)
{
	struct libctx *ctx = getctx(jenv, jobj);
	char *cert = NULL, *sslkey = NULL;

	if (!ctx ||
	    dup_to_cstring(ctx->jenv, jcert, &cert) ||
	    dup_to_cstring(ctx->jenv, jsslkey, &sslkey)) {
		free(cert);
		free(sslkey);
		return;
	}

	openconnect_set_client_cert(ctx->vpninfo, cert, sslkey);
}

/* special handling: multiple string arguments */
JNIEXPORT jint JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_setupTunDevice(
	JNIEnv *jenv, jobject jobj, jstring jarg0, jstring jarg1)
{
	struct libctx *ctx = getctx(jenv, jobj);
	char *arg0 = NULL, *arg1 = NULL;

	if (!ctx ||
	    dup_to_cstring(ctx->jenv, jarg0, &arg0) ||
	    dup_to_cstring(ctx->jenv, jarg1, &arg1)) {
		free(arg0);
		free(arg1);
		return -ENOMEM;
	}
	return openconnect_setup_tun_device(ctx->vpninfo, arg0, arg1);
}

JNIEXPORT void JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_setCSDWrapper(
	JNIEnv *jenv, jobject jobj, jstring jarg0, jstring jarg1, jstring jarg2)
{
	struct libctx *ctx = getctx(jenv, jobj);
	char *arg0 = NULL, *arg1 = NULL, *arg2 = NULL;

	if (!ctx ||
	    dup_to_cstring(ctx->jenv, jarg0, &arg0) ||
	    dup_to_cstring(ctx->jenv, jarg1, &arg1) ||
	    dup_to_cstring(ctx->jenv, jarg2, &arg2)) {
		free(arg0);
		free(arg1);
		free(arg2);
		return;
	}
	openconnect_setup_csd(ctx->vpninfo, getuid(), 1, arg0);

	if (arg1)
		setenv("TMPDIR", arg1, 1);
	free(arg1);

	if (arg2)
		setenv("PATH", arg2, 1);
	free(arg2);
}

JNIEXPORT void JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_setMobileInfo(
	JNIEnv *jenv, jobject jobj, jstring jarg0, jstring jarg1, jstring jarg2)
{
	struct libctx *ctx = getctx(jenv, jobj);
	char *arg0 = NULL, *arg1 = NULL, *arg2 = NULL;

	if (!ctx ||
	    dup_to_cstring(ctx->jenv, jarg0, &arg0) ||
	    dup_to_cstring(ctx->jenv, jarg1, &arg1) ||
	    dup_to_cstring(ctx->jenv, jarg2, &arg2)) {
		free(arg0);
		free(arg1);
		free(arg2);
		return;
	}
	openconnect_set_mobile_info(ctx->vpninfo, arg0, arg1, arg2);
}

/* class methods (general library info) */

JNIEXPORT jstring JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_getVersion(
	JNIEnv *jenv, jclass jcls)
{
	return dup_to_jstring(jenv, openconnect_get_version());
}

JNIEXPORT jboolean JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_hasPKCS11Support(
	JNIEnv *jenv, jclass jcls)
{
	return openconnect_has_pkcs11_support();
}

JNIEXPORT jboolean JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_hasTSSBlobSupport(
	JNIEnv *jenv, jclass jcls)
{
	return openconnect_has_tss_blob_support();
}

JNIEXPORT jboolean JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_hasStokenSupport(
	JNIEnv *jenv, jclass jcls)
{
	return openconnect_has_stoken_support();
}

JNIEXPORT jboolean JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_hasOATHSupport(
	JNIEnv *jenv, jclass jcls)
{
	return openconnect_has_oath_support();
}

/* simple cases: void or int params */

JNIEXPORT jint JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_getPort(
	JNIEnv *jenv, jobject jobj)
{
	struct libctx *ctx = getctx(jenv, jobj);

	if (!ctx)
		return -EINVAL;
	return openconnect_get_port(ctx->vpninfo);
}

JNIEXPORT jint JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_passphraseFromFSID(
	JNIEnv *jenv, jobject jobj)
{
	struct libctx *ctx = getctx(jenv, jobj);

	if (!ctx)
		return -EINVAL;
	return openconnect_passphrase_from_fsid(ctx->vpninfo);
}

JNIEXPORT void JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_clearCookie(
	JNIEnv *jenv, jobject jobj)
{
	struct libctx *ctx = getctx(jenv, jobj);

	if (!ctx)
		return;
	openconnect_clear_cookie(ctx->vpninfo);
}

JNIEXPORT void JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_resetSSL(
	JNIEnv *jenv, jobject jobj)
{
	struct libctx *ctx = getctx(jenv, jobj);

	if (!ctx)
		return;
	openconnect_reset_ssl(ctx->vpninfo);
}

JNIEXPORT void JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_setCertExpiryWarning(
	JNIEnv *jenv, jobject jobj, jint arg)
{
	struct libctx *ctx = getctx(jenv, jobj);

	if (!ctx)
		return;
	openconnect_set_cert_expiry_warning(ctx->vpninfo, arg);
}

JNIEXPORT void JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_setReqMTU(
	JNIEnv *jenv, jobject jobj, jint arg)
{
	struct libctx *ctx = getctx(jenv, jobj);

	if (!ctx)
		return;
	openconnect_set_reqmtu(ctx->vpninfo, arg);
}

JNIEXPORT void JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_setDPD(
	JNIEnv *jenv, jobject jobj, jint arg)
{
	struct libctx *ctx = getctx(jenv, jobj);

	if (!ctx)
		return;
	openconnect_set_dpd(ctx->vpninfo, arg);
}

JNIEXPORT void JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_setPFS(
	JNIEnv *jenv, jobject jobj, jboolean arg)
{
	struct libctx *ctx = getctx(jenv, jobj);

	if (!ctx)
		return;
	openconnect_set_pfs(ctx->vpninfo, arg);
}

JNIEXPORT jint JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_makeCSTPConnection(
	JNIEnv *jenv, jobject jobj)
{
	struct libctx *ctx = getctx(jenv, jobj);

	if (!ctx)
		return -EINVAL;
	return openconnect_make_cstp_connection(ctx->vpninfo);
}

JNIEXPORT jint JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_setupDTLS(
	JNIEnv *jenv, jobject jobj, jint arg)
{
	struct libctx *ctx = getctx(jenv, jobj);

	if (!ctx)
		return -EINVAL;
	return openconnect_setup_dtls(ctx->vpninfo, arg);
}

JNIEXPORT jint JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_mainloop(
	JNIEnv *jenv, jobject jobj, jint arg0, jint arg1)
{
	struct libctx *ctx = getctx(jenv, jobj);

	if (!ctx)
		return -EINVAL;
	return openconnect_mainloop(ctx->vpninfo, arg0, arg1);
}

JNIEXPORT void JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_setLogLevel(
	JNIEnv *jenv, jobject jobj, jint arg)
{
	struct libctx *ctx = getctx(jenv, jobj);

	if (!ctx)
		return;

	(*ctx->jenv)->MonitorEnter(ctx->jenv, ctx->async_lock);
	ctx->loglevel = arg;
	(*ctx->jenv)->MonitorExit(ctx->jenv, ctx->async_lock);
}

JNIEXPORT jint JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_setupTunFD(
	JNIEnv *jenv, jobject jobj, jint arg)
{
	struct libctx *ctx = getctx(jenv, jobj);

	if (!ctx)
		return -EINVAL;
	return openconnect_setup_tun_fd(ctx->vpninfo, arg);
}

JNIEXPORT void JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_setXMLPost(
	JNIEnv *jenv, jobject jobj, jboolean arg)
{
	struct libctx *ctx = getctx(jenv, jobj);

	if (!ctx)
		return;
	openconnect_set_xmlpost(ctx->vpninfo, arg);
}

/* simple cases: return a const string (no need to free it) */

#define RETURN_STRING_START \
	struct libctx *ctx = getctx(jenv, jobj); \
	const char *buf = NULL; \
	jstring jresult = NULL; \
	if (!ctx) \
		return NULL; \

#define RETURN_STRING_END \
	if (!buf) \
		return NULL; \
	jresult = dup_to_jstring(ctx->jenv, buf); \
	if (!jresult) \
		OOM(ctx->jenv); \
	return jresult;

JNIEXPORT jstring JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_getHostname(
	JNIEnv *jenv, jobject jobj)
{
	RETURN_STRING_START
	buf = openconnect_get_hostname(ctx->vpninfo);
	RETURN_STRING_END
}

JNIEXPORT jstring JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_getUrlpath(
	JNIEnv *jenv, jobject jobj)
{
	RETURN_STRING_START
	buf = openconnect_get_urlpath(ctx->vpninfo);
	RETURN_STRING_END
}

JNIEXPORT jstring JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_getCookie(
	JNIEnv *jenv, jobject jobj)
{
	RETURN_STRING_START
	buf = openconnect_get_cookie(ctx->vpninfo);
	RETURN_STRING_END
}

JNIEXPORT jstring JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_getIFName(
	JNIEnv *jenv, jobject jobj)
{
	RETURN_STRING_START
	buf = openconnect_get_ifname(ctx->vpninfo);
	RETURN_STRING_END
}

#define SET_STRING_START(ret) \
	struct libctx *ctx = getctx(jenv, jobj); \
	char *arg; \
	if (dup_to_cstring(ctx->jenv, jarg, &arg)) \
		return ret;

JNIEXPORT jint JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_parseURL(
	JNIEnv *jenv, jobject jobj, jstring jarg)
{
	int ret;
	SET_STRING_START(-ENOMEM)
	ret = openconnect_parse_url(ctx->vpninfo, arg);
	return ret;
}

JNIEXPORT jint JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_setProxyAuth(
	JNIEnv *jenv, jobject jobj, jstring jarg)
{
	int ret;
	SET_STRING_START(-ENOMEM)
	ret = openconnect_set_proxy_auth(ctx->vpninfo, arg);
	return ret;
}

JNIEXPORT jint JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_setHTTPProxy(
	JNIEnv *jenv, jobject jobj, jstring jarg)
{
	int ret;
	SET_STRING_START(-ENOMEM)
	ret = openconnect_set_http_proxy(ctx->vpninfo, arg);
	return ret;
}

JNIEXPORT void JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_setXMLSHA1(
	JNIEnv *jenv, jobject jobj, jstring jarg)
{
	SET_STRING_START()
	openconnect_set_xmlsha1(ctx->vpninfo, arg, strlen(arg) + 1);
	free(arg);
}

JNIEXPORT void JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_setHostname(
	JNIEnv *jenv, jobject jobj, jstring jarg)
{
	SET_STRING_START()
	openconnect_set_hostname(ctx->vpninfo, arg);
}

JNIEXPORT void JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_setUrlpath(
	JNIEnv *jenv, jobject jobj, jstring jarg)
{
	SET_STRING_START()
	openconnect_set_urlpath(ctx->vpninfo, arg);
}

JNIEXPORT void JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_setCAFile(
	JNIEnv *jenv, jobject jobj, jstring jarg)
{
	SET_STRING_START()
	openconnect_set_cafile(ctx->vpninfo, arg);
}

JNIEXPORT jint JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_setReportedOS(
	JNIEnv *jenv, jobject jobj, jstring jarg)
{
	SET_STRING_START(-ENOMEM)
	return openconnect_set_reported_os(ctx->vpninfo, arg);
}

JNIEXPORT jint JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_setTokenMode(
	JNIEnv *jenv, jobject jobj, jint mode, jstring jarg)
{
	int ret;
	SET_STRING_START(-ENOMEM)
	ret = openconnect_set_token_mode(ctx->vpninfo, mode, arg);
	free(arg);
	return ret;
}

JNIEXPORT jint JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_setupTunScript(
	JNIEnv *jenv, jobject jobj, jstring jarg)
{
	int ret;
	SET_STRING_START(-ENOMEM)
	ret = openconnect_setup_tun_script(ctx->vpninfo, arg);
	return ret;
}

JNIEXPORT void JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_setServerCertSHA1(
	JNIEnv *jenv, jobject jobj, jstring jarg)
{
	SET_STRING_START()
	openconnect_set_server_cert_sha1(ctx->vpninfo, arg);
}

JNIEXPORT jobject JNICALL Java_org_infradead_libopenconnect_LibOpenConnect_getIPInfo(
	JNIEnv *jenv, jobject jobj)
{
	struct libctx *ctx = getctx(jenv, jobj);
	jmethodID mid;
	jclass jcls;
	const struct oc_ip_info *ip;
	const struct oc_vpn_option *cstp, *dtls;
	struct oc_split_include *inc;
	int i;

	if (!ctx)
		return NULL;
	if (openconnect_get_ip_info(ctx->vpninfo, &ip, &cstp, &dtls) < 0)
		return NULL;
	if (!ip)
		return NULL;

	jcls = (*ctx->jenv)->FindClass(ctx->jenv,
				       "org/infradead/libopenconnect/LibOpenConnect$IPInfo");
	if (jcls == NULL)
		return NULL;

	mid = (*ctx->jenv)->GetMethodID(ctx->jenv, jcls, "<init>", "()V");
	if (!mid)
		return NULL;
	jobj = (*ctx->jenv)->NewObject(ctx->jenv, jcls, mid);
	if (!jobj)
		return NULL;

	if (set_string(ctx, jobj, "addr", ip->addr) ||
	    set_string(ctx, jobj, "netmask", ip->netmask) ||
	    set_string(ctx, jobj, "addr6", ip->addr6) ||
	    set_string(ctx, jobj, "netmask6", ip->netmask6) ||
	    set_string(ctx, jobj, "domain", ip->domain) ||
	    set_string(ctx, jobj, "proxyPac", ip->proxy_pac) ||
	    set_int(ctx, jobj, "MTU", ip->mtu))
		return NULL;

	for (i = 0; i < 3; i++) {
		if (ip->dns[i] && add_string(ctx, jcls, jobj, "addDNS", ip->dns[i]))
			return NULL;
		if (ip->nbns[i] && add_string(ctx, jcls, jobj, "addNBNS", ip->nbns[i]))
			return NULL;
	}

	for (inc = ip->split_dns; inc; inc = inc->next)
		if (add_string(ctx, jcls, jobj, "addSplitDNS", inc->route))
			return NULL;
	for (inc = ip->split_includes; inc; inc = inc->next)
		if (add_string(ctx, jcls, jobj, "addSplitInclude", inc->route))
			return NULL;
	for (inc = ip->split_excludes; inc; inc = inc->next)
		if (add_string(ctx, jcls, jobj, "addSplitExclude", inc->route))
			return NULL;

	for (; cstp; cstp = cstp->next)
		if (add_string_pair(ctx, jcls, jobj, "addCSTPOption", cstp->option, cstp->value))
			return NULL;
	for (; dtls; dtls = dtls->next)
		if (add_string_pair(ctx, jcls, jobj, "addDTLSOption", dtls->option, dtls->value))
			return NULL;

	return jobj;
}
