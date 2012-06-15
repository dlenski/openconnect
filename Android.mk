LOCAL_PATH := $(call my-dir)


# These lists come from the same variables in Makefile.am:
openconnect_SOURCES = xml.c main.c dtls.c cstp.c mainloop.c tun.c
library_srcs = ssl.c http.c auth.c library.c compat.c
lib_srcs_openssl = openssl.c
noinst_HEADERS = openconnect-internal.h openconnect.h gnutls.h


common_SRC_FILES := $(openconnect_SOURCES) $(library_srcs) $(lib_srcs_openssl) \
	$(noinst_HEADERS) version.c

common_CFLAGS += -DANDROID -DANDROID_KEYSTORE -DIF_TUN_HDR="<linux/if_tun.h>" \
	-DDEFAULT_VPNCSCRIPT=NULL -DHAVE_ASPRINTF -DOPENCONNECT_OPENSSL

common_C_INCLUDES += \
	$(JNI_H_INCLUDE) \
	$(LOCAL_PATH)/WebKit/android/icu \
	external/ \
	external/icu4c/common \
	external/icu4c/i18n \
	external/libxml2/include \
	bionic/libc/include/ \
	external/openssl \
	external/openssl/include \
	external/openssl/crypto \
	external/zlib \
	frameworks/base/cmds/keystore

common_SHARED_LIBRARIES := libcutils \
	libz \
	libicuuc \
	libicui18n

ifneq ($(TARGET_SIMULATOR),true)
	common_SHARED_LIBRARIES += libdl
endif

# static linked binary
# =====================================================

#include $(CLEAR_VARS)
#LOCAL_SRC_FILES := $(common_SRC_FILES)
#LOCAL_CFLAGS := $(common_CFLAGS)
#LOCAL_C_INCLUDES := $(common_C_INCLUDES)
#
#LOCAL_SHARED_LIBRARIES += $(common_SHARED_LIBRARIES)
#LOCAL_STATIC_LIBRARIES:= libopenssl-static liblzo-static
#
##LOCAL_LDLIBS += -ldl
##LOCAL_PRELINK_MODULE:= false
#
#LOCAL_MODULE:= openconnect-static
#LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)
#include $(BUILD_EXECUTABLE)

# dynamic linked binary
# =====================================================

include $(CLEAR_VARS)
LOCAL_SRC_FILES := $(common_SRC_FILES)
LOCAL_CFLAGS := $(common_CFLAGS)
LOCAL_C_INCLUDES := $(common_C_INCLUDES)

LOCAL_SHARED_LIBRARIES := $(common_SHARED_LIBRARIES) libssl libcrypto libz
LOCAL_STATIC_LIBRARIES := libxml2 liblog

#LOCAL_LDLIBS += -ldl
#LOCAL_PRELINK_MODULE := false

LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := openconnect
LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)
include $(BUILD_EXECUTABLE)
