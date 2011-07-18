LOCAL_PATH := $(call my-dir)


# This list comes from the following variables in the normal Makefile.am:
# $(openconnect_SOURCES) $(libopenconnect_la_SOURCES) $(noinst_HEADERS)
common_SRC_FILES := \
	xml.c main.c dtls.c cstp.c mainloop.c tun.c \
	ssl.c http.c version.c auth.c library.c \
	openconnect-internal.h openconnect.h

common_CFLAGS += -DANDROID -DIF_TUN_HDR="<linux/if_tun.h>"

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
