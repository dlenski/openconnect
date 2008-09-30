
ifdef RPM_OPT_FLAGS
CFLAGS := $(RPM_OPT_FLAGS)
else
CFLAGS := -O2 -g -Wall
endif

#M32 := -m32
#OPENSSL := /home/dwmw2/working/openssl-0.9.8f

ifdef OPENSSL
CFLAGS += -I$(OPENSSL)/include $(M32)
LDFLAGS += -lz $(OPENSSL)/libssl.so.* $(OPENSSL)/libcrypto.so.* $(M32)
else
CFLAGS += -I/usr/include/openssl $(M32)
LDFLAGS += -lssl $(M32)
endif

CFLAGS += $(shell xml2-config --cflags) 
LDFLAGS += $(shell xml2-config --libs)

OBJECTS := main.o tun.o dtls.o ssl.o mainloop.o xml.o

anyconnect: $(OBJECTS)
	$(CC) -o $@ $(LDFLAGS) $^

%.o: %.c
	$(CC) -c -o $@ $(CFLAGS) $< -MD -MF .$@.dep

clean:
	rm -f $(OBJECTS) anyconnect $(wildcard .*.o.dep)

include /dev/null $(wildcard .*.o.dep)

