all: dtls-server dtls-client
	$(MAKE) $(MAKEFLAGS) ROLE=server dtls-server
	$(MAKE) $(MAKEFLAGS) clean
	$(MAKE) $(MAKEFLAGS) ROLE=client dtls-client

CONTIKI=../..
#CFLAGS += -DPROJECT_CONF_H=\"project-conf.h\"

WITH_UIP6=1
UIP_CONF_IPV6=1
UIP_CONF_RPL=0

ifneq ($(ROLE),client)
	CFLAGS+= -DHARD_CODED_ADDRESS=\"aaaa::02:232\"
else
	CFLAGS+= 
	CFLAGS+= -DUDP_CONNECTION_ADDR="fe80::ff:fe02:232" \
		 -DHARD_CODED_ADDRESS=\"aaaa::02:230\"
endif

CFLAGS += -ffunction-sections
LDFLAGS += -Wl,--gc-sections,--undefined=_reset_vector__,--undefined=InterruptVectors,--undefined=_copy_data_init__,--undefined=_clear_bss_init__,--undefined=_end_of_init__

CFLAGS += -DUIP_CONF_TCP=0 -DSHA2_USE_INTTYPES_H

APPS += tinydtls/aes tinydtls/sha2 tinydtls/ecc tinydtls

ccm-test: tests/ccm-test

include $(CONTIKI)/Makefile.include
