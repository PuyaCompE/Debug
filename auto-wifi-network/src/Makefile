#
# Copyright (c) 2016 Shenzhen TP-LINK Technologies Co.Ltd.
#
# Author  : Weng Kaiping <wengkaiping@tp-link.net>
# Version : 1.0
# Date    : 11 Apr, 2016
#

ifeq ($(CONFIG_PLATFORM_QCA), 1)
ifeq ($(CONFIG_DECO_WIFIHAL_SUPPORT), 1)
SRC_C = $(wildcard *.c qca/awn_wifi_handler_cfg80211_qca.c)
SRC_H = $(wildcard *.h qca/awn_wifi_handler_cfg80211_qca.h)
else
SRC_C = $(wildcard *.c qca/awn_wifi_handler_qca.c)
SRC_H = $(wildcard *.h qca/awn_wifi_handler_qca.h)
endif
else ifeq ($(CONFIG_PLATFORM_MTK), 1)
SRC_C = $(wildcard *.c mtk/*.c)
SRC_H = $(wildcard *.h mtk/*.h)
else ifeq ($(CONFIG_PLATFORM_BCM), 1)
SRC_C = $(wildcard *.c bcm/*.c)
SRC_H = $(wildcard *.h bcm/*.h)
else ifeq ($(CONFIG_PLATFORM_RTK), 1)
SRC_C = $(wildcard *.c rtk/*.c)
SRC_H = $(wildcard *.h rtk/*.h)
endif


OBJS = $(patsubst %.c,%.o,$(SRC_C))

BIN = awnd

all: $(BIN)

$(OBJS): %.o: %.c $(SRC_H)
	$(CC) $(CFLAGS)  -c -o $@ $<

$(BIN): $(OBJS)
	$(CC) $(LDFLAGS)  -o $@ $^

clean:
	rm $(OBJS) $(BIN)
