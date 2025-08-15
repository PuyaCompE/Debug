#
# Copyright (c) 2016 Shenzhen TP-LINK Technologies Co.Ltd.
#
# Author  : Weng Kaiping <wengkaiping@tp-link.net>
# Version : 1.0
# Date    : 11 Apr, 2016
#

include $(TOPDIR)/rules.mk

PKG_NAME:=auto-wifi-network
PKG_VERSION:=1.0

include $(INCLUDE_DIR)/package.mk


TARGET_CFLAGS += -std=gnu99
TARGET_CFLAGS += -I./include/ -I./ipc/
TARGET_CFLAGS += -I$(STAGING_DIR)/usr/include/
TARGET_CFLAGS += -I$(STAGING_DIR)/usr/include/json-c
TARGET_CFLAGS += -I$(STAGING_DIR)/usr/include/libubox
TARGET_CFLAGS += -I$(STAGING_DIR)/usr/include/libplcapi

ifeq ($(CONFIG_AWN_MESH_OPT_SUPPORT), y)
TARGET_CFLAGS += -I$(STAGING_DIR)/usr/include/libaimsg
TARGET_CFLAGS += -I$(STAGING_DIR)/usr/include/libaialg
endif

TARGET_CFLAGS += -DCONFIG_CONF_METHOD=1
TARGET_CFLAGS += -DATH_SUPPORT_TP_IE=1

ifeq ($(CONFIG_QTL_RG650V), y)
TARGET_CFLAGS += -DONLY_DECO_SUPPORT=1
TARGET_CFLAGS += -DQCA_SUPPORT_SON=1
TARGET_CFLAGS += -DDECO_WHITELIST_SUPPORT
endif

ifeq ($(CONFIG_M_EU_VERSION), y)
	TARGET_CFLAGS += -DCONFIG_M_EU_VERSION=1
else
	TARGET_CFLAGS += -DCONFIG_M_EU_VERSION=0
endif

ifeq ($(CONFIG_ETH_WLAN_BACKHAUL_SUPPORT), y)
	TARGET_CFLAGS += -DCONFIG_ETH_WLAN_BACKHAUL_SUPPORT=1
endif

ifeq ($(CONFIG_PRODUCT_PLC_SGMAC), y)
	TARGET_CFLAGS += -DCONFIG_PRODUCT_PLC_SGMAC=1
endif

ifeq ($(CONFIG_PRODUCT_IS_QCA_AX_HIGH), y)
	TARGET_CFLAGS += -DCONFIG_PRODUCT_IS_QCA_AX_HIGH=1
endif

ifeq ($(CONFIG_PRODUCT_IS_QCA_RCAC_CTRL), y)
	TARGET_CFLAGS += -DCONFIG_PRODUCT_IS_QCA_RCAC_CTRL=1
endif

ifeq ($(CONFIG_AWN_WAIT_FOR_WIRED_NETWORK), y)
	TARGET_CFLAGS += -DCONFIG_AWN_WAIT_FOR_WIRED_NETWORK=1
endif

ifeq ($(CONFIG_AWN_SET_FAPMAC_TO_DRIVER), y)
	TARGET_CFLAGS += -DCONFIG_AWN_SET_FAPMAC_TO_DRIVER=1
endif

ifeq ($(CONFIG_AWN_QCA_WLAN_VDEV_STATE), y)
	TARGET_CFLAGS += -DCONFIG_AWN_QCA_WLAN_VDEV_STATE=1
endif

ifeq ($(CONFIG_AWN_QCA_6G_BACKHATL_ADAPTIVE), y)
	TARGET_CFLAGS += -DCONFIG_AWN_QCA_6G_BACKHATL_ADAPTIVE=1
endif

ifeq ($(CONFIG_5G_HT160_SUPPORT), y)
	TARGET_CFLAGS += -DCONFIG_5G_HT160_SUPPORT=1
endif

ifeq ($(CONFIG_5G2_BAND3_BAND4_SUPPORT), y)
	TARGET_CFLAGS += -DCONFIG_5G2_BAND3_BAND4_SUPPORT=1
endif

ifeq ($(CONFIG_WIFI_HOSTAPD_SUPPORT), y)
	TARGET_CFLAGS += -DCONFIG_WIFI_HOSTAPD_SUPPORT=1
endif

ifeq ($(CONFIG_RE_RESTORE_STA_CONFIG), y)
	TARGET_CFLAGS += -DCONFIG_RE_RESTORE_STA_CONFIG=1
endif

ifeq ($(CONFIG_IPF_PLATFORM_QCA), y)
	TARGET_CFLAGS += -DCONFIG_PLATFORM_QCA=1
	AWN_MAKEOPT += CONFIG_PLATFORM_QCA=1
	TARGET_CFLAGS += -DFAST_RECONNECT_ROOTAP=1
else ifeq ($(CONFIG_IPF_PLATFORM_MTK), y)
	TARGET_CFLAGS += -DCONFIG_PLATFORM_MTK=1
	TARGET_CFLAGS += -DGET_AP_RSSI=1
	AWN_MAKEOPT += CONFIG_PLATFORM_MTK=1
	TARGET_CFLAGS += -DFAST_RECONNECT_ROOTAP=1
ifeq ($(CONFIG_USE_SDK_NL_TINY),y)
	TARGET_CFLAGS += -D_GNU_SOURCE
	TARGET_CFLAGS += -DMTK_NETLINK_SUPPORT
	TARGET_CFLAGS += -I$(SDK_STAGING_DIR)/usr/include/libnl-tiny
	TARGET_LDFLAGS += -L$(SDK_STAGING_DIR)/usr/lib -lnl-tiny
	TARGET_CFLAGS += -I$(SDK_ROOT_DIR)/target/linux/linux-$(KERNELVERSION)/include/uapi/linux/mtk_nl80211_inc
endif
else ifeq ($(CONFIG_IPF_PLATFORM_BCM), y)
	TARGET_CFLAGS += -DCONFIG_PLATFORM_BCM=1
	AWN_MAKEOPT += CONFIG_PLATFORM_BCM=1
	TARGET_CFLAGS += -DSCAN_OPTIMIZATION=1
	TARGET_CFLAGS += -DFAST_RECONNECT_ROOTAP=1

ifeq ($(CONFIG_AWN_BCM_USE_WL_INCLUDE_FILE), y)
	SDK_WL_DIR = $(SDK_ROOT_DIR)/bcmdrivers/broadcom/net/wl/impl$(CONFIG_BCM_WLIMPL)/main
	INC1 = src/include
	INC2 = src/shared/bcmwifi/include
	INC3 = components/router/shared
	INC4 = components/wlioctl/include/
	INC5 = components/proto/include/
	TARGET_CFLAGS += -DTP_AWN -DTPIE
	TARGET_CFLAGS += -I$(SDK_WL_DIR)/$(INC1) -I$(SDK_WL_DIR)/$(INC2) -I$(SDK_WL_DIR)/$(INC3)  -I$(SDK_WL_DIR)/$(INC4) -I$(SDK_WL_DIR)/$(INC5)
endif

else ifeq ($(CONFIG_IPF_PLATFORM_RTK), y)
	TARGET_CFLAGS += -DCONFIG_PLATFORM_RTK=1
	TARGET_CFLAGS += -DGET_AP_RSSI=1
	TARGET_CFLAGS += -I./rtk/wpa_ctrl -I./rtk -I. -DCONFIG_CTRL_IFACE -DCONFIG_CTRL_IFACE_UNIX
	#TARGET_CFLAGS += -Werror
	TARGET_CFLAGS += -I$(TOPDIR)/../rtl8198/lib/libnl-1.1.4/include
	TARGET_LDFLAGS += -L$(TOPDIR)/../rtl8198/lib/libnl-1.1.4/lib
	TARGET_LDFLAGS += -lnl
	TARGET_CFLAGS += -I$(STAGING_DIR)/usr/include/libwpa_ctrl
	TARGET_LDFLAGS += -lwpa_ctrl
	AWN_MAKEOPT += CONFIG_PLATFORM_RTK=1
endif

ifeq ($(CONFIG_TP_SWITCH_E4V3), y)
       TARGET_CFLAGS += -DCONFIG_TP_SWITCH_E4V3=1
else
       TARGET_CFLAGS += -DCONFIG_TP_SWITCH_E4V3=0
endif

ifeq ($(CONFIG_IS_MT798x), y)
	TARGET_CFLAGS += -DCONFIG_IS_MT798x=1
endif

ifeq ($(CONFIG_SUPPORT_WAN_LAN_FLOW_CONTROL), y)
	TARGET_CFLAGS += -DCONFIG_SUPPORT_WAN_LAN_FLOW_CONTROL=1
endif

ifeq ($(CONFIG_AC_IFNAME), y)
	TARGET_CFLAGS += -DCONFIG_AC_IFNAME=1
else ifeq ($(CONFIG_AX_IFNAME), y)
	TARGET_CFLAGS += -DCONFIG_AX_IFNAME=1
endif

ifeq ($(CONFIG_WEXT_SIOCIWPRIV_NUM_RESTRIC_32), y)
	TARGET_CFLAGS += -DWEXT_SIOCIWPRIV_NUM_RESTRIC_32=1
endif

ifeq ($(CONFIG_PACKAGE_awn_RX_PACKETS_CHECK), y)
	TARGET_CFLAGS += -DCONFIG_RX_PACKETS_CHECK=1
else
	TARGET_CFLAGS += -DCONFIG_RX_PACKETS_CHECK=0
endif

ifeq ($(CONFIG_OD_CHANNELLIMIT_SUPPORT), y)
	TARGET_CFLAGS += -DCONFIG_OUTDOOR_CHANNELLIMIT=1
endif

ifeq ($(CONFIG_MTK_DBDC_MODE), y)
	TARGET_CFLAGS += -DCONFIG_RAX_IFNAME=1
else
	TARGET_CFLAGS += -DCONFIG_RAI_IFNAME=1
endif

ifeq ($(CONFIG_PACKAGE_AWN_BSS_STATUS_CHECK), y)
	TARGET_CFLAGS += -DCONFIG_BSS_STATUS_CHECK=1
else
	TARGET_CFLAGS += -DCONFIG_BSS_STATUS_CHECK=0
endif

ifeq ($(CONFIG_PACKAGE_AWN_SUPPORT_WIFI_RELOAD), y)
	TARGET_CFLAGS += -DCONFIG_SUPPORT_WIFI_RELOAD=1
else
	TARGET_CFLAGS += -DCONFIG_SUPPORT_WIFI_RELOAD=0
endif

ifeq ($(CONFIG_PACKAGE_BAND_WIDTH_CHECK), y)
	TARGET_CFLAGS += -DCONFIG_BAND_WIDTH_CHECK=1
else
	TARGET_CFLAGS += -DCONFIG_BAND_WIDTH_CHECK=0
endif

ifeq ($(CONFIG_PACKAGE_AWN_DFS_SCAN_SILENT_5G1), y)
	TARGET_CFLAGS += -DCONFIG_WIFI_DFS_SILENT_5G1=1
	TARGET_CFLAGS += -DCONFIG_WIFI_DFS_SILENT=1
else
	TARGET_CFLAGS += -DCONFIG_WIFI_DFS_SILENT_5G1=0
endif

ifeq ($(CONFIG_PACKAGE_AWN_DFS_SCAN_SILENT_5G2), y)
	TARGET_CFLAGS += -DCONFIG_WIFI_DFS_SILENT_5G2=1
	TARGET_CFLAGS += -DCONFIG_WIFI_DFS_SILENT=1
else
	TARGET_CFLAGS += -DCONFIG_WIFI_DFS_SILENT_5G2=0
endif

ifeq ($(CONFIG_PACKAGE_AWN_WPA_PRI_STATE_CHECK), y)
	TARGET_CFLAGS += -DWPA_PRI_STATE_CHECK=1
endif

ifeq ($(CONFIG_ZERO_WAIT_DFS_SUPPORT), y)
	TARGET_CFLAGS += -DCONFIG_ZERO_WAIT_DFS_SUPPORT=1
else
	TARGET_CFLAGS += -DCONFIG_ZERO_WAIT_DFS_SUPPORT=0
endif

ifeq ($(CONFIG_DCMP_PRECONFIG_support), y)
	TARGET_CFLAGS += -DCONFIG_DCMP_PRECONFIG_support=1
endif

ifeq ($(CONFIG_DCMP_GLOBAL_support), y)
	TARGET_CFLAGS += -DCONFIG_DCMP_GLOBAL_support=1
endif

ifeq ($(CONFIG_AWN_RE_ROAMING), y)
	TARGET_CFLAGS += -DCONFIG_AWN_RE_ROAMING=1
endif

ifeq ($(CONFIG_PACKAGE_wifi-schedule), y)
	TARGET_CFLAGS += -DCONFIG_PACKAGE_WIFI_SCHEDULE=1
endif

ifeq ($(CONFIG_HW_NAT_TRAFFIC_STATS), y)
       TARGET_CFLAGS += -DCONFIG_HW_NAT_TRAFFIC_STATS=1
else
       TARGET_CFLAGS += -DCONFIG_HW_NAT_TRAFFIC_STATS=0
endif

ifeq ($(CONFIG_AWN_BCM_USE_WL_INCLUDE_FILE), y)
    TARGET_CFLAGS += -DCONFIG_BCM_USE_WL_INCLUDE_FILE=1
else
    TARGET_CFLAGS += -DCONFIG_BCM_USE_WL_INCLUDE_FILE=0
endif

ifeq ($(CONFIG_AWN_BOOT_DELAY), y)
	TARGET_CFLAGS += -DCONFIG_AWN_BOOT_DELAY=1
endif

ifeq ($(CONFIG_AWN_CONFIG_BIND_ACCEL), y)
	TARGET_CFLAGS += -DCONFIG_AWN_CONFIG_BIND_ACCEL=1
else
	TARGET_CFLAGS += -DCONFIG_AWN_CONFIG_BIND_ACCEL=0
endif

ifeq ($(CONFIG_AWN_MESH_OPT_SUPPORT), y)
	TARGET_CFLAGS += -DCONFIG_AWN_MESH_OPT_SUPPORT=1
endif

ifeq ($(CONFIG_EXT_SWITCH_IN_VLAN), y)
    TARGET_CFLAGS += -DCONFIG_EXT_SWITCH_IN_VLAN
endif

ifeq ($(CONFIG_SUPPORT_MESHMODE_2G),y)
    TARGET_CFLAGS += -DSUPPORT_MESHMODE_2G=1
endif

ifeq ($(CONFIG_AWN_BOOT_DELAY), y)
	TARGET_CFLAGS += -DCONFIG_AWN_BOOT_DELAY=1
endif

ifeq ($(CONFIG_AWN_CONFIG_BIND_ACCEL), y)
	TARGET_CFLAGS += -DCONFIG_AWN_CONFIG_BIND_ACCEL=1
else
	TARGET_CFLAGS += -DCONFIG_AWN_CONFIG_BIND_ACCEL=0
endif

ifeq ($(CONFIG_DECO_WIFIHAL_SUPPORT), y)
	TARGET_CFLAGS += -DCONFIG_DECO_WIFIHAL_SUPPORT=1
	AWN_MAKEOPT += CONFIG_DECO_WIFIHAL_SUPPORT=1
	TARGET_LDFLAGS += -lwifisoncfg -lhyficommon
	TARGET_LDFLAGS += -lqca_nl80211_wrapper -lnl-3 -lnl-genl-3
endif

ifneq (,$(filter $(CONFIG_PACKAGE_LIBUBOX_VERSION),"2023-05-23" "2024-03-29"))
	TARGET_CFLAGS += -DHAVE_ULOOP_TIMEOUT_REMAINING64=1
endif

TARGET_LDFLAGS += -Wl,--start-group -ldl -Wl,--end-group
TARGET_LDFLAGS += -L$(STAGING_DIR)/usr/lib -pthread -luci -lubox -lplcapi -lubus -lblobmsg_json
ifeq ($(CONFIG_AWN_MESH_OPT_SUPPORT), y)
TARGET_LDFLAGS += -laimsg -laialg
endif
TARGET_LDFLAGS += -L$(STAGING_DIR)/lib -lm
TARGET_LDFLAGS += -ljson-c
TARGET_LDFLAGS += -leth_encap


define Package/auto-wifi-network
  SECTION:=TP-LINK
  CATEGORY:=TP-LINK iplatform apps
  MAINTAINER:=Weng Kaiping <wengkaiping@tp-link.net>
  DEPENDS:=+IPF_PLATFORM_QCA:kmod-qca-wifi +kmod-neighbor-discover +libuci +luci-lib-core +libjson-c +uci +libpthread +libubox +common +plcManager +libubus +ubus +libblobmsg-json +repacd +eth-encap +PACKAGE_libwpa_ctrl:libwpa_ctrl +PACKAGE_ai-center:ai-center +QTL_RG650V:kmod-qca-wifi-cpe-profile +DECO_WIFIHAL_SUPPORT:libwifisoncfg
  TITLE:=Autowifi network for TP-LINK
endef


define Package/auto-wifi-network/Description
	This is a auto wifi network for TP-LINK
endef

define Package/auto-wifi-network/config
	config PACKAGE_awn_RX_PACKETS_CHECK
		bool "check backaul rx_packets num, reconnect if not increase"
		default n

	config AWN_SET_FAPMAC_TO_DRIVER
		bool "Set fap mac to wlan driver"
		default n

	config AWN_QCA_WLAN_VDEV_STATE
		bool "QCA WLAN USE VDEV STATE AS WDS STATE"
		default n

	config PACKAGE_AWN_BSS_STATUS_CHECK
		bool "check bss status(down/up), to wl/bss down/up if necesarry"
		default n
		depends on PACKAGE_auto-wifi-network

	config PACKAGE_AWN_SUPPORT_WIFI_RELOAD
		bool "to wifi reload if necesarry"
		default n
		depends on PACKAGE_AWN_BSS_STATUS_CHECK

	config PACKAGE_BAND_WIDTH_CHECK
	    bool "check wifi band width HT40 or TH80"
		default n
		depends on PACKAGE_AWN_BSS_STATUS_CHECK

	config PACKAGE_AWN_DFS_SCAN_SILENT_5G1
		bool "5G1: not to scan in first one minite if dfs channel"
		default n

	config PACKAGE_AWN_DFS_SCAN_SILENT_5G2
		bool "5G2: not to scan in first one minite if dfs channel"
		default n

	config PACKAGE_AWN_WPA_PRI_STATE_CHECK
		bool "5G2/6G: wpa_supplicant status check"
		default n

	config AWN_RE_ROAMING
		bool "RE fast roaming support"
		default n

	config AWN_QCA_6G_BACKHATL_ADAPTIVE
		bool "Set qca 6G backaul adaptive"
		default n

	config AWN_WAIT_FOR_WIRED_NETWORK
		bool "sleep 10s when wifi connect convert to eth connect(suggest to open when the time of repacd restart less than 10s)"
		default n

	config AWN_BCM_USE_WL_INCLUDE_FILE
		depends on IPF_PLATFORM_BCM
		bool "BCM use include files from wifi drivers"
		default n

	config AWN_BOOT_DELAY
		bool "boot delay"
		default n

	config AWN_CONFIG_BIND_ACCEL
		bool "accelerate bind RE when use config network"
		default n

	config AWN_MESH_OPT_SUPPORT
		bool "support mesh optimization"
		default n

	config RE_RESTORE_STA_CONFIG
		bool "fast reconn Ap after reboot by save sta config"
		default n

	config OD_CHANNELLIMIT_SUPPORT
		bool "Add outdoor channel limit support"
		default n
endef


	
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) -u ./src/* $(PKG_BUILD_DIR)/
endef


define Build/Compile
    $(MAKE) -C $(PKG_BUILD_DIR) $(AWN_MAKEOPT) $(TARGET_CONFIGURE_OPTS) LDFLAGS="$(TARGET_LDFLAGS)" CFLAGS="$(TARGET_CFLAGS)"
endef

define Package/auto-wifi-network/install
	$(CP) ./filesystem/* $(1)/
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/awnd $(1)/usr/sbin
endef

$(eval $(call BuildPackage,auto-wifi-network))
