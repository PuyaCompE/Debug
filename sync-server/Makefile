include $(TOPDIR)/rules.mk

PKG_NAME:=sync-server
PKG_VERSION:=1.0

CMAKE_INSTALL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

TARGET_CFLAGS += -Wall -Os

ifeq ($(CONFIG_IOT_SUPPORT), y)
	
ifeq ($(CONFIG_IOT_WIFI_ONLY), y)
	SYNC_SERVER_SCRIPTS := scripts
else
	TARGET_CFLAGS += -DCONFIG_IOT_SUPPORT=1
	SYNC_SERVER_SCRIPTS := scripts-iot
endif

else
	SYNC_SERVER_SCRIPTS := scripts
endif

ifneq (,$(filter $(CONFIG_PACKAGE_LIBUBOX_VERSION),"2023-05-23" "2024-03-29"))
	CMAKE_OPTIONS += -DULOOP_TIMEOUT_REMAINING64=1
endif

ifeq ($(CONFIG_DECO_WIFIHAL_SUPPORT), y)
	TARGET_CFLAGS += -DCONFIG_DECO_WIFIHAL_SUPPORT=1
endif

define Package/sync-server
  SECTION:=TP-LINK
  CATEGORY:=TP-LINK iplatform apps
  DEPENDS:=+libtmpv2-lua +libubus +libblobmsg-json +libubox
  TITLE:=Synchronization server for config, firmware and other stuff
endef

define Build/Prepare
	$(CP) ./src/* $(PKG_BUILD_DIR)
endef

define Build/Compile
endef

define Package/sync-server/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./src/sync-server.init $(1)/etc/init.d/sync-server
	$(call init_order,$(1)/etc/init.d/sync-server)
	$(INSTALL_BIN) ./src/group-key.init $(1)/etc/init.d/group-key
	$(INSTALL_BIN) ./src/uhttpd-fw.init $(1)/etc/init.d/uhttpd-fw
	$(INSTALL_BIN) ./src/delete_record_check_cron $(1)/etc/init.d/delete_record_check_cron

	$(INSTALL_DIR) $(1)/etc/hotplug.d/mode
	$(INSTALL_BIN) ./src/sync.hotplug $(1)/etc/hotplug.d/mode/00-sync
	$(INSTALL_DIR) $(1)/etc/hotplug.d/ip
	$(INSTALL_BIN) ./src/sync.hotplug.ip $(1)/etc/hotplug.d/ip/00-sync	
	

	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/sync-server $(1)/usr/bin/sync-server
	
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./src/sync-check.lua $(1)/usr/sbin/sync-check	
	$(INSTALL_BIN) ./src/mix_network_check.lua $(1)/usr/sbin/mix_network_check	

	$(INSTALL_DIR) $(1)/usr/lib/lua
	$(INSTALL_DATA) ./src/sync-script.lua $(1)/usr/lib/lua
	$(INSTALL_DATA) ./src/update-info.lua $(1)/usr/lib/lua
	$(INSTALL_DATA) ./src/comp_whole_leave.lua $(1)/usr/lib/lua
	$(INSTALL_DATA) ./src/deco_on_off_iface.lua $(1)/usr/lib/lua
	$(INSTALL_BIN) ./src/notify-iot-role $(1)/usr/lib/lua

	$(INSTALL_DIR) $(1)/lib/sync-server/scripts
	$(INSTALL_BIN) ./src/$(SYNC_SERVER_SCRIPTS)/* $(1)/lib/sync-server/scripts
endef

$(eval $(call BuildPackage,sync-server))
