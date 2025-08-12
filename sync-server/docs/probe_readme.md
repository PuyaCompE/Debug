# Sync Probe报文规范
## 概述：
本文档说明sync probe request/respnose报文的规范，当前字段的含义说明，新增字段要求等

## 规范要求:
1 报文中的字段名称严格限制长度，新增字段名称原则上不能超过3个字符：
(1) 长度偏长的负面示例： performance_limited、firmware_ver、need_account_digest
(2) 例如： "preconf_id"精简成"pid"，在sync list中恢复成正常名称(preconf_id)   http://sohoicigit.rd.tp-link.net/#/c/306999/

2 将值域只有0/1(true/false)、或者值域范围固定[如0-16]，以bit位的形式进行传输，在sync probe接收到回复时，恢复成对应内容，在sync list中对外呈现。
  实现范例、字段增加规范、字段值域bit位映射表: http://sohoicigit.rd.tp-link.net/#/c/309790/

3 需要新增功能/字段，请报告给模块指定负责人在deco_master分支进行首次增加，禁止在其他分支首次添加；

## Probe报文格式：
1. probe request报文

```json
BE95 RE的字段示例：
{
"hwid":"8648E958318665F110AAB334FE891524",
"sync_version":"2",
"eth_backhual":false,
"oemid":"82FDC1E817F16F8C9AE7996763AD8F10",
"group_id":"1e2344e6-7142-11ed-ad41-00ff00298184",
"config_version":"1675232734524.083",
"role":"RE",
"qs_version":"3",
"channel_5g":"40",
"mac":"00:FF:00:2B:A6:72",
"tipc":36873,
"need_account_digest":true,
"iptv_extend":"1",
"channel_2g":"6",
"oui_version":"1",
"oversized_firmware":false,
"guest_ver":"1",
"device_model":"BE95",
"device_id":"FF01E46ADF8BE4524E16824AACEE1FBF2086CFDA",
"firmware_ver":"1.0.0 Build 20230130 Rel. 70321",
"preconf_id":"d3f65d06e22b4bb33abf832afe862388",
"ip":"202.88.128.111"
}
```

2. probe response报文
```json
{
"hwid":"8648E958318665F110AAB334FE891524",
"sync_version":"2",
"eth_backhual":false,
"oemid":"82FDC1E817F16F8C9AE7996763AD8F10",
"group_id":"1e2344e6-7142-11ed-ad41-00ff00298184",
"config_version":"1675232734524.083",
"role":"RE",
"qs_version":"3",
"channel_5g":"40",
"mac":"00:FF:00:2B:A6:72",
"tipc":36873,
"need_account_digest":true,
"iptv_extend":"1",
"channel_2g":"6",
"oui_version":"1",
"oversized_firmware":false,
"guest_ver":"1",
"device_model":"BE95",
"device_id":"FF01E46ADF8BE4524E16824AACEE1FBF2086CFDA",
"firmware_ver":"1.0.0 Build 20230130 Rel. 70321",
"preconf_id":"d3f65d06e22b4bb33abf832afe862388",
"ip":"202.88.128.111"
}
```

3. sync list
```json
ubus call sync list
{
        "FF01E46ADF8BE4524E16824AACEE1FBF2086CFDA": {
                "hwid": "8648E958318665F110AAB334FE891524",
                "sync_version": "2",
                "eth_backhual": false,
                "oemid": "82FDC1E817F16F8C9AE7996763AD8F10",
                "ip": "202.88.128.111",
                "config_version": "1675232734524.083",
                "role": "RE",
                "qs_version": "3",
                "channel_5g": "40",
                "mac": "00:FF:00:2B:A6:72",
                "oui_version": "1",
                "channel_6g_2": "0",
                "tipc": 36873,
                "need_account_digest": true,
                "fw_version": "1.0.0 Build 20230130 Rel. 70321",
                "iptv_extend": "1",
                "channel_2g": "6",
                "countdown": 4,
                "guest_ver": "1",
                "device_model": "BE95",
                "oversized_firmware": false,
                "channel_6g": "69",
                "preconf_id": "d3f65d06e22b4bb33abf832afe862388",
                "myself": true
        }
}
```


## Probe报文的字段含义：

1 目前包含的字段如下：
字段                字段说明                                        代码提交
device_id           DUT dev_id 适配混组升级                         3e238ce
device_model        DUT model删除设备时用到                         c57f175
group_id            DUT groupid                                    928b2e5
sync_version        用于判断DUT syncversion是否有效                  9ab32e9
eth_backhual        有线连接状态                                    fa2b971
preconf_id          预组网信息                                      F90ccfe
iptv_extend         添加re时判断是否支持iptv3                        c74f2eb
guest_ver           guest network混组时关闭RE guest 网络            73e566e
config_version      用于判断DUT 配置版本是否有效                     907c4e3
firmware_ver        当软件版本不匹配时，不进行配置同步                c8ef3d8
oemid               增加oemid保证第一次添加到sync list时数据完整      6f7caa5
hwid                DUT dev_id
role                DUT role                                       c6c50b4
ip                  DUT ip                                         c6c50b4
mac                 DUT mac                                        7483721
channel_2g          DUT 各个频段信道信息 用于FAP和RE信道同步          ceebb37
channel_5g
channel_6g
signal_level        无线信号强度                                    a20cb64
need_account_digest 兼容旧版软件，涉及登录用户名及密码                eaadc8b
qs_version          兼容旧版软件，给RE传递用户名密码，不做RSA加密     d33b752
oversized_firmware  大固件从url下载                                 37d9033
oui_version         Bind_device_list中写入oui_version              da82f56
performance_limited M5 不向M3W 发送数据包获取dev_list               481159c
tipc                解决连续重启tipc-server导致RE的TIPC路由表未更新  0db0dd4

2 字段调整记录：
(1) 预组网字段缩减，不兼容旧固件
http://sohoicigit.rd.tp-link.net/#/c/306999/
                        优化前                                              优化后
Probe字段               "preconf_id": "d3f65d06e22b4bb33abf832afe862388",  "pid":"7A367096",
发送报文CONTENT_LENGTH   923                                                879
回复报文Content-Length   935                                                895
sync list               "preconf_id": "d3f65d06e22b4bb33abf832afe862388",  "preconf_id": "7A367096",

2 probe报文中字段和sync list展示字段不同的列表
报文中的字段名称严格限制长度，新增字段名称不能超过3个字符，在sync list中恢复成正常名称,在下面列表中说明清楚，避免错漏

字段              probe request中字段名     probe request中字段名    sync list中名称
preconf_id        pid                      pid                     preconf_id

