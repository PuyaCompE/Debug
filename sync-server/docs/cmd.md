```c
/* 绑定第一台DECO*/
echo '{"config_version":"1482213341007","params":{"nickname":{"nickname":"living_room"},"date_time":{"time":1428804080351,"timezone":480,"tz_region":"China/Shanghai"},"wireless":{"ssid":"QEBsc3dsZGxlZGU=","password":"OTg3NjU0MzIx"},"cloud_account":{"username":"d2VuZ2thaXBpbmdAdHAtbGluay5jb20uY24=","password":"MTIzNDU2Nzg="}}}' | tmpcli -o 0x4020


/* 绑定从设备，username, password为云账号的base64编码*/
echo '{"config_version":"1482213341008", "params":{"cloud_account":{"username":"d2VuZ2thaXBpbmdAdHAtbGluay5jb20uY24=", "password":"MTIzNDU2Nzg="},"device_list":[{"device_id":"801922409E9C91131EDEA9E0C519E6C71806798A","nickname":{"nickname":"bedroom"}}]}}' | tmpcli -o 0x420B

/*串口下给未绑定设备发送消息,示例为绑定从设备 */
echo '{"params":{"group_id": "31fe27fc-d344-11e7-990b-50c7bf2a667d","nickname":"living_room"}}' | tmpcli -u 192.168.0.100 -s -a -U test@tp-link.net -P test -o 0x4021


/* 删除从设备*/
echo '{"config_version":"1482213341009","params":{"device_list":[{"device_id":"801922409E9C91131EDEA9E0C519E6C71806798A"}]}}' | tmpcli -o 0x4022


/* 指定新的AP*/
echo '{"config_version":"1482213341100","params":{ "device_id":"801922409E9C91131EDEA9E0C519E6C71806798A"}}' | tmpcli -o 0x420F
echo '{"config_version":"1482213341110", "params":{ "device_id":"8019E1BF0365163AC3F2822AF95BF69318059B90"}}' | tmpcli -u 192.168.0.100 -s -a -U wengkaiping@tp-link.com.cn -P 12345678 -o 0x420F

/* 检查是否存在同名网络 */
echo '{"params":{"user_network": {"ssid" : "YXB0ZXN0X3Vlcw=="}}}' | tmpcli -o 0x4207
echo '{"params":{"user_network": {"ssid" : "YXB0ZXN0X3Vlcw=="},"eponymous_network":{"ssid" : "YXB0ZXN0X3Vlcw==","channel":{"band5_1":"48","band2_4":"4"} }}}' | tmpcli -o 0x4207
```

