/******************************************************************************
Copyright (c) 2009-2023 TP-Link Technologies CO.,LTD.  All rights reserved.

File name	: awn_cfg80211_mtk.c
Version		: v0.1
Description	: Get/Set wifi info through Netlink, first use in Realtek chip

Author		: Jiang Ji <jiangji@tp-link.com.hk>
Create date	: 2023/3/23

History		:
01, 2023/3/23 Jiangji, Created file.

*****************************************************************************/
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <linux/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <time.h>
#include <pthread.h>

//#include "nl80211.h"
#include "awn_cfg80211_mtk.h"
//#include "awn_log.h"



/*-----------------------------------------------------*
 *------------   common help function  ----------------*
 *-----------------------------------------------------*/
/**
 * mac_addr_n2a - Convert MAC address (colon-delimited format) to ASCII string
 * @mac_addr: Buffer for the MAC address (MAC_ADDR_LEN = 6 bytes)
 * @txt: MAC address as a string (e.g., "00:11:22:33:44:55")
 * Returns: 0 on success, -1 on failure (e.g., string not a MAC address)
 */
void mac_addr_n2a(char *txt, const unsigned char *mac_addr)
{
	int i, l;

	l = 0;
	for (i = 0; i < MAC_ADDR_LEN ; i++) {
		if (i == 0) {
			sprintf(txt+l, "%02x", mac_addr[i]);
			l += 2;
		} else {
			sprintf(txt+l, ":%02x", mac_addr[i]);
			l += 3;
		}
	}
}

/**
 * mac_addr_a2n - Convert ASCII string to MAC address (colon-delimited format)
 * @txt: MAC address as a string (e.g., "00:11:22:33:44:55")
 * @mac_addr: Buffer for the MAC address (MAC_ADDR_LEN = 6 bytes)
 * Returns: 0 on success, -1 on failure (e.g., string not a MAC address)
 */
int mac_addr_a2n(unsigned char *mac_addr, char *txt)
{
	int i;

	for (i = 0; i < MAC_ADDR_LEN ; i++) {
		UINT32 temp;
		char *cp = strchr(txt, ':');
		if (cp) {
			*cp = 0;
			cp++;
		}
		if (sscanf(txt, "%x", &temp) != 1)
			return -1;
		if (temp < 0 || temp > 255)
			return -1;

		mac_addr[i] = temp;
		if (!cp)
			break;
		txt = cp;
	}
	if (i < MAC_ADDR_LEN - 1)
		return -1;

	return 0;
}

/**
 * phy_lookup - get phy_id for given phy_name
 * @name: phy name, ie: phy0
 * Returns: phy_id on success, -1 on failure
 */
static int phy_lookup(const char *name)
{
	char buf[200];
	int fd, pos;

	snprintf(buf, sizeof(buf), "/sys/class/ieee80211/%s/index", name);

	fd = open(buf, O_RDONLY);
	if (fd < 0)
		return -1;
	pos = read(fd, buf, sizeof(buf) - 1);
	if (pos < 0) {
		close(fd);
		return -1;
	}
	buf[pos] = '\0';
	close(fd);
	return atoi(buf);
}

/**
 * save_scan_entry - find a slot to hold new arrived scan entry
 *      if the bss already exist, update it;
 *      if not exist, add it;
 *          +- if bss_list is full, replace the entry with lowest rssi
 *          +- else drop it
 *
 * @bss_list: buffer to hold scan entry
 * @bss: scan entry to be enqueue
 * Returns: 0 for success; others for fail
 */
static int save_scan_entry(TP_CFG80211_SCAN_RESULTS *bss_list, TP_CFG80211_SCAN_RESULT_ENTRY *bss)
{
	int idx = 0;
	int lowest_entry_idx = -1;
	int target_entry_idx = -1;
	int ret = 0;
	int lowest = 0;
	bool update = false;

	if (bss_list == NULL || bss == NULL)
	{
		return -1;
	}

	lowest = bss->level;
	for (idx = 0; idx < bss_list->bss_num; idx++)
	{
		/* exist check */
		if (memcmp(bss_list->bss_entry[idx].bssid, bss->bssid, MAC_ADDR_LEN) == 0)
		{
			update = true;
			break;
		}

		if (bss_list->bss_entry[idx].level < lowest)
		{
			lowest = bss_list->bss_entry[idx].level;
			lowest_entry_idx = idx;
		}
	}

	/* add a new entry */
	if (update)
	{
		if (bss->tsf > bss_list->bss_entry[idx].tsf)
		{
			target_entry_idx = idx;
		}
	}
	else
	{
		if (bss_list->bss_num >= CFG80211_SCAN_ENTRY_MAX_NUM)
		{
			target_entry_idx = lowest_entry_idx;
		}
		else
		{
			target_entry_idx = bss_list->bss_num;
			bss_list->bss_num++;
		}
	}

	if (target_entry_idx >= 0 && target_entry_idx < CFG80211_SCAN_ENTRY_MAX_NUM)
	{
		memcpy(&bss_list->bss_entry[target_entry_idx], bss, sizeof(TP_CFG80211_SCAN_RESULT_ENTRY));
	}
	else
	{
		ret = -2;
	}

	return ret;
}

/*---------------------------------------------------*
 *----------   netlink system api  ------------------*
 *---------------------------------------------------*/
/*
static inline struct nl_handle *nl_socket_alloc(void)
{
	return nl_handle_alloc();
}

static inline void nl_socket_free(struct nl_handle *h)
{
	nl_handle_destroy(h);
}

static inline int nl_socket_set_buffer_size(struct nl_handle *sk,
					    int rxbuf, int txbuf)
{
	return nl_set_buffer_size(sk, rxbuf, txbuf);
}
*/

static int nl80211_init(struct nl80211_state *state)
{
	int err;

	state->nl_sock = nl_socket_alloc();
	if (!state->nl_sock) {
		AWN_LOG_ERR("Failed to allocate netlink socket.\n");
		return -ENOMEM;
	}

	if (genl_connect(state->nl_sock)) {
		AWN_LOG_ERR("Failed to connect to generic netlink.\n");
		err = -ENOLINK;
		goto out_handle_destroy;
	}

	nl_socket_set_buffer_size(state->nl_sock, 8192, 8192);

	/* try to set NETLINK_EXT_ACK to 1, ignoring errors */
	err = 1;
	setsockopt(nl_socket_get_fd(state->nl_sock), SOL_NETLINK,
		   NETLINK_EXT_ACK, &err, sizeof(err));

	/* try to set NETLINK_CAP_ACK to 1, ignoring errors */
	err = 1;
	setsockopt(nl_socket_get_fd(state->nl_sock), SOL_NETLINK,
		   NETLINK_CAP_ACK, &err, sizeof(err));

	state->nl80211_id = genl_ctrl_resolve(state->nl_sock, "nl80211");
	if (state->nl80211_id < 0) {
		AWN_LOG_ERR("nl80211 not found.\n");
		err = -ENOENT;
		goto out_handle_destroy;
	}

	return 0;

 out_handle_destroy:
	nl_socket_free(state->nl_sock);
	state->nl_sock = NULL;
	return err;
}

static void nl80211_cleanup(struct nl80211_state *state)
{
	if (state->nl_sock)
	{
		nl_socket_free(state->nl_sock);
	}
}

/*-----------------------------------------------------------------------*
 *---------------------  private netlink handle  ------------------------*
 *-----------------------------------------------------------------------*/
void register_handler(int (*handler)(struct nl_msg *, void *), void *data)
{
	registered_handler = handler;
	registered_handler_data = data;
}

int valid_handler(struct nl_msg *msg, void *arg)
{
	if (registered_handler)
		return registered_handler(msg, registered_handler_data);

	return NL_OK;
}

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
			 void *arg)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)err - 1;
	int len = nlh->nlmsg_len;
	struct nlattr *attrs;
	struct nlattr *tb[NLMSGERR_ATTR_MAX + 1];
	int *ret = arg;
	int ack_len = sizeof(*nlh) + sizeof(int) + sizeof(*nlh);

	*ret = err->error;

	if (!(nlh->nlmsg_flags & NLM_F_ACK_TLVS))
		return NL_SKIP;

	if (!(nlh->nlmsg_flags & NLM_F_CAPPED))
		ack_len += err->msg.nlmsg_len - sizeof(*nlh);

	if (len <= ack_len)
		return NL_STOP;

	attrs = (void *)((unsigned char *)nlh + ack_len);
	len -= ack_len;

	nla_parse(tb, NLMSGERR_ATTR_MAX, attrs, len, NULL);
	if (tb[NLMSGERR_ATTR_MSG]) {
		len = strnlen((char *)nla_data(tb[NLMSGERR_ATTR_MSG]),
			      nla_len(tb[NLMSGERR_ATTR_MSG]));
		AWN_LOG_ERR("kernel reports: %*s\n", len,
			(char *)nla_data(tb[NLMSGERR_ATTR_MSG]));
	}

	return NL_SKIP;
}

static int finish_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;
	*ret = 0;
	return NL_SKIP;
}

static int ack_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;
	*ret = 0;
	return NL_STOP;
}

static int handle_common_command(struct nl_msg *msg,
			   unsigned short sub_cmd_id, char *data, size_t len)
{
	void *attr;

	attr = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
	if (!attr)
		return -1;

	if (nla_put(msg, sub_cmd_id, len, data))
		return -1;

	nla_nest_end(msg, attr);

	return 0;
}

/* convert wifi freq to chan number
 * para:
 *     in @freq: wifi channel in XXX Mhz
 * return: chan number; 0 for error
 */
static int ieee80211_frequency_to_channel(int freq)
{
	/* see 802.11 17.3.8.3.2 and Annex J */
	if (freq == 2484)
		return 14;
	else if (freq < 2484)
		return (freq - 2407) / 5;
	else if (freq >= 4910 && freq <= 4980)
		return (freq - 4000) / 5;
	else if (freq < 5925)
		return (freq - 5000) / 5;
	else if (freq == 5935)
		return 2;
	else if (freq <= 45000)
		/* see 802.11ax D6.1 27.3.22.2 */
		return (freq - 5950) / 5;
	else if (freq >= 58320 && freq <= 64800)
		return (freq - 56160) / 2160;
	else
		return 0;
}

/* convert chan number to wifi freq
 * para:
 *     in @chan: ieee802.11 channel number
 *     in @band: 2g/5g/6g
 * return: wifi freq; 0 for error
 */
int ieee80211_channel_to_frequency(int chan, AWND_REAL_BAND_TYPE band)
{
	/* see 802.11 17.3.8.3.2 and Annex J
	 * there are overlapping channel numbers in 5GHz and 2GHz bands */
	if (chan <= 0)
		return 0; /* not supported */
	switch (band) {
	case AWND_REAL_BAND_2G:
		if (chan == 14)
			return 2484;
		else if (chan < 14)
			return 2407 + chan * 5;
		break;
	case AWND_REAL_BAND_5G:
	case AWND_REAL_BAND_5G2:
		if (chan >= 182 && chan <= 196)
			return 4000 + chan * 5;
		else
			return 5000 + chan * 5;
		break;
	case AWND_REAL_BAND_6G:
			return 5950 + chan * 5;
		break;
	default:
		;
	}
	return 0; /* not supported */
}

static int print_tpie_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	int err = 0;
	char* nl_data;

	TP_CFG80211_VENDOR_DATA *vendor = (TP_CFG80211_VENDOR_DATA *)arg;
	int len = 0;

	struct nlattr *sub_tb[MTK_NL80211_VENDOR_ATTR_GET_RUNTIME_INFO_MAX + 1];

	if (!arg)
		return -1;

	err = nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
			  genlmsg_attrlen(gnlh, 0), NULL);
	if (err < 0)
		return err;

	if (tb[NL80211_ATTR_VENDOR_DATA]) {
		err = nla_parse_nested(sub_tb, MTK_NL80211_VENDOR_ATTR_GET_RUNTIME_INFO_MAX,
			tb[NL80211_ATTR_VENDOR_DATA], NULL);
		if (err < 0)
			return err;

		if (sub_tb[MTK_NL80211_VENDOR_ATTR_GET_RUNTIME_INFO_GET_TPIE_INFO]) {
			nl_data = nla_data(sub_tb[MTK_NL80211_VENDOR_ATTR_GET_RUNTIME_INFO_GET_TPIE_INFO]);
			len = nla_len(sub_tb[MTK_NL80211_VENDOR_ATTR_GET_RUNTIME_INFO_GET_TPIE_INFO]);
			vendor->data = (u_int8_t *)malloc(len + 1);
			if (vendor->data)
			{
				memset(vendor->data, 0, len + 1);
				memcpy(vendor->data, nl_data, len);
				vendor->data_len = len;
			}
			else
			{
				vendor->data_len = 0;
			}
		}
	} else
		AWN_LOG_CRIT("%s(), no any show rsp string from driver\n", __func__);

	return 0;
}

/* get vendor data from driver through cfg80211 vendor cmd
 * para:
 *     in @msg: "iw dev XXX vendor recv 0x001d0f subcmd_id xxx"
 *     out @arg: private struct USER buf to hold vendor data
 * return: NL_SKIP / NL_OK
 */
static int print_stainfo_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	int err = 0;
	char* nl_data;

	struct nlattr *sub_tb[MTK_NL80211_VENDOR_ATTR_GET_RUNTIME_INFO_MAX + 1];

	if (!arg)
		return -1;

	err = nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
			  genlmsg_attrlen(gnlh, 0), NULL);
	if (err < 0)
		return err;

	if (tb[NL80211_ATTR_VENDOR_DATA]) {
		err = nla_parse_nested(sub_tb, MTK_NL80211_VENDOR_ATTR_GET_RUNTIME_INFO_MAX,
			tb[NL80211_ATTR_VENDOR_DATA], NULL);
		if (err < 0)
			return err;

		if (sub_tb[MTK_NL80211_VENDOR_ATTR_GET_RUNTIME_INFO_GET_CONNINFO]) {
			nl_data = nla_data(sub_tb[MTK_NL80211_VENDOR_ATTR_GET_RUNTIME_INFO_GET_CONNINFO]);
			memcpy(arg, nl_data, sizeof(WLAN_CONN_INFO));
		}
	} else
		AWN_LOG_ERR("%s(), no any show rsp string from driver\n", __func__);

	return 0;
}

static int print_chaninfo_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	int err = 0;
	char* nl_data;

	struct nlattr *sub_tb[MTK_NL80211_VENDOR_ATTR_GET_RUNTIME_INFO_MAX + 1];

	if (!arg)
		return -1;

	err = nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
			  genlmsg_attrlen(gnlh, 0), NULL);
	if (err < 0)
		return err;

	if (tb[NL80211_ATTR_VENDOR_DATA]) {
		err = nla_parse_nested(sub_tb, MTK_NL80211_VENDOR_ATTR_GET_RUNTIME_INFO_MAX,
			tb[NL80211_ATTR_VENDOR_DATA], NULL);
		if (err < 0)
			return err;

		if (sub_tb[MTK_NL80211_VENDOR_ATTR_GET_RUNTIME_INFO_GET_CHANINFO]) {
			nl_data = nla_data(sub_tb[MTK_NL80211_VENDOR_ATTR_GET_RUNTIME_INFO_GET_CHANINFO]);
			memcpy(arg, nl_data, sizeof(CHAN_INFO));
		}
	} else
		AWN_LOG_ERR("%s(), no any show rsp string from driver\n", __func__);

	return 0;
}

static int print_cacnopstatus_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	int err = 0;
	char* nl_data;

	struct nlattr *sub_tb[MTK_NL80211_VENDOR_ATTR_GET_RUNTIME_INFO_MAX + 1];

	if (!arg)
		return -1;

	err = nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
			  genlmsg_attrlen(gnlh, 0), NULL);
	if (err < 0)
		return err;

	if (tb[NL80211_ATTR_VENDOR_DATA]) {
		err = nla_parse_nested(sub_tb, MTK_NL80211_VENDOR_ATTR_GET_RUNTIME_INFO_MAX,
			tb[NL80211_ATTR_VENDOR_DATA], NULL);
		if (err < 0)
			return err;

		if (sub_tb[MTK_NL80211_VENDOR_ATTR_GET_RUNTIME_INFO_GET_CACNOPSTATUS]) {
			nl_data = nla_data(sub_tb[MTK_NL80211_VENDOR_ATTR_GET_RUNTIME_INFO_GET_CACNOPSTATUS]);
			memcpy(arg, nl_data, sizeof(WLAN_CAC_STATUS));
		}
	} else
		AWN_LOG_ERR("%s(), no any show rsp string from driver\n", __func__);

	return 0;
}

static int print_scanstatus_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	int err = 0;
	char* nl_data;

	struct nlattr *sub_tb[MTK_NL80211_VENDOR_ATTR_GET_RUNTIME_INFO_MAX + 1];

	if (!arg)
		return -1;

	err = nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
			  genlmsg_attrlen(gnlh, 0), NULL);
	if (err < 0)
		return err;

	if (tb[NL80211_ATTR_VENDOR_DATA]) {
		err = nla_parse_nested(sub_tb, MTK_NL80211_VENDOR_ATTR_GET_RUNTIME_INFO_MAX,
			tb[NL80211_ATTR_VENDOR_DATA], NULL);
		if (err < 0)
			return err;

		if (sub_tb[MTK_NL80211_VENDOR_ATTR_GET_RUNTIME_INFO_GET_SCAN_STATUS]) {
			nl_data = nla_data(sub_tb[MTK_NL80211_VENDOR_ATTR_GET_RUNTIME_INFO_GET_SCAN_STATUS]);
			memcpy(arg, nl_data, sizeof(UINT8));
		}
	} else
		AWN_LOG_ERR("%s(), no any show rsp string from driver\n", __func__);

	return 0;
}

/* collect vap interface info
 * para:
 *     in @msg: "iw dev info"
 *     out @arg: private struct NR_CFG80211_AP_INFO to hold vap info
 * return: NL_SKIP for all case
 */
static int print_iface_handler(struct nl_msg *msg, void *arg)
{
	TP_VAP_INFO *vap_info = (TP_VAP_INFO *)arg;
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];

	if (vap_info == NULL)
	{
		AWN_LOG_ERR("buffer missing!\n");
		return NL_SKIP;
	}

	nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (tb_msg[NL80211_ATTR_MAC]) {
		memcpy(vap_info->mac, nla_data(tb_msg[NL80211_ATTR_MAC]), MAC_ADDR_LEN);
	}
	if (tb_msg[NL80211_ATTR_SSID]) {
		memcpy(vap_info->ssid, nla_data(tb_msg[NL80211_ATTR_SSID]),
			nla_len(tb_msg[NL80211_ATTR_SSID]));
	}

	if (tb_msg[NL80211_ATTR_WIPHY])
	{
		uint32_t phy_id = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY]);
		vap_info->phy_id = (uint16_t)phy_id;
	}
	if (tb_msg[NL80211_ATTR_WIPHY_FREQ]) {
		uint32_t freq = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY_FREQ]);
		vap_info->channum = (unsigned char)ieee80211_frequency_to_channel(freq);
	}

	return NL_SKIP;
}

/* collect ap vap phy info
 * para:
 *     in @msg: "iw phy info"
 *     out @arg: private struct TP_PHYCAP_INFO to hold ap phy info
 * return: NL_SKIP for all case
 */
static int print_phy_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

	int err = 0;
	char* nl_data;
	void* res;

	struct nlattr *sub_tb[MTK_NL80211_VENDOR_ATTR_GET_RUNTIME_INFO_MAX + 1];

	if (arg == NULL)
	{
		fprintf(stderr, "buffer missing!\n");
		return NL_SKIP;
	}
	err = nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
			 genlmsg_attrlen(gnlh, 0), NULL);
	if (err < 0)
		return err;

	if (tb[NL80211_ATTR_VENDOR_DATA]) {
		err = nla_parse_nested(sub_tb, MTK_NL80211_VENDOR_ATTR_GET_RUNTIME_INFO_MAX,
			tb[NL80211_ATTR_VENDOR_DATA], NULL);
		if (err < 0)
			return err;
		if (sub_tb[MTK_NL80211_VENDOR_ATTR_GET_RUNTIME_INFO_GET_PHYCAPINFO]) {
			nl_data = nla_data(sub_tb[MTK_NL80211_VENDOR_ATTR_GET_RUNTIME_INFO_GET_PHYCAPINFO]);
			memcpy(arg, nl_data, sizeof(struct _WLAN_PHYINFO));
		}
	} else
		printf("%s(), no any show rsp string from driver\n", __func__);
		
	return NL_SKIP;
}

/* collect scan result info
 * para:
 *     in @msg: "iw dev scan dump"
 *     out @arg: private struct NR_CFG80211_SCAN_RESULTS to hold scan result info
 * return: NL_SKIP for all case
 */
static int print_scan_bss_handler(struct nl_msg *msg, void *arg)
{
	TP_CFG80211_SCAN_RESULTS *bss_list = (TP_CFG80211_SCAN_RESULTS *)arg;
	TP_CFG80211_SCAN_RESULT_ENTRY bss_entry;
	int ret = 0;

	uint8_t *ssid = NULL;
	uint8_t *tpie = NULL;
	size_t ssid_len = 0;
	size_t tpie_len = 0;

	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *bss[NL80211_BSS_MAX + 1];
	static struct nla_policy bss_policy[NL80211_BSS_MAX + 1] = {
		[NL80211_BSS_BSSID] = { },
		[NL80211_BSS_FREQUENCY] = { .type = NLA_U32 },
		[NL80211_BSS_TSF] = { .type = NLA_U64 },
		[NL80211_BSS_BEACON_INTERVAL] = { .type = NLA_U16 },
		[NL80211_BSS_CAPABILITY] = { .type = NLA_U16 },
		[NL80211_BSS_INFORMATION_ELEMENTS] = { },
		[NL80211_BSS_SIGNAL_MBM] = { .type = NLA_U32 },
		[NL80211_BSS_SIGNAL_UNSPEC] = { .type = NLA_U8 },
		[NL80211_BSS_STATUS] = { .type = NLA_U32 },
		[NL80211_BSS_SEEN_MS_AGO] = { .type = NLA_U32 },
		[NL80211_BSS_BEACON_IES] = { },
	};

	if (bss_list == NULL)
	{
		AWN_LOG_ERR("buffer missing!\n", __func__);
		return NL_SKIP;
	}

	/* init bss entry struct */;
	memset(&bss_entry, 0, sizeof(bss_entry));

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (!tb[NL80211_ATTR_BSS])
	{
		AWN_LOG_ERR("bss info missing!\n");
		return NL_SKIP;
	}

	if (nla_parse_nested(bss, NL80211_BSS_MAX, tb[NL80211_ATTR_BSS],
					 bss_policy))
	{
		AWN_LOG_ERR("failed to parse nested attributes!\n");
		return NL_SKIP;
	}

	if (!bss[NL80211_BSS_BSSID])
	{
		return NL_SKIP;
	}
	else
	{
		memcpy(bss_entry.bssid, nla_data(bss[NL80211_BSS_BSSID]), MAC_ADDR_LEN);
	}

	if (bss[NL80211_BSS_FREQUENCY])
	{
		bss_entry.freq = nla_get_u32(bss[NL80211_BSS_FREQUENCY]);
	}
	if (bss[NL80211_BSS_BEACON_INTERVAL])
	{
		bss_entry.beacon_int = nla_get_u16(bss[NL80211_BSS_BEACON_INTERVAL]);
	}
	if (bss[NL80211_BSS_CAPABILITY])
	{
		bss_entry.caps = nla_get_u16(bss[NL80211_BSS_CAPABILITY]);
	}

	if (bss[NL80211_BSS_SIGNAL_MBM])
	{
		bss_entry.level = nla_get_u32(bss[NL80211_BSS_SIGNAL_MBM]);
		bss_entry.level /= 100; /* mBm to dBm */
	}
	else if (bss[NL80211_BSS_SIGNAL_UNSPEC])
	{
		bss_entry.level = nla_get_u8(bss[NL80211_BSS_SIGNAL_UNSPEC]);
	}

	if (bss[NL80211_BSS_TSF])
	{
		bss_entry.tsf = nla_get_u64(bss[NL80211_BSS_TSF]);
	}
	if (bss[NL80211_BSS_SEEN_MS_AGO])
	{
		bss_entry.age = nla_get_u32(bss[NL80211_BSS_SEEN_MS_AGO]);
	}

	if (bss[NL80211_BSS_INFORMATION_ELEMENTS])
	{
		struct nlattr *ies = bss[NL80211_BSS_INFORMATION_ELEMENTS];

		ssid = tp_get_ie(nla_data(ies), nla_len(ies), WLAN_EID_SSID, NULL, 0, &ssid_len);
		if (ssid && ssid_len > 0)
		{
			memcpy(bss_entry.ssid, ssid + 2, ssid_len - 2);
			bss_entry.ssid_len = ssid_len - 2;
		}

		tpie = tp_get_ie(nla_data(ies), nla_len(ies), WLAN_EID_VENDOR_SPECIFIC,
			(uint8_t *)TP_OUI, 3, &tpie_len);
		if (!tpie)
		{
			tpie = tp_get_ie(nla_data(ies), nla_len(ies), WLAN_EID_VENDOR_SPECIFIC,
				(uint8_t *)TP_NEW_OUI, 3, &tpie_len);
		}
	}
	else if (bss[NL80211_BSS_BEACON_IES])
	{
		struct nlattr *bcnies = bss[NL80211_BSS_BEACON_IES];

		ssid = tp_get_ie(nla_data(bcnies), nla_len(bcnies), WLAN_EID_SSID, NULL, 0, &ssid_len);
		if (ssid && ssid_len > 0)
		{
			memcpy(bss_entry.ssid, ssid + 2, ssid_len - 2);
			bss_entry.ssid_len = ssid_len - 2;
		}

		tpie = tp_get_ie(nla_data(bcnies), nla_len(bcnies), WLAN_EID_VENDOR_SPECIFIC,
			(uint8_t *)TP_OUI, 3, &tpie_len);
		if (!tpie)
		{
			tpie = tp_get_ie(nla_data(bcnies), nla_len(bcnies), WLAN_EID_VENDOR_SPECIFIC,
				(uint8_t *)TP_NEW_OUI, 3, &tpie_len);
		}
	}

	if (tpie && tpie_len)
	{
		memcpy(bss_entry.tpie, tpie, tpie_len);
		bss_entry.tpie_len = tpie_len;
	}
	else
	{
		return NL_SKIP;
	}

	ret = save_scan_entry(bss_list, &bss_entry);
	if (ret)
	{
		return NL_SKIP;
	}

	return NL_SKIP;
}

/*-----------------------------------------------------*
 *------------   cb function register  ----------------*
 *-----------------------------------------------------*/
static int handle_phy_info(void *data)
{
	register_handler(print_phy_handler, data);
	return 0;
}

static int handle_scan_info(void *data)
{
	register_handler(print_scan_bss_handler, data);
	return 0;
}

static int handle_tpie_dump(void *data)
{
	register_handler(print_tpie_handler, data);
	return 0;
}

static int handle_stainfo_dump(void *data)
{
	register_handler(print_stainfo_handler, data);
	return 0;
}

static int handle_interface_dump(void *data)
{
	register_handler(print_iface_handler, data);
	return 0;
}

static int handle_chaninfo_dump(void *data)
{
	register_handler(print_chaninfo_handler, data);
	return 0;
}

static int handle_cacnopstatus_dump(void *data)
{
	register_handler(print_cacnopstatus_handler, data);
	return 0;
}

static int handle_scanstatus_dump(void *data)
{
	register_handler(print_scanstatus_handler, data);
	return 0;
}

static int handle_phyinfo_dump(void *data)
{
	register_handler(print_phy_handler, data);
	return 0;
}



/* find eid in given frame
 * para:
 *     in @ies: mgmt frame from driver
 *     in @ies_len: mgmt frame len
 *     in @eid: target ie we want to find
 *     in @oui: option, OUI for vender ie
 *     in @oui_len: OUI len
 *
 *     out @ie_len: target ie len if founded
 * return: target_ie start addr, NULL for not found
 */
static uint8_t *tp_get_ie(const uint8_t *ies, size_t ies_len, uint8_t eid,
	uint8_t *oui, size_t oui_len, size_t *ie_len)
{
	u_int32_t cnt;
	const uint8_t *target_ie = NULL;

	if (ie_len)
	{
		*ie_len = 0;
	}

	if (!ies || ies_len <= 0)
	{
		return (uint8_t *)target_ie;
	}

	cnt = 0;

	while (cnt < ies_len)
	{
		if (eid == ies[cnt]
		    && (!oui || memcmp(&ies[cnt + 2], oui, oui_len) == 0))
		{
			target_ie = &ies[cnt];

			if (ie_len)
			{
				*ie_len = ies[cnt + 1] + 2;
			}

			break;
		}
		else
		{
			cnt += ies[cnt + 1] + 2; /* goto next */
		}

	}

	return (uint8_t *)target_ie;
}

static int tp_construct_scan_msg(struct nl_msg *msg, void *data)
{
	TP_SCAN_PARAM *params = (TP_SCAN_PARAM *)data;
	u_int32_t flags = NL80211_SCAN_FLAG_AP;
	int i = 0;

	if (params->num_channels > 0)
	{
		int freq = 0;
		struct nlattr *freqs = nla_nest_start(msg, NL80211_ATTR_SCAN_FREQUENCIES);
		if (freqs == NULL)
		{
			AWN_LOG_ERR("scan_msg: NL80211_ATTR_SCAN_FREQUENCIES fail\n");
			goto fail;
		}

		for (i = 0; i < params->num_channels; i++)
		{
			freq = ieee80211_channel_to_frequency(params->channels[i], params->scan_band);

			if (nla_put_u32(msg, i + 1, freq))
				goto fail;
		}

		nla_nest_end(msg, freqs);
	}

	if (params->ssid_len > 0)
	{
		struct nlattr *ssids = nla_nest_start(msg, NL80211_ATTR_SCAN_SSIDS);
		if (ssids == NULL)
		{
			fprintf(stderr, "scan_msg: NL80211_ATTR_SCAN_SSIDS fail\n");
			goto fail;
		}

		if (nla_put(msg, 1, params->ssid_len, params->ssid))
				goto fail;
		nla_nest_end(msg, ssids);
	}

	if (params->flush) {
		flags |= NL80211_SCAN_FLAG_FLUSH;
	}
	//flags |= NL80211_SCAN_FLAG_LOW_PRIORITY;

	if (flags &&  nla_put_u32(msg, NL80211_ATTR_SCAN_FLAGS, flags))
	{
		AWN_LOG_ERR("scan_msg: NL80211_ATTR_SCAN_FLAGS fail\n");
		goto fail;
	}

	return 0;

fail:
	return 1;
}

/*
 * Main function to communicate with Netlink
 * para:
 *     in @ifname: dev_name or phy_name, indicate which interface to connect
 *        @cmdid: specify cmd type
 *     out @data: record data after transfer from netlink message to local private struct
 *         @argc: any further arg count if needed
 *         @argv: any further arg valuse if needed
 * return: 0 for success; others for fail
 */
int netlink_debug = 0;
static
int wifi_cfg80211_send_cmd(const char *ifname, int cmdid, void *data, uint8_t argc, void *argv)
{
	struct nl80211_state nlstate;
	int ret = 0;
	char *tmp = NULL;
	
	signed long long devidx = 0;
	int nl_msg_flags = 0;
	int nl_msg_cmd = 0;
	int cib = 0;
	unsigned int oui = 0;
	unsigned int subcmd = 0;
	unsigned int subcmd_id = 0;
	int cmm_len = 0;
	const char cmm_data[8] = "Any";
	char *p_cmm_data = NULL;
	
	struct nl_cb *cb = NULL;
	struct nl_cb *s_cb = NULL;
	struct nl_msg *msg = NULL;

	/* init nl80211_id here, just to avoid compile warning */
	nlstate.nl80211_id = 0;

	ret = nl80211_init(&nlstate);
	if (ret)
	{
		AWN_LOG_ERR("nl80211_init fail\n");
		ret = 1;
		goto END;
	}

	switch(cmdid)
	{
	case AWN_CMD_START_SCAN:
		nl_msg_flags = 0;
		nl_msg_cmd = NL80211_CMD_TRIGGER_SCAN;
		cib = CIB_NETDEV;
		register_handler(NULL, NULL);
		break;
	case AWN_CMD_SCAN_RESULT:
		nl_msg_flags = NLM_F_DUMP;
		nl_msg_cmd = NL80211_CMD_GET_SCAN;
		cib = CIB_NETDEV;
		handle_scan_info(data);
		break;
	case AWN_CMD_GET_TPIE:
		nl_msg_flags = 0;
		nl_msg_cmd = NL80211_CMD_VENDOR;
		cib = CIB_NETDEV;
		handle_tpie_dump(data);
		break;
	case AWN_CMD_GET_STAINFO:
		nl_msg_flags = 0;
		nl_msg_cmd = NL80211_CMD_VENDOR;
		cib = CIB_NETDEV;
		handle_stainfo_dump(data);
		break;
	case AWN_CMD_AP_INFO:
		nl_msg_flags = 0;
		nl_msg_cmd = NL80211_CMD_GET_INTERFACE;
		cib = CIB_NETDEV;
		handle_interface_dump(data);
		break;
	case AWN_CMD_AP_PHYINFO:
		nl_msg_flags = 0;
		nl_msg_cmd = NL80211_CMD_VENDOR;
		cib = CIB_NETDEV;
		handle_phyinfo_dump(data);
		break;
	case AWN_CMD_GET_CHANINFO:
		nl_msg_flags = 0;
		nl_msg_cmd = NL80211_CMD_VENDOR;
		cib = CIB_NETDEV;
		handle_chaninfo_dump(data);
		break;
	case AWN_CMD_GET_CACNOPSTATUS:
		nl_msg_flags = 0;
		nl_msg_cmd = NL80211_CMD_VENDOR;
		cib = CIB_NETDEV;
		handle_cacnopstatus_dump(data);
		break;
	case AWN_CMD_GET_SCAN_STATUS:
		nl_msg_flags = 0;
		nl_msg_cmd = NL80211_CMD_VENDOR;
		cib = CIB_NETDEV;
		handle_scanstatus_dump(data);
		break;
	default:
		AWN_LOG_ERR("Unkown Cfg80211 NR_CMD %d\n", cmdid);
		ret = 2;
		goto END;
	}

	msg = nlmsg_alloc();
	if (!msg) {
		AWN_LOG_ERR("failed to allocate netlink message\n");
		ret = 3;
		goto END;
	}
	
	cb = nl_cb_alloc(netlink_debug ? NL_CB_DEBUG : NL_CB_DEFAULT);
	s_cb = nl_cb_alloc(netlink_debug ? NL_CB_DEBUG : NL_CB_DEFAULT);
	if (!cb || !s_cb) {
		AWN_LOG_ERR("failed to allocate netlink callbacks\n");
		ret = 4;
		goto out;
	}
	
	genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0,
		    nl_msg_flags, nl_msg_cmd, 0);

	switch (cib) {
	case CIB_PHY:
		devidx = phy_lookup(ifname);
		NLA_PUT_U32(msg, NL80211_ATTR_WIPHY, devidx);
		break;

	case CIB_NETDEV:
		devidx = if_nametoindex(ifname);
		if (devidx == 0)
		{
			devidx = -1;
		}

		NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devidx);
		break;

	case CIB_WDEV:
		devidx = strtoll(ifname, &tmp, 0);
		if (*tmp != '\0')
		{
			ret = 5;
			goto out;
		}
		NLA_PUT_U64(msg, NL80211_ATTR_WDEV, devidx);
		break;

	default:
		break;
	}

	switch(cmdid)
	{
	case AWN_CMD_GET_TPIE:
		oui = MTK_NL80211_VENDOR_ID;
		subcmd = MTK_NL80211_VENDOR_SUBCMD_GET_RUNTIME_INFO;
		subcmd_id = MTK_NL80211_VENDOR_ATTR_GET_RUNTIME_INFO_GET_TPIE_INFO;
		p_cmm_data = (char *)argv;
		cmm_len = sizeof(TPIE_SEARCH_ENTRY);
		break;
	case AWN_CMD_GET_STAINFO:
		oui = MTK_NL80211_VENDOR_ID;
		subcmd = MTK_NL80211_VENDOR_SUBCMD_GET_RUNTIME_INFO;
		subcmd_id = MTK_NL80211_VENDOR_ATTR_GET_RUNTIME_INFO_GET_CONNINFO;
		p_cmm_data = data;
		cmm_len = sizeof(WLAN_CONN_INFO);
		break;
	case AWN_CMD_START_SCAN:
		ret = tp_construct_scan_msg(msg, argv);
		if (ret)
		{
			fprintf(stderr, "failed to construct scan msg, ret=%d\n", ret);
			goto out;
		}
		break;
	case AWN_CMD_GET_CHANINFO:
		oui = MTK_NL80211_VENDOR_ID;
		subcmd = MTK_NL80211_VENDOR_SUBCMD_GET_RUNTIME_INFO;
		subcmd_id = MTK_NL80211_VENDOR_ATTR_GET_RUNTIME_INFO_GET_CHANINFO;
		break;
	case AWN_CMD_GET_CACNOPSTATUS:
		oui = MTK_NL80211_VENDOR_ID;
		subcmd = MTK_NL80211_VENDOR_SUBCMD_GET_RUNTIME_INFO;
		subcmd_id = MTK_NL80211_VENDOR_ATTR_GET_RUNTIME_INFO_GET_CACNOPSTATUS;
		break;
	case AWN_CMD_AP_PHYINFO:
		oui = MTK_NL80211_VENDOR_ID;
		subcmd = MTK_NL80211_VENDOR_SUBCMD_GET_RUNTIME_INFO;
		subcmd_id = MTK_NL80211_VENDOR_ATTR_GET_RUNTIME_INFO_GET_PHYCAPINFO;
		p_cmm_data = data;
		cmm_len = sizeof(WLAN_PHYINFO);
		break;
	case AWN_CMD_GET_SCAN_STATUS:
		oui = MTK_NL80211_VENDOR_ID;
		subcmd = MTK_NL80211_VENDOR_SUBCMD_GET_RUNTIME_INFO;
		subcmd_id = MTK_NL80211_VENDOR_ATTR_GET_RUNTIME_INFO_GET_SCAN_STATUS;
		break;
	default:
		break;
	}
	
	if (oui && subcmd)
	{
		NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, oui);
		NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD, subcmd);
	}

	/*
	 参考 nla_reserve()@dl/libnl-tiny-/attr.c
	 tlen = NLMSG_ALIGN(msg->nm_nlh->nlmsg_len) + nla_total_size(attrlen);
	 if ((tlen + msg->nm_nlh->nlmsg_len) > msg->nm_size)
		return NULL;
	 (Bug?? msg->nm_nlh->nlmsg_len used 2 times)

	 unl_genl_msg() 分配的msg大小( nm_size)是4096。一些sub_cmd_id的data太长了，在进行到 
	 handle_common_command-nla_put-nla_reserve时，判断msg剩余长度不够用时，就会报错退出。
	 其实nla_put传入的data和len只要不为空就行，driver并不会使用这些传回数据，因此这里对于
	 这种情况直接替换为较短的buf。
	*/
	if (subcmd_id != 0){
		if (p_cmm_data == NULL)
		{
			//printf("sub_cmd_id:%d, nm_size:%d, nlmsg_len:%d/%d, u32/nla_u32:%d/%d\n", sub_cmd_id, msg->nm_size, 
			//	msg->nm_nlh->nlmsg_len, NLMSG_ALIGN(msg->nm_nlh->nlmsg_len),
			//	sizeof(if_idx), nla_total_size(sizeof(if_idx)));
			// All subcmd_ids that do not require parameter use the default parameters
			p_cmm_data = cmm_data;
			cmm_len = strlen(cmm_data);
		}

		if (handle_common_command(msg, subcmd_id, p_cmm_data, cmm_len))
		{
			printf("Failed to handle_common_command()\n");
			ret = -1;
			nlmsg_free(msg);
			goto out;
		}
	}
	
	nl_socket_set_cb(nlstate.nl_sock, s_cb);

	ret = nl_send_auto_complete(nlstate.nl_sock, msg);
	if (ret < 0)
	{
		AWN_LOG_ERR("failed to nl_send_auto_complete, ret=%d\n", ret);
		goto out;
	}

	ret = 1;
	nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &ret);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &ret);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &ret);
	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_handler, NULL);

	while (ret > 0)
	{
		ret = nl_recvmsgs(nlstate.nl_sock, cb);
		if (ret == -NLE_DUMP_INTR) {
			/* Most likely one of the nl80211 dump routines hit a
			 * case where internal results changed while the dump
			 * was being sent. The most common known case for this
			 * is scan results fetching while associated were every
			 * received Beacon frame from the AP may end up
			 * incrementing bss_generation. This
			 * NL80211_CMD_GET_SCAN case tries again in the caller;
			 * other cases (of which there are no known common ones)
			 * will stop and return an error. */
			fprintf(stderr, "nl80211: get NLE_DUMP_INTR; convert to -EAGAIN\n");
			ret = -EAGAIN;
		}
	}
out:
	nl_cb_put(cb);
	nl_cb_put(s_cb);
	nlmsg_free(msg);
END:
	nl80211_cleanup(&nlstate);
	return ret;

nla_put_failure:
	nl80211_cleanup(&nlstate);
	return ret;
}

/*-----------------------------------------------------*
 *------------   Public API function   ----------------*
 *-----------------------------------------------------*/

/* trigger scan
 * para:
 *     in @ifname: which wifi interface
 *     out @data: record sta info which extrace from driver data
 *         @data_len: len of final data
 * return: 0 for success; others for fail
 */
int awn_cfg80211_scan(const char *ifname, TP_SCAN_PARAM *scan_params)
{
	int ret = 0;

	if (ifname == NULL || scan_params == NULL)
	{
		AWN_LOG_ERR("%s:detect NULL pointer in param\n", __func__);
		return -1;
	}

	ret = wifi_cfg80211_send_cmd(ifname, AWN_CMD_START_SCAN, NULL, 1, scan_params);
	if (ret)
	{
		perror("start scan fail");
	}

	return ret;
}

/* get scan results
 * para:
 *     in @ifname: which wifi interface
 *     out @data: record sta info which extrace from driver data
 *         @data_len: len of final data
 * return: 0 for success; others for fail
 */
int awn_cfg80211_scan_result(const char *ifname, void *data, int *data_len)
{
	MTK_SCAN_RESULT *bss_list = NULL;
	MTK_SCAN_ENTRY *bss_entry = NULL;
	TP_CFG80211_SCAN_RESULTS scan_results;
	int count = 0;
	int i = 0;
	int idx = 0;
	int ret = 0;

	if (ifname == NULL || data == NULL || data_len == NULL)
	{
		AWN_LOG_ERR("%s:detect NULL pointer in param\n", __func__);
		return -1;
	}

try_again:
	memset(&scan_results, 0, sizeof(scan_results));

	ret = wifi_cfg80211_send_cmd(ifname, AWN_CMD_SCAN_RESULT, &scan_results, 0, NULL);
	if (ret)
	{
		if (ret == -EAGAIN)
		{
			count++;
			if (count >= 10)
			{
				AWN_LOG_ERR("%s: Failed to receive consistent scan result\n", __func__);
			}
			else
			{
				AWN_LOG_ERR("%s: Failed to receive consistent scan result - try again\n", __func__);
				goto try_again;
			}
		}

		perror("get scan result fail");
	}
	else
	{
		bss_list = (MTK_SCAN_RESULT *)data;
		for (i = 0; i < scan_results.bss_num && idx < TP_SCAN_ENTRY_MAX_NUM; i++)
		{
			bss_entry = &bss_list->scan_entry[idx];

			if (scan_results.bss_entry[i].ssid_len > 0)
			{
				memcpy(bss_entry->ssid, scan_results.bss_entry[i].ssid, scan_results.bss_entry[i].ssid_len);
				bss_entry->ssidLen = scan_results.bss_entry[i].ssid_len;
			}

			if (scan_results.bss_entry[i].tpie_len > 0)
			{
				memcpy(&bss_entry->netInfo.netInfo, scan_results.bss_entry[i].tpie, scan_results.bss_entry[i].tpie_len);
				bss_entry->netInfo.tpie_len = scan_results.bss_entry[i].tpie_len;
			}

			memcpy(bss_entry->bssid, scan_results.bss_entry[i].bssid, MAC_ADDR_LEN);
			bss_entry->freq = scan_results.bss_entry[i].freq;
			bss_entry->channel = ieee80211_frequency_to_channel(scan_results.bss_entry[i].freq);
			if (scan_results.bss_entry[i].level < -95) {
				bss_entry->rssi = 0;
			} else if (scan_results.bss_entry[i].level > 0) {
				bss_entry->rssi = 95;
			} else {
				bss_entry->rssi = (uint8_t)(scan_results.bss_entry[i].level + 95);
			}
			idx++;
		}
		bss_list->count = idx;
		*data_len = bss_list->count * sizeof(MTK_SCAN_ENTRY) + sizeof(bss_list->count);
	}

	return ret;
}

/*
 * Get TPIE from driver through Netlink
 * para:
 *     in @ifname: which wifi interface
 *     out @data: record TPIE which extrace from driver data
 *         @data_len: len of final data
 * return: 0 for success; others for fail
 */
int awn_cfg80211_get_tpie(const char *ifname, TPIE_SEARCH_ENTRY *pSearchEntry, void *data, int *data_len)
{
	int ret = AWND_OK;
	TP_CFG80211_VENDOR_DATA vendor_data;

	if (ifname == NULL || data == NULL || data_len == NULL)
	{
		AWN_LOG_DEBUG("detect NULL pointer in param\n");
		return AWND_ERROR;;
	}

	memset(&vendor_data, 0, sizeof(vendor_data));
	ret = wifi_cfg80211_send_cmd(ifname, AWN_CMD_GET_TPIE, &vendor_data, 1, pSearchEntry);
	if (ret)
	{
		AWN_LOG_DEBUG("get tpie fail\n");
		ret = AWND_ERROR;
	}
	else
	{
		if (vendor_data.data_len > 0)
		{
			if (vendor_data.data_len == 4 && memcmp(vendor_data.data, "err", 3) == 0)
			{
				ret = AWND_NOT_FOUND;
			}
			else
			{
				if (vendor_data.data_len > sizeof(AWND_NET_INFO)) {
					*data_len = sizeof(AWND_NET_INFO);
				} else {
					*data_len = vendor_data.data_len;
				}
				memcpy(data, vendor_data.data, *data_len);
				AWN_LOG_DEBUG("final data len is:%d, vendor_data len is:%d\n", *data_len, vendor_data.data_len);
			}
		}
		else
		{
			ret = AWND_ERROR;
		}

		if (vendor_data.data != NULL)
		{
			free(vendor_data.data);
		}
	}

	return ret;
}

/*
 * Get sta interface info from driver through Netlink
 * para:
 *	   in @ifname: which sta interface name
 *	   out @data: record chanutil which extrace from driver data
 *		   @data_len: len of final data
 * return: 0 for success; others for fail
 */
int awn_cfg80211_get_sta_info(const char *ifname, void *data, int *data_len)
{
	int ret = 0;

	if (ifname == NULL || data == NULL || data_len == NULL)
	{
		AWN_LOG_ERR("detect NULL pointer in param");
		return -1;
	}

	ret = wifi_cfg80211_send_cmd(ifname, AWN_CMD_GET_STAINFO, data, 0, NULL);
	if (ret)
	{
		perror("get sta_info fail");
	}

	return ret;
}

int awn_cfg80211_get_channel_info(const char *ifname, void *data, int *data_len)
{
	int ret = 0;

	if (ifname == NULL || data == NULL || data_len == NULL)
	{
		AWN_LOG_ERR("detect NULL pointer in param");
		return -1;
	}

	ret = wifi_cfg80211_send_cmd(ifname, AWN_CMD_GET_CHANINFO, data, 0, NULL);
	if (ret)
	{
		perror("get sta_info fail");
	}

	return ret;
}


/* Get vap info from driver through Netlink
 * para:
 *	   in @ifname: which wifi interface
 *	   out @data: record sta info which extrace from driver data
 *		   @data_len: len of final data
 * return: 0 for success; others for fail
 */
int awn_cfg80211_get_vap_info(const char *ifname, void *data, int *data_len)
{
	TP_VAP_INFO *cfg80211_ap_info = NULL;
	int ret = 0;

	if (ifname == NULL || data == NULL || data_len == NULL)
	{
		fprintf(stderr, "%s:detect NULL pointer in param\n", __func__);
		return -1;
	}

	cfg80211_ap_info = (TP_VAP_INFO *)data;

	ret = wifi_cfg80211_send_cmd(ifname, AWN_CMD_AP_INFO, cfg80211_ap_info, 0, NULL);
	if (ret)
	{
		perror("get vap_info fail");
	}
	else
	{
		*data_len = sizeof(TP_VAP_INFO);
	}

	return ret;
}

/* Get AP phy cap info from driver through Netlink
 * para:
 *     in @ifname: which wifi interface
 *     out @data: record phy info which extrace from driver data
 *         @data_len: len of final data
 * return: 0 for success; others for fail
 */
int awn_cfg80211_get_ap_phyinfo(const char *ifname, void *data, int *data_len)
{
	TP_PHYCAP_INFO *phy_info = (TP_PHYCAP_INFO *)data;
	TP_VAP_INFO cfg80211_ap_info;
	char phy_name[10] = {'\0'};
	int ret = 0;
	WLAN_PHYINFO wlan_phyinfo;

	if (ifname == NULL || data == NULL || data_len == NULL)
	{
		fprintf(stderr, "%s:detect NULL pointer in param\n", __func__);
		return -1;
	}

	/* get the mac first*/
	memset(&cfg80211_ap_info, 0, sizeof(cfg80211_ap_info));
	ret = wifi_cfg80211_send_cmd(ifname, AWN_CMD_AP_INFO, &cfg80211_ap_info, 0, NULL);
	if (ret)
	{
		perror("PHY info: get ap_info fail");
	}
	else
	{
		memcpy(wlan_phyinfo.mac, cfg80211_ap_info.mac, MAC_ADDR_LEN);
		memset(phy_info, 0, sizeof(TP_PHYCAP_INFO));
		ret = wifi_cfg80211_send_cmd(ifname, AWN_CMD_AP_PHYINFO, &wlan_phyinfo, 0, NULL);
		if (ret)
		{
			perror("get ap_phyinfo fail");
		}
		phy_info->maxMCS = wlan_phyinfo.phycap.maxMCS;
		phy_info->numStreams = wlan_phyinfo.phycap.numStreams;
		phy_info->phyMode = wlan_phyinfo.phycap.phyMode;
		phy_info->maxChWidth = wlan_phyinfo.phycap.maxChWidth;
		*data_len = sizeof(TP_PHYCAP_INFO);
	}
	return ret;
}


int awn_cfg80211_get_cacnopstatus(const char *ifname, void *data, int *data_len)
{
	int ret = 0;

	if (ifname == NULL || data == NULL || data_len == NULL)
	{
		AWN_LOG_ERR("detect NULL pointer in param");
		return -1;
	}

	ret = wifi_cfg80211_send_cmd(ifname, AWN_CMD_GET_CACNOPSTATUS, data, 0, NULL);
	if (ret)
	{
		AWN_LOG_ERR("get cacnopstatus fail");
	}
	return ret;
}

int awn_cfg80211_get_scan_status(const char *ifname, void *data, int *data_len)
{
	int ret = 0;

	if (ifname == NULL || data == NULL || data_len == NULL)
	{
		AWN_LOG_ERR("detect NULL pointer in param");
		return -1;
	}

	ret = wifi_cfg80211_send_cmd(ifname, AWN_CMD_GET_SCAN_STATUS, data, 0, NULL);
	if (ret)
	{
		AWN_LOG_ERR("get scan status fail");
	}
	return ret;
}


