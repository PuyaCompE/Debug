/*
 * Copyright (c) 2006-2020 TP-Link Technologies CO.,LTD. All rights reserved.
 * 
 * File name       : ping.c
 * Description     :
 * 
 * Author          : Wu Kan
 * Date Created    : 2020-05-15
 */
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <libubox/uloop.h>

#include <aidata.h>
#include <aimsg.h>
#include <dataInterface.h>

#include "ai_nwk_defines.h"
#include "awn_log.h"
#include "auto_wifi_net.h"
#include "aimsg_handler.h"



/* -------------------------------------------------------------------------- */
/*                                   DEFINES                                  */
/* -------------------------------------------------------------------------- */
#define IPV4_BIT_SHIFT(_d, _bits)   (uint8_t)((_d>>_bits)&0xff)
#define IPV4_ADDR_FMT               "%hhu.%hhu.%hhu.%hhu"
#define IPV4_ADDR_DATA(_d) \
    IPV4_BIT_SHIFT(_d, 24), \
    IPV4_BIT_SHIFT(_d, 16), \
    IPV4_BIT_SHIFT(_d, 8), \
    IPV4_BIT_SHIFT(_d, 0)


#define MAX_PING_NUM            ALG_TimeDelayTestCnt
#define PING_INTERVAL_MS        200
#define PING_TIMEOUT_MS         ALG_MAX_DELAY_TIME

struct icmp_ping_sock {
    struct uloop_fd sock;
    int cnt_waiting;
};

struct icmp_ping_query {
    int n_sent;
    int n_recv;
    uint16_t seq;
    uint16_t delay_ms;
};

struct icmp_ping_state {
    bool busy;
    int num;
    int num_sent;
    int num_handled;
    uint32_t timeout_ms;
    uint32_t interval_ms;
    struct sockaddr_in addr;
    uint8_t dst_mac[6];
    struct icmp_ping_query queries[MAX_PING_NUM];
};


/* -------------------------------------------------------------------------- */
/*                              EXTERN PROTOTYPES                             */
/* -------------------------------------------------------------------------- */


/* -------------------------------------------------------------------------- */
/*                              LOCAL PROTOTYPES                              */
/* -------------------------------------------------------------------------- */
static int ping_query_init(void);
static int ping_query_fini(void);
static void ping_state_clear(void);
static int ping_sock_wait(void);
static void ping_sock_leave(void);
static uint16_t calculate_checksum(uint8_t *buf, int bytes);
static int pack_echo_packet(struct icmp *packet, uint16_t seq);
static int ping_send(int sd, uint16_t seq, int n_dup);
static int ping_recv(int sd);
static void ping_reply_timeout_cb(struct uloop_timeout *timeout);
static void ping_interval_timeout_cb(struct uloop_timeout *timeout);
static int ping_all_done(void);
static int ping_finish(void);
static void ping_read_cb(struct uloop_fd *u, unsigned int events);


/* -------------------------------------------------------------------------- */
/*                                  VARIABLES                                 */
/* -------------------------------------------------------------------------- */
static struct icmp_ping_sock ping_sock = {
    .sock = {
        .fd = -1,
        .cb = ping_read_cb,
    },
    .cnt_waiting = 0,
};
static struct icmp_ping_state ping_state = {0};
static struct uloop_timeout ping_interval_timeout = {
    .cb = ping_interval_timeout_cb,
};
static struct uloop_timeout ping_reply_timeout = {
    .cb = ping_reply_timeout_cb,
};
static uint16_t ping_seq = 0;
static uint8_t parent_mac[6] = {0};


/* -------------------------------------------------------------------------- */
/*                               LOCAL FUNCTIONS                              */
/* -------------------------------------------------------------------------- */
static int ping_query_init(void)
{
    memset(&ping_state, 0, sizeof(ping_state));

    return 0;
}

static int ping_query_fini(void)
{
    memset(&ping_state, 0, sizeof(ping_state));
    return 0;
}

static void ping_state_clear(void) {
    ping_state.busy = false;
    memset(&ping_state, 0, sizeof(ping_state));
    memset(ping_state.queries, 0, sizeof(ping_state.queries));
}

static int ping_sock_wait(void)
{
    if (ping_sock.cnt_waiting == 0) {
        ping_sock.sock.fd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (ping_sock.sock.fd < 0) {
            AWN_LOG_ERR("Fail to create socket: %s", strerror(errno));
            return -1;
        }
        AWN_LOG_DEBUG("ICMP socket created.");
        uloop_fd_add(&ping_sock.sock, ULOOP_READ);
    }

    ping_sock.cnt_waiting++;
    return 0;
}

static void ping_sock_leave(void)
{
    if (--ping_sock.cnt_waiting == 0) {
        uloop_fd_delete(&ping_sock.sock);
        close(ping_sock.sock.fd);
        ping_sock.sock.fd = -1;
    }
}

static uint16_t calculate_checksum(uint8_t *buf, int bytes)
{
    uint32_t checksum = 0;
    uint32_t carry;
    uint8_t *end = buf + bytes;

    /* odd bytes add last byte and reset end */
    if (bytes % 2 == 1) {
        end = buf + bytes - 1;
        checksum += (*end) << 8;
    }

    /* add words of 16bit, one by one */
    while (buf < end) {
        checksum += buf[0] << 8;
        checksum += buf[1];
        buf += 2;
    }

    /* carry handle */
    carry = checksum >> 16;
    while (carry) {
        checksum = (checksum & 0xffff) + carry;
        carry = checksum >> 16;
    }

    /* negate checksum */
    checksum = ~checksum;
    return (uint16_t)(checksum & 0xffff);
}

static int pack_echo_packet(struct icmp *packet, uint16_t seq)
{
    static uint16_t pid = 0;
    int packet_len = 0;
    uint8_t *data;

    assert(packet != NULL);

    if (pid == 0) {
        pid = (uint16_t)getpid();
    }

    packet->icmp_type = ICMP_ECHO;
    packet->icmp_code = 0;
    packet->icmp_cksum = 0;
    packet->icmp_id = htons(pid);
    packet->icmp_seq = htons(seq);

    data = (uint8_t *)packet + ICMP_MINLEN;

    if (gettimeofday((struct timeval *)data, NULL) < 0) {
        memset(data, 0, sizeof(struct timeval));
    }

    packet_len = ICMP_MINLEN + sizeof(struct timeval);
    packet->icmp_cksum = htons(calculate_checksum((uint8_t *)packet, packet_len));
    return packet_len;
}

static int ping_send(int sd, uint16_t seq, int n_dup)
{
    /*
    uint8_t *buf;
    buf = (uint8_t *)malloc(100);
    struct *p_packet = (struct icmp *)buf;
    */
    struct icmp packet;
    int len = 0;
    int n_sent = 0;
    for (n_sent = 0; n_sent < n_dup; n_sent++) {
        len = pack_echo_packet(&packet, seq);
        if ((sendto(sd, (void *)&packet, len, 0,
            (struct sockaddr *)&ping_state.addr,
            sizeof(ping_state.addr))) < 0) {
            AWN_LOG_ERR("Fail to send ICMP: %s", strerror(errno));
            return n_sent;
        }
    }
    return n_sent;
}

static int ping_recv(int sd)
{
    static struct timeval tv_recv;
    struct icmp *icmp_hdr = NULL;
    struct ip *ip_hdr = NULL;
    struct timeval *tv_sent;
    uint16_t seq = 0;
    int len_recv;
    int ping_ind = ping_state.num_handled;
    uint16_t delay_ms = 0;
    struct sockaddr_in addr_from;
    int alen = sizeof(addr_from);

#define SIZE_EXPECTED \
    (sizeof(struct ip) + ICMP_MINLEN + sizeof(struct timeval))
#define RECV_BUF_SIZE       4096
    uint8_t buf[RECV_BUF_SIZE] = {0};
    gettimeofday(&tv_recv, NULL);

    while ((len_recv = recvfrom(sd, buf, RECV_BUF_SIZE, 0,
        (struct sockaddr *)&addr_from, &alen)) > 0) {
        if (len_recv < SIZE_EXPECTED) {
            AWN_LOG_NOTICE("len_recv(%d) too small. %d expected.",
                len_recv, SIZE_EXPECTED);
            continue;
        }

        ip_hdr = (struct ip *)buf;
        if (ip_hdr->ip_src.s_addr != ping_state.addr.sin_addr.s_addr) {
            AWN_LOG_INFO("Ping response from different IP: 0x%08X.",
                ntohl(ip_hdr->ip_src.s_addr));
            continue;
        }

        icmp_hdr = (struct icmp *)(buf + sizeof(struct ip));
        if (icmp_hdr->icmp_type != ICMP_ECHOREPLY ||
            icmp_hdr->icmp_id != htons((uint16_t)getpid())) {
            continue;
        }

        tv_sent = (struct timeval *)icmp_hdr->icmp_data;
        delay_ms = (uint16_t)(tv_recv.tv_sec - tv_sent->tv_sec +
            tv_recv.tv_usec/1000 - tv_sent->tv_usec/1000);
        seq = ntohs(icmp_hdr->icmp_seq);
        AWN_LOG_INFO("Received ping response. Seq: %hu, Delay: %hums.",
            seq, delay_ms);
        if (seq != ping_seq) {
            AWN_LOG_NOTICE("Seq received is different from waiting for.");
            continue;
        }

        ping_state.queries[ping_ind].delay_ms = delay_ms;
        ping_state.queries[ping_ind].n_recv++;
        ping_state.num_handled++;
        ping_sock_leave();
        uloop_timeout_cancel(&ping_reply_timeout);
        if (ping_all_done()) {
            ping_finish();
        } else {
            /* Send another ping packet */
            uloop_timeout_set(&ping_interval_timeout, ping_state.interval_ms);
        }
        return ping_state.queries[ping_ind].n_recv;
    }

    return 0;
}

static void ping_reply_timeout_cb(struct uloop_timeout *timeout)
{
    AWN_LOG_INFO("Ping timeout of seq(%hu).", ping_seq);
    ping_sock_leave();
    if (ping_all_done()) {
        ping_finish();
        return;
    }

    ping_state.num_handled++;
    if (ping_all_done()) {
        ping_finish();
        return;
    }
    uloop_timeout_set(&ping_interval_timeout, ping_state.interval_ms);
}

static void ping_interval_timeout_cb(struct uloop_timeout *timeout)
{
    int ind = ping_state.num_sent;
    if (ping_state.num_sent < ping_state.num) {
        if (++ping_seq == 0) {
            ++ping_seq;
        }

        ping_sock_wait();
        ping_state.queries[ind].n_sent = ping_send(
            ping_sock.sock.fd, ping_seq, 1);
        ping_state.queries[ind].seq = ping_seq;
        ping_state.num_sent++;
        if (ping_state.queries[ind].n_sent == 0) {
            ping_state.num_handled++;
            AWN_LOG_ERR("Fail to send ping packet of seq(%hu).", ping_seq);
            ping_sock_leave();
            if (ping_all_done()) {
                ping_finish();
            } else {
                uloop_timeout_set(&ping_interval_timeout,
                    ping_state.interval_ms);
            }
            return;
        }
        AWN_LOG_INFO("%d ping pakcets sent with seq(%hu).", ind, ping_seq);
        uloop_timeout_set(&ping_reply_timeout, ping_state.timeout_ms);
    }
}

static int ping_all_done(void)
{
    if (ping_state.num_handled < ping_state.num) {
        return 0;
    }
    return 1;
}

static int ping_finish(void)
{
    int i;
    TimeDelayInfo delay = {0};

    AWN_LOG_INFO("Ping process over.");

    snprintf(delay.fatherMAC, sizeof(delay.fatherMAC),
        MAC_ADDR_FMT, MAC_ADDR_DATA(ping_state.dst_mac));

    for (i = 0; i < ping_state.num; i++) {
        AWN_LOG_INFO("ping at ind(%d), seq(%hu) delay(%hums)", i,
            ping_state.queries[i].seq,
            ping_state.queries[i].delay_ms);
        delay.delayTime[i] = ping_state.queries[i].delay_ms;
    }
    ping_state_clear();
    if (ping_sock.cnt_waiting != 0) {
        ping_sock.cnt_waiting = 0;
        close(ping_sock.sock.fd);
    }

    /* ALG TODO */
    /* save time delay info to file */
    updateSingleTimeDelayInfo(AR_TIME_DELAY_INFO_FILE, &delay);
    // alg todo: only for debug used.
    // appendSingleTimeDelayInfo("/tmp/dynamicNetworking/debugTimeDelayInfo.txt", &delay);
    
    update_devinfo();
    re_alg_process();

    // struct timeval tv = {0};
    // gettimeofday(&tv, NULL);
    // uint32_t cost_time = tv.tv_sec - alg_time_stamp;
    // AWN_LOG_NOTICE("[info] Total time cost is (%u) seconds.", cost_time);

    return 0;
}

static void ping_read_cb(struct uloop_fd *u, unsigned int events)
{
    if (events & ULOOP_READ) {
        ping_recv(u->fd);
    }
}


/* -------------------------------------------------------------------------- */
/*                              PUBLIC FUNCTIONS                              */
/* -------------------------------------------------------------------------- */

int ping_lanip(uint32_t lanip)
{
    if (ping_state.busy) {
        AWN_LOG_NOTICE("Last echo ping still running.");
        return -1;
    }

    if (ping_query_init() < 0) {
        AWN_LOG_ERR("Fail to init a ping query.");
        ping_query_fini();
        return -1;
    }
    
    memcpy(ping_state.dst_mac, parent_mac, 6);
    ping_state.addr.sin_family = AF_INET;
    ping_state.addr.sin_port = 0;
    ping_state.addr.sin_addr.s_addr = htonl(lanip);
    AWN_LOG_NOTICE("Sending ping to "IPV4_ADDR_FMT,
        IPV4_ADDR_DATA(lanip));

    ping_state.interval_ms = PING_INTERVAL_MS;
    ping_state.timeout_ms = PING_TIMEOUT_MS;
    ping_state.num = MAX_PING_NUM;
    ping_state.busy = 1;
    uloop_timeout_set(&ping_interval_timeout, 1);

    return 0;
}

int set_parent_mac(uint8_t *p_mac)
{
    if (!p_mac) {
        memset(parent_mac, 0, 6);
        return -1;
    }

    memcpy(parent_mac, p_mac, 6);
    return 0;
}
#endif  /* CONFIG_AWN_MESH_OPT_SUPPORT */