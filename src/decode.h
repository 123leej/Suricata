/* Copyright (C) 2007-2010 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef __DECODE_H__
#define __DECODE_H__

#define NFQ
#define COUNTERS

#include "threadvars.h"

#include "source-nfq.h"

#include "action-globals.h"

#include "decode-lorawan-frame.h"
#include "decode-lorawan-Mac.h"

#include "detect-reference.h"


/* forward declaration */
struct DetectionEngineThreadCtx_;


/* EUI */
typedef struct EUI_ {
    uint64_t deveui;
    uint64_t appeui;
} EUI;


#define SET_LORAWAN_EUI (pkt, eui) do {                  \
        (eui)->deveui = (pkt)->deveui;                            \
        (eui)->appeui = (pkt)->appeui;                            \
    } while(0)


#define CLEAR_EUI (pkt, eui) do {                                 \
        (eui)->deveui = 0;                                        \
        (eui)->appeui = 0;                                        \
    } while(0)


#define COPY_EUI (a, b) do {                                      \
        (a)->deveui = (b)->deveui;                                \
        (a)->appeui = (b)->appeui;                                \
    } while(0)


#define GET_LORAWAN_DEVEUI(pkt) ((pkt)->deveui)
#define GET_LORAWAN_APPEUI(pkt) ((pkt)->appeui)


#define CMP_EUI(e1, e2)                                           \
    (((e1)->deveui == (e2)->deveui &&                             \
      (e1)->appeui == (e2)->appeui ))


#define PKT_IS_IPV4(p)      (((p)->ip4h != NULL))
#define PKT_IS_IPV6(p)      (((p)->ip6h != NULL))
#define PKT_IS_TCP(p)       (((p)->tcph != NULL))
#define PKT_IS_UDP(p)       (((p)->udph != NULL))
#define PKT_IS_LORAWAN(p)   (((p)->LorawanMacHdr != NULL))
#define PKT_IS_TOSERVER(p)  (((p)->UNCONFIRMED_DATA_UP | CONFIRMED_DATA_UP))
#define PKT_IS_TOMOTE(p)    (((p)->UNCONFIRMED_DATA_DOWN | CONFIRMED_DATA_DOWN))

#define IPH_IS_VALID(p) (PKT_IS_IPV4((p)) || PKT_IS_IPV6((p)))

/* structure to store the sids/gids/etc the detection engine
 * found in this packet */
typedef struct PacketAlert_ {
    SigIntId num; /* Internal num, used for sorting */
    SigIntId order_id; /* Internal num, used for sorting */
    uint8_t action; /* Internal num, used for sorting */
    uint32_t  gid;
    uint32_t sid;
    uint8_t  rev;
    uint8_t class;
    uint8_t prio;
    char *msg;
    char *class_msg;
    Reference *references;
} PacketAlert;

#define PACKET_ALERT_MAX 256

typedef struct PacketAlerts_ {
    uint16_t cnt;
    PacketAlert alerts[PACKET_ALERT_MAX];
} PacketAlerts;

#define PACKET_DECODER_EVENT_MAX 16

typedef struct PacketDecoderEvents_ {
    uint8_t cnt;
    uint8_t events[PACKET_DECODER_EVENT_MAX];
} PacketDecoderEvents;

typedef struct PktVar_ {
    char *name;
    struct PktVar_ *next; /* right now just implement this as a list,
                           * in the long run we have thing of something
                           * faster. */
    uint8_t *value;
    uint16_t value_len;
} PktVar;

/* forward declartion since Packet struct definition requires this */
struct PacketQueue_;

/* sizes of the members:
 * src: 17 bytes
 * dst: 17 bytes
 * sp/type: 1 byte
 * dp/code: 1 byte
 * proto: 1 byte
 * recurs: 1 byte
 *
 * sum of above: 38 bytes
 *
 * flow ptr: 4/8 bytes
 * flags: 1 byte
 * flowflags: 1 byte
 *
 * sum of above 44/48 bytes
 */
typedef struct Packet_
{
    /* Addresses, Ports and protocol
     * these are on top so we can use
     * the Packet as a hash key */
    union {
        uint64_t index_no;
        u_int8_t of_flag;
    };

    union {
        EUI eui;
        uint8_t direction;
    };
    uint8_t proto;

    /* Pkt Flags */
    uint8_t flags;
    /* flow */
    uint8_t flowflags;
    struct Flow_ *flow;

    struct timeval ts;

    NFQPacketVars nfq_v;

    /* IPS action to take */
    uint8_t action;

    /* pkt vars */
    PktVar *pktvar;

    LorawanMacHdr *lorawanmh;
    LorawanMacVars * lorawanmvars;

    LorawanFrameHdr *lorawanfh;
    LorawanFrameVars *lorawanfvars;
    LorawanFrameCtrl *lorawanfctl;

    uint8_t *payload;
    uint16_t payload_len;

    /* storage: maximum ip packet size + link header */
    uint8_t pkt[IPV6_HEADER_LEN + 65536 + 28];
    uint32_t pktlen;

    PacketAlerts alerts;

    /* ready to set verdict counter, only set in root */
    uint8_t rtv_cnt;
    SCMutex mutex_rtv_cnt;

    /* decoder events */
    PacketDecoderEvents events;

    /* double linked list ptrs */
    struct Packet_ *next;
    struct Packet_ *prev;

    /* tunnel/encapsulation handling */
    struct Packet_ *root; /* in case of tunnel this is a ptr
                           * to the 'real' packet, the one we
                           * need to set the verdict on --
                           * It should always point to the lowest
                           * packet in a encapsulated packet */
} Packet;

typedef struct PacketQueue_ {
    Packet *top;
    Packet *bot;
    uint16_t len;
    SCMutex mutex_q;
    SCCondT cond_q;
#ifdef DBG_PERF
    uint16_t dbg_maxlen;
#endif /* DBG_PERF */
} PacketQueue;

///** \brief Specific ctx for AL proto detection */
//typedef struct AlpProtoDetectDirectionThread_ {
//    MpmThreadCtx mpm_ctx;
//    PatternMatcherQueue pmq;
//} AlpProtoDetectDirectionThread;
//
///** \brief Specific ctx for AL proto detection */
//typedef struct AlpProtoDetectThreadCtx_ {
//    AlpProtoDetectDirectionThread toserver;
//    AlpProtoDetectDirectionThread toclient;
//} AlpProtoDetectThreadCtx;

/** \brief Structure to hold thread specific data for all decode modules */
typedef struct DecodeThreadVars_
{
    /** Specific context for udp protocol detection (here atm) */
    AlpProtoDetectThreadCtx udp_dp_ctx;

    /** stats/counters */
    uint16_t counter_lorawan_dataframe;
    uint16_t counter_lorawan_mac;
    uint16_t counter_pkts;
    uint16_t counter_pkts_per_sec;
    uint16_t counter_bytes;
    uint16_t counter_bytes_per_sec;
    uint16_t counter_mbit_per_sec;
    uint16_t counter_ipv4;
    uint16_t counter_ipv6;
    uint16_t counter_eth;
    uint16_t counter_sll;
    uint16_t counter_tcp;
    uint16_t counter_udp;
    uint16_t counter_avg_pkt_size;
    uint16_t counter_max_pkt_size;

    /** frag stats - defrag runs in the context of the decoder. */
    uint16_t counter_defrag_ipv4_fragments;
    uint16_t counter_defrag_ipv4_reassembled;
    uint16_t counter_defrag_ipv4_timeouts;
    uint16_t counter_defrag_ipv6_fragments;
    uint16_t counter_defrag_ipv6_reassembled;
    uint16_t counter_defrag_ipv6_timeouts;
} DecodeThreadVars;

/**
 *  \brief reset these to -1(indicates that the packet is fresh from the queue)
 */
#define PACKET_RESET_CHECKSUMS(p) do { \
        (p)->ip4c.comp_csum = -1;      \
        (p)->tcpc.comp_csum = -1;      \
        (p)->udpc.comp_csum = -1;      \
    } while (0)

/**
 *  \brief Initialize a packet structure for use.
 */
#define PACKET_INITIALIZE(p) { \
    memset((p), 0x00, sizeof(Packet)); \
    SCMutexInit(&(p)->mutex_rtv_cnt, NULL); \
    PACKET_RESET_CHECKSUMS((p)); \
}



/**
 *  \brief Recycle a packet structure for reuse.
 *  \todo the mutex destroy & init is necessary because of the memset, reconsider
 */
#define PACKET_DO_RECYCLE(p) do {               \
        CLEAR_ADDR(&(p)->src);                  \
        CLEAR_ADDR(&(p)->dst);                  \
        (p)->sp = 0;                            \
        (p)->dp = 0;                            \
        (p)->proto = 0;                         \
        (p)->recursion_level = 0;               \
        (p)->flags = 0;                         \
        (p)->flowflags = 0;                     \
        (p)->flow = NULL;                       \
        (p)->ts.tv_sec = 0;                     \
        (p)->ts.tv_usec = 0;                    \
        (p)->datalink = 0;                      \
        (p)->action = 0;                        \
        if ((p)->pktvar != NULL) {              \
            PktVarFree((p)->pktvar);            \
            (p)->pktvar = NULL;                 \
        }                                       \
        (p)->ethh = NULL;                       \
        if ((p)->ip4h != NULL) {                \
            CLEAR_IPV4_PACKET((p));             \
        }                                       \
        if ((p)->ip6h != NULL) {                \
            CLEAR_IPV6_PACKET((p));             \
        }                                       \
        if ((p)->tcph != NULL) {                \
            CLEAR_TCP_PACKET((p));              \
        }                                       \
        if ((p)->udph != NULL) {                \
            CLEAR_UDP_PACKET((p));              \
        }                                       \
        (p)->payload = NULL;                    \
        (p)->payload_len = 0;                   \
        (p)->pktlen = 0;                        \
        (p)->alerts.cnt = 0;                    \
        (p)->next = NULL;                       \
        (p)->prev = NULL;                       \
        (p)->rtv_cnt = 0;                       \
        (p)->tpr_cnt = 0;                       \
        SCMutexDestroy(&(p)->mutex_rtv_cnt);    \
        SCMutexInit(&(p)->mutex_rtv_cnt, NULL); \
        (p)->tunnel_proto = 0;                  \
        (p)->tunnel_pkt = 0;                    \
        (p)->tunnel_verdicted = 0;              \
        (p)->events.cnt = 0;                    \
        (p)->root = NULL;                       \
        PACKET_RESET_CHECKSUMS((p));            \
    } while (0)

#define PACKET_RECYCLE(p) PACKET_DO_RECYCLE((p))

/**
 *  \brief Cleanup a packet so that we can free it. No memset needed..
 */
#define PACKET_CLEANUP(p) do {                  \
        if ((p)->pktvar != NULL) {              \
            PktVarFree((p)->pktvar);            \
        }                                       \
        SCMutexDestroy(&(p)->mutex_rtv_cnt);    \
    } while (0)


/* macro's for setting the action
 * handle the case of a root packet
 * for tunnels */
#define ACCEPT_PACKET(p)       ((p)->root ? ((p)->root->action = ACTION_ACCEPT) : ((p)->action = ACTION_ACCEPT))
#define DROP_PACKET(p)         ((p)->root ? ((p)->root->action = ACTION_DROP) : ((p)->action = ACTION_DROP))
#define REJECT_PACKET(p)       ((p)->root ? ((p)->root->action = ACTION_REJECT) : ((p)->action = ACTION_REJECT))
#define REJECT_PACKET_DST(p)   ((p)->root ? ((p)->root->action = ACTION_REJECT_DST) : ((p)->action = ACTION_REJECT_DST))
#define REJECT_PACKET_BOTH(p)  ((p)->root ? ((p)->root->action = ACTION_REJECT_BOTH) : ((p)->action = ACTION_REJECT_BOTH))

#define TUNNEL_INCR_PKT_RTV(p) do {                                                 \
        SCMutexLock((p)->root ? &(p)->root->mutex_rtv_cnt : &(p)->mutex_rtv_cnt);   \
        ((p)->root ? (p)->root->rtv_cnt++ : (p)->rtv_cnt++);                        \
        SCMutexUnlock((p)->root ? &(p)->root->mutex_rtv_cnt : &(p)->mutex_rtv_cnt); \
    } while (0)

#define TUNNEL_INCR_PKT_TPR(p) do {                                                 \
        SCMutexLock((p)->root ? &(p)->root->mutex_rtv_cnt : &(p)->mutex_rtv_cnt);   \
        ((p)->root ? (p)->root->tpr_cnt++ : (p)->tpr_cnt++);                        \
        SCMutexUnlock((p)->root ? &(p)->root->mutex_rtv_cnt : &(p)->mutex_rtv_cnt); \
    } while (0)

#define TUNNEL_DECR_PKT_TPR(p) do {                                                 \
        SCMutexLock((p)->root ? &(p)->root->mutex_rtv_cnt : &(p)->mutex_rtv_cnt);   \
        ((p)->root ? (p)->root->tpr_cnt-- : (p)->tpr_cnt--);                        \
        SCMutexUnlock((p)->root ? &(p)->root->mutex_rtv_cnt : &(p)->mutex_rtv_cnt); \
    } while (0)

#define TUNNEL_DECR_PKT_TPR_NOLOCK(p) do {                   \
        ((p)->root ? (p)->root->tpr_cnt-- : (p)->tpr_cnt--); \
    } while (0)

#define TUNNEL_PKT_RTV(p)             ((p)->root ? (p)->root->rtv_cnt : (p)->rtv_cnt)
#define TUNNEL_PKT_TPR(p)             ((p)->root ? (p)->root->tpr_cnt : (p)->tpr_cnt)

#define IS_TUNNEL_ROOT_PKT(p)  (((p)->root == NULL && (p)->tunnel_pkt == 1))
#define IS_TUNNEL_PKT(p)       (((p)->tunnel_pkt == 1))
#define SET_TUNNEL_PKT(p)      ((p)->tunnel_pkt = 1)


void DecodeRegisterPerfCounters(DecodeThreadVars *, ThreadVars *);
Packet *PacketPseudoPktSetup(Packet *parent, uint8_t *pkt, uint16_t len, uint8_t proto);
Packet *PacketGetFromQueueOrAlloc(void);

DecodeThreadVars *DecodeThreadVarsAlloc();

/* decoder functions */
void DecodeEthernet(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);
void DecodeSll(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);
void DecodeTunnel(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);
void DecodeIPV4(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);
void DecodeIPV6(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);
void DecodeTCP(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);
void DecodeUDP(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);

/** \brief Set the No payload inspection Flag for the packet.
 *
 * \param p Packet to set the flag in
 */
#define DecodeSetNoPayloadInspectionFlag(p) do { \
        (p)->flags |= PKT_NOPAYLOAD_INSPECTION;  \
    } while (0)

/** \brief Set the No packet inspection Flag for the packet.
 *
 * \param p Packet to set the flag in
 */
#define DecodeSetNoPacketInspectionFlag(p) do { \
        (p)->flags |= PKT_NOPACKET_INSPECTION;  \
    } while (0)


#define DECODER_SET_EVENT(p, e) do { \
    if ((p)->events.cnt < PACKET_DECODER_EVENT_MAX) { \
        (p)->events.events[(p)->events.cnt] = e; \
        (p)->events.cnt++; \
    } \
} while(0)

#define DECODER_ISSET_EVENT(p, e) ({ \
    int r = 0; \
    uint8_t u; \
    for (u = 0; u < (p)->events.cnt; u++) { \
        if ((p)->events.events[u] == (e)) { \
            r = 1; \
            break; \
        } \
    } \
    r; \
})

/* older libcs don't contain a def for IPPROTO_DCCP
 * inside of <netinet/in.h>
 * if it isn't defined let's define it here.
 */
#ifndef IPPROTO_DCCP
#define IPPROTO_DCCP 33
#endif

/* pcap provides this, but we don't want to depend on libpcap */
#ifndef DLT_EN10MB
#define DLT_EN10MB 1
#endif

/* taken from pcap's bpf.h */
#ifndef DLT_RAW
#ifdef __OpenBSD__
#define DLT_RAW     14  /* raw IP */
#else
#define DLT_RAW     12  /* raw IP */
#endif
#endif

/** libpcap shows us the way to linktype codes
 * \todo we need more & maybe put them in a separate file? */
#define LINKTYPE_ETHERNET   DLT_EN10MB
#define LINKTYPE_LINUX_SLL  113

/*Packet Flags*/
#define PKT_NOPACKET_INSPECTION         0x01    /**< Flag to indicate that packet header or contents should not be inspected*/
#define PKT_NOPAYLOAD_INSPECTION        0x02    /**< Flag to indicate that packet contents should not be inspected*/
#define PKT_ALLOC                       0x04    /**< Packet was alloc'd this run, needs to be freed */
#define PKT_HAS_TAG                     0x08    /**< Packet has matched a tag */
#define PKT_STREAM_ADD                  0x10    /**< Packet payload was added to reassembled stream */
#define PKT_STREAM_EOF                  0x20    /**< Stream is in eof state */

#endif /* __DECODE_H__ */

