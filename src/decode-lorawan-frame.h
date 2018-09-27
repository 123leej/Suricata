//
// Created by JONGWON on 2018-07-09.
//

#ifndef SRC_DECODE_LORAWAN_FRAME_H
#define SRC_DECODE_LORAWAN_FRAME_H

/** FHDR(7~22) [DevAddr(4) | FCtrl(1) [ ADR(1) | ADR_ACK_REQ(1) | ACK(1) | FPENDING(1) | FOPTSLEN(4) ] |  FCnt(2) | FOpts(15)] **/
/** FPORTS(0~1) **/
/** FRMPayload(0~N) **/


#include "decode.h"

#define LORAWAN_FRAME_DEV_ADDR_LEN              4
#define LORAWAN_FRAME_HEADER_LEN_MIN            7            /**< Header Minimum length */
#define LORAWAN_FRAME_PORT_LEN                  1            /**< Frame Ports length */
#define LORAWAN_FRAME_CTRL_LEN                  1            /**< Frame Control length */
#define LORAWAN_FPORT_MAC_COMMAND               0x00


typedef struct LorawanFrameHdr_ {
    uint32_t dev_addr;                                      /* DevAddr */
    struct LorawanFrameCtrl *fctl;                         /* Fctl */
    uint16_t fcnt;                                          /* Fcnt */
    unsigned char* fopts;                                 /* Fopts */
} LorawanFrameHdr;

typedef struct LorawanFrameVars_ {
    uint8_t fports;
}LorawanFrameVars;

typedef struct LorawanFrameCtrl_ {
    unsigned int address : 1;
    unsigned int address_ack_request : 1;
    unsigned int ack : 1;
    unsigned int fpending : 1;
    unsigned int fopts_len : 4;
} LorawanFrameCtrl;

#define LORAWAN_FRAME_SET_FOPTS_LEN(p, len) ((p)->lorawanfh->fctl.fopts_len = len)
#define LORAWAN_FRAME_GET_FPORT(p) ((p)->lorawanfvars->fports)
#define LORAWAN_FRAME_GET_HEADER_LEN(p) ((p)->lorawanfh->fctl.fopts_len + LORAWAN_FRAME_HEADER_LEN_MIN)


void DecodeLorawanFrame(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, uint8_t *pkt, uint16_t len, PacketQueue *pq);
static int DecodeLorawanFramePacket(ThreadVars *tv, Packet *p, uint8_t *pkt, uint16_t len);
static int DecodeLorawanFrameControls(ThreadVars *tv, Packet *p, uint8_t *pkt, uint16_t len);

#endif //SRC_DECODE_LORAWAN_FRAME_H
