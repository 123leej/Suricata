//
// Created by JONGWON on 2018-07-09.
//

#ifndef SRC_DECODE_LORAWAN_FRAME_H
#define SRC_DECODE_LORAWAN_FRAME_H

/** FHDR(7~23) [DevAddr(4) | FCtrl(1) [ ADR(1) | ADR_ACK_REQ(1) | ACK(1) | FPENDING(1) | FOPTSLEN(4) ] |  FCnt(2) | FOpts(15)] **/
/** FPORTS(0~1) **/
/** FRMPayload(0~N) **/

#define LORAWAN_FRAME_HEADER_LEN_MIN            7            /**< Header Minimum length */
#define LORAWAN_FRAME_HEADER_LEN_MAX            15           /**< Header Maximum length */
#define LORAWAN_FRAME_PORT_LEN                  1            /**< Frame Ports length */

#define LORAWAN_FPORT_MAC_COMMAND               0x00

/** Frame Options CID **/
#define LINK_CHECK_REQ                          0x02         /**< Link Check Request from End-Device*/
#define LINK_CHECK_ANS                          0x02         /**< Link Check Answer from GateWay*/
#define LINK_ADR_REQ                            0x03         /**< Link Address Request from GateWay*/
#define LINK_ADR_ANS                            0x03         /**< Link Address Answer from End-Device*/
#define DUTY_CYCLE_REQ                          0x04         /**< Duty Cycle Request from GateWay*/
#define DUTY_CYCLE_ANS                          0x04         /**< Duty Cycle Answer from End-Device*/
#define RX_PARAM_SETUP_REQ                      0x05         /**< Rx parameter Setup Request from GateWay*/
#define RX_PARAM_SETUP_ANS                      0x05         /**< Rx parameter Setup Answer from End-Device*/
#define DEV_STATUS_REQ                          0x06         /**< Device Status Request from GateWay*/
#define DEV_STATUS_ANS                          0x06         /**< Device Status Answer from End-Device*/
#define NEW_CHANNEL_REQ                         0x07         /**< New Channel Request from GateWay*/
#define NEW_CHANNEL_ANS                         0x07         /**< New Channel Answer from End-Device*/
#define RX_TIMING_SETUP_REQ                     0x08         /**< Rx Timing Setup Request from GateWay*/
#define RX_TIMING_SETUP_ANS                     0x08         /**< Rx Timing Setup Answer from End-Device*/


typedef struct LorawanFrameHdr_ {
    uint32_t dev_addr;                  /* DevAddr */
    struct LorawanFrameCtrl *fctl;       /* Fctl */
    uint16_t fcnt;
    uint

} LorawanFrameHdr;

typedef struct LorawanFrameCtrl_ {
    unsigned int address : 1;
    unsigned int address_ack_request : 1;
    unsigned int ack : 1;
#ifdef uplink
    unsigned int fpending : 1;
#else
    unsigned int rfu : 1;
#endif
    unsigned int fopts_len : 4;
} LorawanFrameCtrl;



#endif //SRC_DECODE_LORAWAN_FRAME_H
