//
// Created by JONGWON on 2018-07-09.
//

#ifndef SRC_DECODE_LORAWAN_FRAME_H
#define SRC_DECODE_LORAWAN_FRAME_H

/** FHDR(7~23) [DevAddr(4) | FCtrl(1) [ ADR(1) | ADR_ACK_REQ(1) | ACK(1) | FPENDING(1) | FOPTSLEN(4) ] |  FCnt(2) | FOpts(15)] **/
/** FPORTS(0~1) **/
/** FRMPayload(0~N) **/


/** Frame Options CID **/
#define LINK_CHECK_REQ                          0x02
#define LINK_CHECK_ANS                          0x02
#define LINK_ADR_REQ                            0x03
#define LINK_ADR_ANS                            0x03
#define DUTY_CYCLE_REQ                          0x04
#define DUTY_CYCLE_ANS                          0x04
#define RX_PARAM_SETUP_REQ                      0x05
#define RX_PARAM_SETUP_ANS                      0x05
#define DEV_STATUS_REQ                          0x06
#define DEV_STATUS_ANS                          0x06
#define NEW_CHANNEL_REQ                         0x07
#define NEW_CHANNEL_ANS                         0x07
#define RX_TIMING_SETUP_REQ                     0x08
#define RX_TIMING_SETUP_ANS                     0x08

typedef struct LorawanFrameHdr_ {
} LorawanFrameHdr;

typedef struct LorawanFrameCtrl_ {

} LorawanFrameCtrl;



#endif //SRC_DECODE_LORAWAN_FRAME_H
