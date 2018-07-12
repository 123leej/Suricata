//
// Created by JONGWON on 2018-07-09.
//
#include "suricata-common.h"
#include "packet-queue.h"
#include "decode.h"
#include "decode-events.h"
#include "defrag.h"
#include "util-debug.h"
#include "decode-lorawan-frame.h"



static int DecodeLorawanFrameControls(ThreadVars *tv, Packet *p, uint8_t *pkt, uint16_t len)
{
    LORAWAN_FRAME_SET_FOPTS_LEN(p, pkt+len-LORAWAN_FRAME_FOPTSLEN_LEN);
    LORAWAN_FRAME_SET_HEADER_LEN(LORAWAN_FRAME_HEADER_LEN_MIN + LORAWAN_FRAME_GET_FOPTS_LEN(p));

    return 0;
}


static int DecodeLorawanFramePacket(ThreadVars *tv, Packet *p, uint8_t *pkt, uint16_t len)
{
    int ret;

    if (len < LORAWAN_FRAME_HEADER_LEN_MIN) {
        DECODER_SET_EVENT(p,LORAWAN_PKT_TOO_SMALL);
        return -1;
    }

    p->lorafh = (LorawanFrame4Hdr *)pkt;

    ret = DecodeLorawanFrameControls(tv, p, p->lorawanfh->fctl, LORAWAN_FRAME_CTRL_LEN);

    if (ret < 0) {
        SCLogDebug("decoding Lorawan frame control failed");
        p->lorawanfh = NULL;
        return -1;
    }

    if (LORAWAN_FRAME_HEADER_LEN_MAX < LORAWAN_FRAME_GET_HEADER_LEN(p)) {
        DECODER_SET_EVENT(p, LORAWAN_FRAME_HEADER_TOO_BIG);
        return -1;
    }

    p->lorawan_frame_vars.fports = pkt + LORAWAN_FRAME_GET_HEADER_LEN(p);

    if (len < LORAWAN_FRAME_GET_HEADER_LEN(p) + LORAWAN_FPORT_LEN) {
        DECODER_SET_EVENT(p, LORAWAN_PKT_TOO_SMALL);
        return -1;
    }

    if (len != LORAWAN_FRAME_GET_LEN(p)) {
        DECODER_SET_EVENT(p,LORAWAN_FRAME_PKT_INVALID);
        return -1;
    }

    p->payload = pkt + LORAWAN_FRAME_GET_HEADER_LEN(p) + LORAWAN_FRAME_PORT_LEN;
    p->payload_len = len - LORAWAN_FRAME_GET_HEADER_LEN(p) - LORAWAN_FRAME_PORT_LEN;

    return 0;
}


void DecodeLorawanFrame(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
    int ret;

    SCPerfCounterIncr(dtv->counter_lorawan_dataframe, tv->sc_perf_pca);


    ret = DecodeLorawanFramePacket(tv, p, pkt, len);
    if (ret < 0) {
        SCLogDebug("decoding Lorawan frame packet failed");
        p->lorawanfh = NULL;
        return;
    }

    switch (LORAWAN_FRAME_GET_FPORT(p)) {
        case 0x00:
            if (LORAWAN_FRAME_GET_HEADER_LEN(p) == LORAWAN_FRAME_HEADER_LEN_MIN) {
                DecodeLorawanMacCommand(tv, p, pkt + LORAWAN_FRAME_HEADER_LEN_MIN, LORAWAN_FRAME_GET_FOPTS_LEN(p));
            } else {
                DecodeLorawanMacCommand(tv, p, p->payload, p->payload_len);
            }
            break;
        case 0x01:
            //TODO IF Some AppLayer IOT Protocols Based on LoRaWan Decoding From Here
            break;
        default:
            //TODO Decode Raw Payloads
            break;
    }

    //TODO HOW TO PROCESS THE RE-ASSEMBLY or VerdictNFQ ???
    return;
}