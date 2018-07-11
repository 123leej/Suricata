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



static int DecodeLORAWANFrameControls(ThreadVars *tv, Packet *p, uint8_t *pkt, uint16_t len)
{
    return 0;
}


static int DecodeLORAWANFrameOptions(ThreadVars *tv, Packet *p, uint8_t *pkt, uint16_t len)
{
    return 0;
}

static int DecodeLORAWANFramePacket(ThreadVars *tv, Packet *p, uint8_t *pkt, uint16_t len)
{
    if (len < LORAWAN_FRAME_HEADER_LEN_MIN) {
        DECODER_SET_EVENT(p,LORAWAN_PKT_TOO_SMALL);
        return -1;
    }

    p->lorafh = (LorawanFrame4Hdr *)pkt;

    if (LORAWAN_FRAME_GET_HLEN(p) < LORAWAN_FRAME_GET_FOPTS_LEN + 7) {
        DECODER_SET_EVENT(p,LORAWAN_FRAME_HLEN_TOO_SMALL);
        return -1;
    }

    if (len != LORAWAN_FRAME_GET_LEN(p)) {
        DECODER_SET_EVENT(p,LORAWAN_FRAME_PKT_INVALID);
        return -1;
    }

    DecodeLORAWANFrameControls(tv, p, pkt + sizeof(p->lorawan_frame_hdr.dev_addr), sizeof(p->lorawan_frame_hdr.fctl));

    if (p->lorawanhdr.fctl.fopts_len > 0) {
        DecodeLORAWANFrameOptions(tv, p, pkt + sizeof(p->lorawan_frame_hdr.dev_addr) + sizeof(p->lorawan_frame_hdr.fctl->fopts_len), p->lorawan_frame_hdr.fctl->fopts_len);
    }

    p->payload = pkt + LoRAWAN_FRAME_HEADER_LEN;        //??????????????????????
    p->payload_len = len - LoRAWAN_FRAME_HEADER_LEN;

    return 0;
}

void DecodeLORAWANFrame(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
    int ret;

    SCPerfCounterIncr(dtv->counter_lorawan_dataframe, tv->sc_perf_pca);


    ret = DecodeLORAWANFramePacket(tv, p, pkt, len);
    if (ret < 0) {
        SCLogDebug("decoding Lorawan frame packet failed");
        p->lorawanfh = NULL;
        return;
    }

    switch (LORAWAN_GET_FPORT(p)) {
        case LORAWAN_FPORT_MAC_COMMAND:
            //
            DecocdeLorawanMACComands();
            break;
        case LORAWAN_FPORT_APP_SPCIFIC:
            break;
    }

    //TODO HOW TO PROCESS THE RE-ASSEMBLY
    return;
}