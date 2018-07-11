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


static void DecodeLoraWanFrameHdrs(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
    return;
}

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