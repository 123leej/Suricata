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
    return;
}