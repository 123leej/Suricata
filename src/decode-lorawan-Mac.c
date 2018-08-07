//
// Created by eunbang on 2018-07-013.
//
#include "suricata-common.h"
#include "packet-queue.h"
#include "decode.h"
#include "decode-events.h"
#include "defrag.h"
#include "util-debug.h"
#include "decode-lorawan-Mac.h"

static int DecodeLorawanMACPacket(ThreadVars *tv, Packet *p, uint8_t *pkt, uint16_t len)
{

	if (len != LORAWAN_MAC_HEADER_LEN){
		DECODER_SET_EVENT(p,LORAWAN_HEADER_INVALID_LEN);
		return -1;
	}

	p->lorawanmh = (LorawanMacHdr *)pkt;

	p->lorawanmvars->macpayload = pkt + LORAWAN_MAC_HEADER_LEN;

	return 0;
}

void DecodeLorawanMAC(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
	int ret;

	SCPerfCounterIncr(dtv->counter_lorawan_dataframe, tv->sc_perf_pca);

    ret = DecodeLorawanMACPacket(tv, p, pkt, len);
    if (ret < 0) {
        SCLogDebug("decoding Lorawan MAC packet failed");
        p->lorawanfh = NULL;
        return;
    }

	if(len < LORAWAN_MAC_HEADER_LEN + LORAWAN_MAC_PAYLOAD_LEN_MIN) {
		DECODER_SET_EVENT(p,LORAWAN_PKT_TOO_SMALL);
		return;
	}

	LORAWAN_MAC_TRIM_MIC(p,p->lorawanmvars);

    switch (p->lorawanmh->mtype) {

    	//TODO check for uplink and downlink about detailed MAC command
    	case 0x02:	//unconfirmed data up
    		break;
    	case 0x04:	//unconfirmed data down
    		break;
    	case 0x05:	//confirmed data up
    		DecodeLorawanFrame(tv, dtv, p, pkt, len, pq);
    	case 0x06:	//confirmed data down
    		break;
    	default:	//join-request, join-accept, RFU, proprietary
    		//TODO whether goto veridict directly?
    		break;
    }
}