//
// Created by eunbang on 2018-07-013.
//
#include "suricata-common.h"
#include "packet-queue.h"
#include "decode.h"
#include "decode-events.h"
#include "defrag.h"
#include "util-debug.h"


static int DecodeLorawanMACPacket(ThreadVars *tv, Packet *p, uint8_t *pkt, uint16_t len)
{

	if (len < LORAWAN_MAC_HEADER_LEN){
		DECODER_SET_EVENT(p,LORAWAN_PKT_TOO_SMALL);
		return -1;
	}

	p->lorawan_mac_header = (LorawanMacHdr *)pkt;

	if(len < LORAWAN_MAC_GET_HEADER_LEN(p)) {
		DECODER_SET_EVENT(p,LORAWAN_PKT_TOO_SMALL);
		return -1;
	}

	LORAWAN_MAC_SET_MTYPE(p);
	LORAWAN_MAC_SET_RFU(p);
	LORAWAN_MAC_SET_MAJOR(p);

	p->lorawan_mac_vars.macpayload = pkt + LORAWAN_MAC_GET_HEADER_LEN(p);

	if(len < LORAWAN_MAC_GET_HEADER_LEN(p) + LORAWAN_MAC_PAYLOAD_LEN_MIN) {
		DECODER_SET_EVENT(p,LORAWAN_PKT_TOO_SMALL);
		return -1;
	}

	if(len != LORAWAN_MAC_GET_LEN(p)) {
		DECODER_SET_EVENT(p,LORAWAN_PKT_TOO_SMALL);
		return -1;
	}

	//TODO trim MIC 
	return 0;
}

static int DecodeLorawanMAC(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
	int ret;

	SCPerfCounterIncr(dtv->counter_lorawan_dataframe, tv->sc_perf_pca);

    ret = DecodeLorawanMACPacket(tv, p, pkt, len);
    if (ret < 0) {
        SCLogDebug("decoding Lorawan MAC packet failed");
        p->lorawanfh = NULL;
        return;
    }


    switch (LORAWAN_MAC_GET_MTYPE(p)) {
/*    	case 0x00: //join-request
    		break;
    	case 0x01: //join-accept
    		break;
*/
    	//TODO check for uplink and downlink about detailed MAC command
    	case 0x02: //unconfirmed data up
    		break;
    	case 0x04: //unconfirmed data down
    		break;
    	case 0x05: //confirmed data up
    		break;
    	case 0x06: //confirmed data down
    		break;
    	default:
    		break;
    }
}