//
//	Created by eunbang on 2018-10-11
//

#ifndef __SOURCE_PKTQUEUE_H__
#define __SOURCE_PKTQUEUE_H__

// not used but neeeded in API
typedef struct PacketQueuePacketVars_
{
} PacketQueuePacketVars;

//Structure to hold thread specific variables
typedef struct PacketQueueThreadVars_
{
	

	/* counters */
    uint32_t pkts;
    uint64_t bytes;
    uint32_t errs;
    uint32_t accepted;
    uint32_t dropped;

} PacketQueueThreadVars;

void TmModuleReceivePacketQueueRegister (void);
void TmModuleVerdictPacketQueueRegister (void);
void TmModuleDecodePacketQueueRegister (void);

#endif