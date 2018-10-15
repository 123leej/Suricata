//
//	Created by eunbang on 2018-10-10
//

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "decode.h"
#include "packet-queue.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-queuehandlers.h"
#include "tm-modules.h"
#include "action-globals.h"

#include "util-debug.h"
#include "util-error.h"
#include "util-byte.h"
#include "util-privs.h"
#include "conf.h"
#include "tmqh-packetpool.h"

TmEcode ReceivePacketQueue(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode ReceivePacketQueueThreadInit(ThreadVars *, void *, void **);
void ReceivePacketQueueThreadExitStats(ThreadVars *, void *);


void TmModuleReceivePacketQueueRegister (void) {
    /* XXX create a general NFQ setup function */
    memset(&nfq_g, 0, sizeof(nfq_g));
    memset(&nfq_t, 0, sizeof(nfq_t));
    SCMutexInit(&nfq_init_lock, NULL);

    tmm_modules[TMM_RECEICEPACKETQUQUE].name = "ReceivePacketQueue";
    tmm_modules[TMM_RECEICEPACKETQUQUE].ThreadInit = ReceivePacketQueuehreadInit;
    tmm_modules[TMM_RECEICEPACKETQUQUE].Func = ReceivePacketQueue;
    tmm_modules[TMM_RECEICEPACKETQUQUE].ThreadExitPrintStats = ReceivePacketQueueThreadExitStats;
    tmm_modules[TMM_RECEICEPACKETQUQUE].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEICEPACKETQUQUE].RegisterTests = NULL;
}

TmEcode ReceivePacketQueue(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq){

}

TmEcode ReceivePacketQueueThreadInit(ThreadVars *tv, void *initdata, void **data){

}

void ReceivePacketQueueThreadExitStats(ThreadVars *tv, void *data){

}