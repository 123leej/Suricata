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
    tmm_modules[TMM_RECEICEPACKETQUQUE].name = "ReceivePacketQueue";
    tmm_modules[TMM_RECEICEPACKETQUQUE].ThreadInit = ReceivePacketQueuehreadInit;
    tmm_modules[TMM_RECEICEPACKETQUQUE].Func = ReceivePacketQueue;
    tmm_modules[TMM_RECEICEPACKETQUQUE].ThreadExitPrintStats = ReceivePacketQueueThreadExitStats;
    tmm_modules[TMM_RECEICEPACKETQUQUE].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEICEPACKETQUQUE].RegisterTests = NULL;
}

TmEcode ReceivePacketQueue(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq){
	PacketQueueThreadVars *ptv = (PacketQueueThreadVars *)data;

	///what to do?

	return TM_ECODE_OK;
}

TmEcode ReceivePacketQueueThreadInit(ThreadVars *tv, void *initdata, void **data){
    
    sigset_t sigs;
    sigfillset(&sigs);
    pthread_sigmask(SIG_BLOCK, &sigs, NULL);


    /* Extract the queue number-initdata from command line */
    uint16_t queue_num = 0;
    if ((ByteExtractStringUint16(&queue_num, 10, strlen((char *)initdata),
                                      (char *)initdata)) < 0)
    {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "specified queue number %s is not "
                                        "valid", (char *)initdata);
        exit(EXIT_FAILURE);
    }

    /*setup Threadvars*/
    PacketQueueThreadVars *ptv = SCMalloc(sizeof(PacketQueueThreadVars));
    if (ptv == NULL)
        SCReturnInt(TM_ECODE_FAILED);
    memset(ptv, 0, sizeof(PacketQueueThreadVars));    

    //pass threadvar pointer
    *data = (void *)ptv;

    SCReturnInt(TM_ECODE_OK);
}

void ReceivePacketQueueThreadExitStats(ThreadVars *tv, void *data){

}