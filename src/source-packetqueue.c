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
#include "signal.h"

#define PQ_ACCEPT 0
#define PQ_DROP 1

TmEcode ReceivePacketQueue(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode ReceivePacketQueueThreadInit(ThreadVars *, void *, void **);
void ReceivePacketQueueThreadExitStats(ThreadVars *, void *);

TmEcode DecodePacketQueue(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode DecodePacketQueueThreadInit(ThreadVars *, void *, void **);

TmEcode VerdictPacketQueue(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode VerdictPacketQueueThreadInit(ThreadVars *, void *, void **);
void VerdictPacketQueueThreadExitStats(ThreadVars *, void *);
TmEcode VerdictPacketQueueThreadDeinit(ThreadVars *, void *);

void TmModuleReceivePacketQueueRegister (void) {
    tmm_modules[TMM_RECEIVEPACKETQUEUE].name = "ReceivePacketQueue";
    tmm_modules[TMM_RECEIVEPACKETQUEUE].ThreadInit = ReceivePacketQueuehreadInit;
    tmm_modules[TMM_RECEIVEPACKETQUEUE].Func = ReceivePacketQueue;
    tmm_modules[TMM_RECEIVEPACKETQUEUE].ThreadExitPrintStats = ReceivePacketQueueThreadExitStats;
    tmm_modules[TMM_RECEIVEPACKETQUEUE].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVEPACKETQUEUE].RegisterTests = NULL;
}

void TmModuleDecodePacketQueueRegister (void) {
    tmm_modules[TMM_DECODEPACKETQUEUE].name = "DecodePacketQueue";
    tmm_modules[TMM_DECODEPACKETQUEUE].ThreadInit = DecodePacketQueuehreadInit;
    tmm_modules[TMM_DECODEPACKETQUEUE].Func = DecodePacketQueue;
    tmm_modules[TMM_DECODEPACKETQUEUE].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEPACKETQUEUE].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODEPACKETQUEUE].RegisterTests = NULL;
}

void TmModuleVerdictPacketQueueRegister (void) {
    tmm_modules[TMM_VERDICTPACKETQUEUE].name = "VerdictPacketQueue";
    tmm_modules[TMM_VERDICTPACKETQUEUE].ThreadInit = VerdictPacketQueueThreadInit;
    tmm_modules[TMM_VERDICTPACKETQUEUE].Func = VerdictPacketQueue;
    tmm_modules[TMM_VERDICTPACKETQUEUE].ThreadExitPrintStats = VerdictPacketQueueThreadExitStats;
    tmm_modules[TMM_VERDICTPACKETQUEUE].ThreadDeinit = VerdictPacketQueueThreadDeinit;
    tmm_modules[TMM_VERDICTPACKETQUEUE].RegisterTests = NULL;
}

/*
 * Receiving Part
 */
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

TmEcode ReceivePacketQueue(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq){
	PacketQueueThreadVars *ptv = (PacketQueueThreadVars *)data;

	///TODO discuss funcs to be added

	return TM_ECODE_OK;
}

// receive module stats printing function
void ReceivePacketQueueThreadExitStats(ThreadVars *tv, void *data){
    PacketQueueThreadVars *ptv = (PacketQueueThreadVars *)data;
#ifdef COUNTERS
    SCLogInfo("(%s) Pkts %" PRIu32 ", Bytes %" PRIu64 ", Errors %" PRIu32 "",
            tv->name, ptv->pkts, ptv->bytes, ptv->errs);
#endif
}

/*
 * Decoding Part
 */
TmEcode DecodePacketQueue(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq){
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    //Counter update
    SCPerfCounterIncr(dtv->counter_pkts, tv->sc_perf_pca);
    SCPerfCounterAddUI64(dtv->counter_bytes, tv->sc_perf_pca, p->pktlen);
    SCPerfCounterAddUI64(dtv->counter_avg_pkt_size, tv->sc_perf_pca, p->pktlen);
    SCPerfCounterSetUI64(dtv->counter_max_pkt_size, tv->sc_perf_pca, p->pktlen);
    SCPerfCounterAddDouble(dtv->counter_bytes_per_sec, tv->sc_perf_pca, p->pktlen);
    SCPerfCounterAddDouble(dtv->counter_mbit_per_sec, tv->sc_perf_pca,
                           (p->pktlen * 8)/1000000.0);
    //process LoRaWAN packets
    if (PKT_IS_LORAWAN(p)) {
        SCLogDebug("Lorawan packet");
        DecodeLorawanMAC(tv, dtv, p, p->pkt, p->pktlen, pq);
    } else {
        SCLogDebug("packet unsupported by lorawan, first byte: %02x", *p->pkt);
    }

    return TM_ECODE_OK;
}

//initialize decode thread variables
TmEcode DecodePacketQueueThreadInit(ThreadVars *tv, void *initdata, void **data){
    DecodeThreadVars *dtv = NULL;
    dtv = DecodeThreadVarsAlloc();

    if (dtv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    DecodeRegisterPerfCounters(dtv, tv);

    *data = (void *)dtv;

    return TM_ECODE_OK;
}


/*
 * Veridict Part
 */
TmEcode VerdictPacketQueueThreadInit(ThreadVars *tv, void *initdata, void **data) {
	PacketQueueThreadVars *ptv = NULL;

    if ( (ptv = SCMalloc(sizeof(PacketQueueThreadVars))) == NULL)
        SCReturnInt(TM_ECODE_FAILED);
    memset(ptv, 0, sizeof(PacketQueueThreadVars));

    *data = (void *)ptv;

    return TM_ECODE_OK;
}

TmEcode VerdictPacketQueueThreadDeinit(ThreadVars *tv, void *data) {
	
	/* will be called after VerdictPacketQueueThreadExitStats 
	 * NFQ cases needed to call nfq_destory_queue (unbinding queue handle)
	 * IPFW cases did nothing 
	 * TODO discuss funcs needed to be added
	 */
	return TM_ECODE_OK;
}

void PacketQueueSetVerdict(PacketQueueThreadVars *ptv, Packet *p) {
    int ret;
    uint32_t verdict;

    if (p->action & ACTION_REJECT || p->action & ACTION_REJECT_BOTH ||
        p->action & ACTION_REJECT_DST || p->action & ACTION_DROP) {
        verdict = PQ_DROP;
        ptv->dropped++;
	signal(SIGUSR2, dropped);
	raise(SIGUSR2); /* SIGUSR2 is raised */
                        /* dropped() is called */
    } else {
        verdict = PQ_ACCEPT;
        ptv->accepted++;
	signal(SIGUSR2, accepted); /* SIGUSR2 is raised */
	raise(SIGUSR2);            /* accepted() is called */
        //TODO packet accept case 
    }

}

TmEcode VerdictPacketQueue(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq) {
	PacketQueueThreadVars *ptv = (PacketQueueThreadVars *)data;

	PacketQueueSetVerdict(ptv,p);

	return TM_ECODE_OK;
}

// verdict module stats printing function
void VerdictPacketQueueThreadExitStats(ThreadVars *tv, void *data) {
    PacketQueueThreadVars *ptv = (PacketQueueThreadVars *)data;
    SCLogInfo("(%s) Pkts accepted %" PRIu32 ", dropped %" PRIu32 "",tv->name, ptv->accepted, ptv->dropped);
}

