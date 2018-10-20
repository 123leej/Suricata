#include "suricata-common.h"
#include "packet-queue.h"
#include "decode.h"
#include "threads.h"

typedef struct PacketQueue_ {
    Packet *top;
    Packet *bot;
    uint16_t len;
    SCMutex mutex_q;
    SCCondT cond_q;
#ifdef DBG_PERF
    uint16_t dbg_maxlen;
#endif /* DBG_PERF */
} PacketQueue;

SCMutexInit(pq.mutex_q, NULL);
SCCondInit(pq.cond_q, NULL);