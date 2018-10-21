#include "suricata-common.h"
#include "packet-queue.h"
#include "decode.h"
#include "threads.h"

#define DE_STATE_CHUNK_SIZE 16
#define IPV6_HEADER_LEN 40
#define SCSpinlock pthread_spinlock_t
#define SigIntId uint16_t
#define SCMutex pthread_mutex_t
#define SCCondT pthread_cond_t
#define SCCondInit pthread_cond_init
#define SCMutexInit(mut, mutattrs) SCMutexInit_dbg(mut, mutattrs)
#define SCMutexInit_dbg(mut, mutattr) ({ \
    int ret; \
    ret = pthread_mutex_init(mut, mutattr); \
    if (ret != 0) { \
        switch (ret) { \
            case EINVAL: \
            printf("The value specified by attr is invalid\n"); \
            printf("%16s(%s:%d): (thread:%"PRIuMAX") mutex %p initialization returned %" PRId32 "\n", __FUNCTION__, __FILE__, __LINE__, (uintmax_t)pthread_self(), mut, ret); \
            break; \
            case EAGAIN: \
            printf("The system temporarily lacks the resources to create another mutex\n"); \
            printf("%16s(%s:%d): (thread:%"PRIuMAX") mutex %p initialization returned %" PRId32 "\n", __FUNCTION__, __FILE__, __LINE__, (uintmax_t)pthread_self(), mut, ret); \
            break; \
            case ENOMEM: \
            printf("The process cannot allocate enough memory to create another mutex\n"); \
            printf("%16s(%s:%d): (thread:%"PRIuMAX") mutex %p initialization returned %" PRId32 "\n", __FUNCTION__, __FILE__, __LINE__, (uintmax_t)pthread_self(), mut, ret); \
            break; \
        } \
    } \
    ret; \
})

#define SC_ATOMIC_DECLARE(type, name) \
    type name ## _sc_atomic__; \
    SCSpinlock name ## _sc_lock__

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

typedef struct Packet_
{
    /* Addresses, Ports and protocol
     * these are on top so we can use
     * the Packet as a hash key */
    union {
        uint64_t index_no;
        u_int8_t of_flag;
    };

    union {
        EUI eui;
        uint8_t direction;
    };
    uint8_t proto;

    /* Pkt Flags */
    uint8_t flags;
    /* flow */
    uint8_t flowflags;
    struct Flow_ *flow;

    struct timeval ts;

    /* IPS action to take */
    uint8_t action;

    /* pkt vars */
    PktVar *pktvar;

    LorawanMacHdr *lorawanmh;
    LorawanMacVars *lorawanmvars;

    LorawanFrameHdr *lorawanfh;
    LorawanFrameVars *lorawanfvars;

    uint8_t *payload;
    uint16_t payload_len;

    /* storage: maximum ip packet size + link header */
    uint8_t pkt[IPV6_HEADER_LEN + 65536 + 28];
    uint32_t pktlen;

    PacketAlerts alerts;

    /* ready to set verdict counter, only set in root */
    uint8_t rtv_cnt;
    SCMutex mutex_rtv_cnt;

    /* decoder events */
    PacketDecoderEvents events;

    /* double linked list ptrs */
    struct Packet_ *next;
    struct Packet_ *prev;

    /* tunnel/encapsulation handling */
    struct Packet_ *root; /* in case of tunnel this is a ptr
                           * to the 'real' packet, the one we
                           * need to set the verdict on --
                           * It should always point to the lowest
                           * packet in a encapsulated packet */
} Packet;


typedef struct EUI_ {
    uint64_t deveui;
    uint64_t appeui;
} EUI;

typedef struct Flow_
{
    /* flow "header", used for hashing and flow lookup. Static after init,
     * so safe to look at without lock */
    uint8_t proto;
    uint8_t recursion_level;

    /* end of flow "header" */

    uint16_t flags;

    /* ts of flow init and last update */
    struct timeval startts;
    struct timeval lastts;

    /* pointer to the var list */
    GenericVar *flowvar;

    uint32_t todstpktcnt;
    uint32_t tosrcpktcnt;
    uint64_t bytecnt;

    /** mapping to Flow's protocol specific protocols for timeouts
        and state and free functions. */
    uint8_t protomap;

    /** protocol specific data pointer, e.g. for TcpSession */
    void *protoctx;

    /** how many pkts and stream msgs are using the flow *right now*. This
     *  variable is atomic so not protected by the Flow mutex "m".
     *
     *  On receiving a packet the counter is incremented while the flow
     *  bucked is locked, which is also the case on timeout pruning.
     */
    SC_ATOMIC_DECLARE(unsigned short, use_cnt);

    /** detection engine state */
    struct DetectEngineState_ *de_state;
    SCMutex de_state_m;          /**< mutex lock for the de_state object */

    /** toclient sgh for this flow. Only use when FLOW_SGH_TOCLIENT flow flag
     *  has been set. */
    struct SigGroupHead_ *sgh_toclient;
    /** toserver sgh for this flow. Only use when FLOW_SGH_TOSERVER flow flag
     *  has been set. */
    struct SigGroupHead_ *sgh_toserver;

    SCMutex m;

    /** List of tags of this flow (from "tag" keyword of type "session") */
    DetectTagDataEntryList *tag_list;

    /* list flow ptrs
     * NOTE!!! These are NOT protected by the
     * above mutex, but by the FlowQ's */
    struct Flow_ *hnext; /* hash list */
    struct Flow_ *hprev;
    struct Flow_ *lnext; /* list */
    struct Flow_ *lprev;

    struct FlowBucket_ *fb;

    uint16_t alproto; /**< application level protocol */
    void **aldata; /**< application level storage ptrs */
    uint8_t alflags; /**< application level specific flags */

} Flow;

typedef struct GenericVar_ {
    uint8_t type;
    struct GenericVar_ *next;
    uint16_t idx;
} GenericVar;

typedef struct DetectEngineState_ {
    DeStateStore *head; /**< signature state storage */
    DeStateStore *tail; /**< tail item of the storage list */
    SigIntId cnt;       /**< number of sigs in the storage */
} DetectEngineState;

typedef struct DeStateStore_ {
    DeStateStoreItem store[DE_STATE_CHUNK_SIZE];    /**< array of storage objects */
    struct DeStateStore_ *next;                     /**< ptr to the next array */
} DeStateStore;

typedef struct DeStateStoreItem_ {
    SigIntId sid;   /**< Signature internal id to store the state for (16 or
                     *   32 bit depending on how SigIntId is defined). */
    uint16_t flags; /**< flags */
    SigMatch *nm;   /**< next sig match to try, or null if done */
} DeStateStoreItem;

typedef struct SigMatch_ {
    uint16_t idx; /**< position in the signature */
    uint8_t type; /**< match type */
    void *ctx; /**< plugin specific data */
    struct SigMatch_ *next;
    struct SigMatch_ *prev;
} SigMatch;

typedef struct SigGroupHead_ {
    uint8_t flags;

    uint8_t pad0;
    uint16_t pad1;

    /* number of sigs in this head */
    uint32_t sig_cnt;

    /** chunk of memory containing the "header" part of each
     *  signature ordered as an array. Used to pre-filter the
     *  signatures to be inspected in a cache efficient way. */
    SignatureHeader *head_array;

    /* pattern matcher instances */
    MpmCtx *mpm_ctx;
    MpmCtx *mpm_stream_ctx;
    uint16_t mpm_content_maxlen;
    uint16_t mpm_streamcontent_maxlen;
    MpmCtx *mpm_uri_ctx;
    uint16_t mpm_uricontent_maxlen;

    /** Array with sig ptrs... size is sig_cnt * sizeof(Signature *) */
    Signature **match_array;

    /* ptr to our init data we only use at... init :) */
    SigGroupHeadInitData *init;
} SigGroupHead;

typedef struct SignatureHeader_ {
    uint32_t flags;

    /* app layer signature stuff */
    uint16_t alproto;

    /** pattern in the mpm matcher */
    uint32_t mpm_pattern_id;

    SigIntId num; /**< signature number, internal id */

    /** pointer to the full signature */
    struct Signature_ *full_sig;
} SignatureHeader;

typedef struct MpmCtx_ {
    void *ctx;
    uint16_t mpm_type;

    uint32_t memory_cnt;
    uint32_t memory_size;

    uint32_t pattern_cnt;       /* unique patterns */
    uint32_t total_pattern_cnt; /* total patterns added */

    uint16_t minlen;
    uint16_t maxlen;
} MpmCtx;

typedef struct Signature_ {
    uint32_t flags;

    /* app layer signature stuff */
    uint16_t alproto;

    /** pattern in the mpm matcher */
    uint32_t mpm_pattern_id;

    SigIntId num; /**< signature number, internal id */

    /** address settings for this signature */
    DetectAddressHead src, dst;
    /** port settings for this signature */
    DetectPort *sp, *dp;

    /** addresses, ports and proto this sig matches on */
    DetectProto proto;

    /** netblocks and hosts specified at the sid, in CIDR format */
    IPOnlyCIDRItem *CidrSrc, *CidrDst;

    /** ptr to the SigMatch lists */
    struct SigMatch_ *match; /* non-payload matches */
    struct SigMatch_ *match_tail; /* non-payload matches, tail of the list */
    struct SigMatch_ *pmatch; /* payload matches */
    struct SigMatch_ *pmatch_tail; /* payload matches, tail of the list */
    struct SigMatch_ *umatch; /* uricontent payload matches */
    struct SigMatch_ *umatch_tail; /* uricontent payload matches, tail of the list */
    struct SigMatch_ *amatch; /* general app layer matches */
    struct SigMatch_ *amatch_tail; /* general app layer  matches, tail of the list */
    struct SigMatch_ *dmatch; /* dce app layer matches */
    struct SigMatch_ *dmatch_tail; /* dce app layer matches, tail of the list */
    struct SigMatch_ *tmatch; /* list of tags matches */
    struct SigMatch_ *tmatch_tail; /* tag matches, tail of the list */

    /** ptr to the next sig in the list */
    struct Signature_ *next;

    struct SigMatch_ *dsize_sm;

    /** inline -- action */
    uint8_t action;

    /* helper for init phase */
    uint16_t mpm_content_maxlen;
    uint16_t mpm_uricontent_maxlen;

    /** number of sigmatches in the match and pmatch list */
    uint16_t sm_cnt;

    SigIntId order_id;

    /** pattern in the mpm matcher */
    uint32_t mpm_uripattern_id;

    uint8_t rev;
    int prio;

    uint32_t gid; /**< generator id */
    uint32_t id;  /**< sid, set by the 'sid' rule keyword */
    char *msg;

    /** classification id **/
    uint8_t class;

    /** classification message */
    char *class_msg;

    /** Reference */
    Reference *references;

    /* Be careful, this pointer is only valid while parsing the sig,
     * to warn the user about any possible problem */
    char *sig_str;

#ifdef PROFILING
    uint16_t profiling_id;
#endif
} Signature;

typedef struct SigGroupHeadInitData_ {
    /* list of content containers
     * XXX move into a separate data struct
     * with only a ptr to it. Saves some memory
     * after initialization
     */
    uint8_t *content_array;
    uint32_t content_size;
    uint8_t *uri_content_array;
    uint32_t uri_content_size;
    uint8_t *stream_content_array;
    uint32_t stream_content_size;

    /* "Normal" detection uses these only at init, but ip-only
     * uses it during runtime as well, thus not in init... */
    uint8_t *sig_array; /**< bit array of sig nums (internal id's) */
    uint32_t sig_size; /**< size in bytes */

    /* port ptr */
    struct DetectPort_ *port;
} SigGroupHeadInitData;

typedef struct DetectPort_ {
    uint16_t port;
    uint16_t port2;

    /* signatures that belong in this group */
    struct SigGroupHead_ *sh;

    struct DetectPort_ *dst_ph;

    /* double linked list */
    union {
        struct DetectPort_ *prev;
        struct DetectPort_ *hnext; /* hash next */
    };
    struct DetectPort_ *next;

    uint32_t cnt;
    uint8_t flags;  /**< flags for this port */
} DetectPort;

typedef struct DetectTagDataEntryList_ {
    DetectTagDataEntry *header_entry;
//    Address addr;                       /**< Var used to store dst or src addr */
    uint8_t ipv;                        /**< IP Version */
    SCMutex lock;
}DetectTagDataEntryList;

typedef struct DetectTagDataEntry_ {
    DetectTagData *td;                  /**< Pointer referencing the tag parameters */
    uint32_t sid;                       /**< sid originating the tag */
    uint32_t gid;                       /**< gid originating the tag */
    uint32_t packets;                   /**< number of packets */
    uint32_t bytes;                     /**< number of bytes */
    struct timeval first_ts;            /**< First time seen (for metric = seconds) */
    struct timeval last_ts;             /**< Last time seen (to prune old sessions) */
    struct DetectTagDataEntry_ *next;   /**< Pointer to the next tag of this
                                         * session/src_host/dst_host (if any from other rule) */
    uint16_t cnt_match;                 /**< number of times this tag was reset/updated */
    uint8_t first_time;                 /**< Used at unified output. The first packet write the
                                             header with the data of the sig. The next packets use
                                             gid/sid/rev of the tagging engine */
} DetectTagDataEntry;

typedef struct DetectTagData_ {
    uint8_t type;          /**< tag type */
    uint32_t count;        /**< count */
    uint32_t metric;       /**< metric */
    uint8_t direction;     /**< host direction */
} DetectTagData;

typedef struct FlowBucket_ {
    Flow *f;
//    SCMutex m;
    SCSpinlock s;
} FlowBucket;

typedef struct PktVar_ {
    char *name;
    struct PktVar_ *next; /* right now just implement this as a list,
                           * in the long run we have thing of something
                           * faster. */
    uint8_t *value;
    uint16_t value_len;
} PktVar;

typedef struct LorawanMacHdr_ {
	unsigned int mtype : 3;
	unsigned int rfu : 3;
	unsigned int major : 2;
} LorawanMacHdr;

typedef struct LorawanMacVars_ {
	unsigned int macpayload;

} LorawanMacVars;

typedef struct LorawanFrameHdr_ {
    uint32_t dev_addr;
    struct LorawanFrameCtrl *fctl;
    uint16_t fcnt;
    unsigned char* fopts;
} LorawanFrameHdr;

typedef struct LorawanFrameVars_ {
    uint8_t fports;
}LorawanFrameVars;

typedef struct LorawanFrameCtrl_ {
    unsigned int address : 1;
    unsigned int address_ack_request : 1;
    unsigned int ack : 1;
    unsigned int fpending : 1;
    unsigned int fopts_len : 4;
} LorawanFrameCtrl;

typedef struct PacketAlerts_ {
    uint16_t cnt;
    PacketAlert alerts[PACKET_ALERT_MAX];
} PacketAlerts;

typedef struct PacketAlert_ {
    SigIntId num; /* Internal num, used for sorting */
    SigIntId order_id; /* Internal num, used for sorting */
    uint8_t action; /* Internal num, used for sorting */
    uint32_t  gid;
    uint32_t sid;
    uint8_t  rev;
    uint8_t class;
    uint8_t prio;
    char *msg;
    char *class_msg;
    Reference *references;
} PacketAlert;

typedef struct Reference_ {
    char *key;                  /**< pointer to key */
    char *reference;            /**< reference data */
    struct Reference_ *next;   /**< next reference in the signature */
} Reference;

typedef struct PacketDecoderEvents_ {
    uint8_t cnt;
    uint8_t events[PACKET_DECODER_EVENT_MAX];
} PacketDecoderEvents;


/* 
PQHandling(){
	PacketQueue *q = &trans_q['inputqueue-id'];
}

*/