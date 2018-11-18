/* Copyright (C) 2007-2010 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 */

#include "suricata-common.h"

#include <getopt.h>
#include <signal.h>
#include <pthread.h>

#include "suricata.h"
#include "decode.h"
#include "detect.h"
#include "packet-queue.h"
#include "threads.h"
#include "threadvars.h"

#include "util-spm.h"
#include "util-hash.h"
#include "util-hashlist.h"
#include "util-bloomfilter.h"
#include "util-bloomfilter-counting.h"
#include "util-pool.h"
#include "util-byte.h"
#include "util-cpu.h"
#include "util-action.h"
#include "util-pidfile.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-sigorder.h"
#include "detect-engine-payload.h"
#include "detect-engine-dcepayload.h"
#include "detect-engine-uri.h"
#include "detect-engine-state.h"
#include "detect-engine-tag.h"

#include "tm-queuehandlers.h"
#include "tm-queues.h"
#include "tm-modules.h"
#include "tm-threads.h"

#include "conf.h"
#include "conf-yaml-loader.h"

#include "alert-fastlog.h"
#include "alert-unified-log.h"
#include "alert-unified-log.h"
#include "alert-unified-alert.h"
#include "alert-unified2-alert.h"
#include "alert-debuglog.h"
#include "alert-prelude.h"

#include "log-httplog.h"

#include "stream-tcp.h"

#include "source-nfq.h"
#include "source-nfq-prototypes.h"

#include "respond-reject.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-bit.h"
#include "flow-alert-sid.h"
#include "pkt-var.h"

#include "app-layer-detect-proto.h"
#include "app-layer-parser.h"
#include "app-layer-tls.h"
#include "app-layer-smb.h"
#include "app-layer-dcerpc.h"
#include "app-layer-dcerpc-udp.h"
#include "app-layer-htp.h"
#include "app-layer-ftp.h"
#include "app-layer-ssl.h"

#include "util-radix-tree.h"
#include "util-host-os-info.h"
#include "util-cidr.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-time.h"
#include "util-rule-vars.h"
#include "util-classification-config.h"
#include "util-threshold-config.h"
#include "util-profiling.h"

#include "defrag.h"

#include "runmodes.h"

#include "util-decode-asn1.h"
#include "util-debug.h"
#include "util-error.h"
#include "detect-engine-siggroup.h"
#include "util-daemon.h"
#include "reputation.h"


#include "output.h"
#include "util-privs.h"

#include "tmqh-packetpool.h"

#include "util-ringbuffer.h"

/*
 * we put this here, because we only use it here in main.
 */
volatile sig_atomic_t sigint_count = 0;
volatile sig_atomic_t sighup_count = 0;
volatile sig_atomic_t sigterm_count = 0;

/* Max packets processed simultaniously. */
#define DEFAULT_MAX_PENDING_PACKETS 50

/** suricata engine control flags */
uint8_t suricata_ctl_flags = 0;

/** Run mode selected */
int run_mode = MODE_UNKNOWN;

/** Maximum packets to simultaneously process. */
intmax_t max_pending_packets;

/** set caps or not */
int sc_set_caps;


static void SignalHandlerSigint(/*@unused@*/ int sig) {
    sigint_count = 1;
    suricata_ctl_flags |= SURICATA_STOP;
}
static void SignalHandlerSigterm(/*@unused@*/ int sig) {
    sigterm_count = 1;
    suricata_ctl_flags |= SURICATA_KILL;
}

static void SignalHandlerSetup(int sig, void (*handler)())
{
    struct sigaction action;

    action.sa_handler = handler;
    sigemptyset(&(action.sa_mask));
    sigaddset(&(action.sa_mask),sig);
    action.sa_flags = 0;
    sigaction(sig, &action, 0);
}

void GlobalInits()
{
    memset(trans_q, 0, sizeof(trans_q));
    memset(data_queues, 0, sizeof(data_queues));

    /* Initialize the trans_q mutex */
    int blah;
    int r = 0;
    for(blah=0;blah<256;blah++) {
        r |= SCMutexInit(&trans_q[blah].mutex_q, NULL);
        r |= SCCondInit(&trans_q[blah].cond_q, NULL);

        r |= SCMutexInit(&data_queues[blah].mutex_q, NULL);
        r |= SCCondInit(&data_queues[blah].cond_q, NULL);
   }

    if (r != 0) {
        SCLogInfo("Trans_Q Mutex not initialized correctly");
        exit(EXIT_FAILURE);
    }
}

/* XXX hack: make sure threads can stop the engine by calling this
   function. Purpose: pcap file mode needs to be able to tell the
   engine the file eof is reached. */
void EngineStop(void) {
    suricata_ctl_flags |= SURICATA_STOP;
}

void EngineKill(void) {
    suricata_ctl_flags |= SURICATA_KILL;
}

static void SetBpfString(int optind, char *argv[]) {
    char *bpf_filter = NULL;
    uint32_t bpf_len = 0;
    int tmpindex = 0;

    /* attempt to parse remaining args as bpf filter */
    tmpindex = optind;
    while(argv[tmpindex] != NULL) {
        bpf_len+=strlen(argv[tmpindex]) + 1;
        tmpindex++;
    }

    if (bpf_len == 0)
        return;

    bpf_filter = SCMalloc(bpf_len);
    if (bpf_filter == NULL)
        return;
    memset(bpf_filter, 0x00, bpf_len);

    tmpindex = optind;
    while(argv[tmpindex] != NULL) {
        strlcat(bpf_filter, argv[tmpindex],bpf_len);
        if(argv[tmpindex + 1] != NULL) {
            strlcat(bpf_filter," ", bpf_len);
        }
        tmpindex++;
    }

    if(strlen(bpf_filter) > 0) {
        if (ConfSet("bpf-filter", bpf_filter, 0) != 1) {
            fprintf(stderr, "ERROR: Failed to set bpf filter.\n");
            exit(EXIT_FAILURE);
        }
    }
}

void usage(const char *progname)
{
    printf("%s %s\n", PROG_NAME, PROG_VER);
    printf("USAGE: %s\n\n", progname);
    printf("\t-c <path>                    : path to configuration file\n");
    printf("\t-q <qid>                     : run in inline nfqueue mode\n");
     printf("\n");
    printf("\nTo run the engine with default configuration on "
            "interface eth0 with signature file \"signatures.rules\", run the "
            "command as:\n\n%s -c suricata.yaml -s signatures.rules -i eth0 \n\n",
            progname);
}


int main(int argc, char **argv) {
    int opt;
    char *pcap_file = NULL;
    char pcap_dev[128];
    char *pfring_dev = NULL;
    char *sig_file = NULL;
    char *nfq_id = NULL;
    char *conf_filename = NULL;
    char *pid_filename = NULL;

    int dump_config = 0;
    int list_unittests = 0;
    int daemon = 0;
    char *user_name = NULL;
    char *group_name = NULL;
    uint8_t do_setuid = FALSE;
    uint8_t do_setgid = FALSE;
    uint32_t userid = 0;
    uint32_t groupid = 0;
    char *erf_file = NULL;
    char *dag_input = NULL;

    char *log_dir;
    struct stat buf;

    sc_set_caps = FALSE;

    /* initialize the logging subsys */
    SCLogInitLogModule(NULL);

    SCLogInfo("This is %s version %s", PROG_NAME, PROG_VER);

    /* Initialize the configuration module. */
    ConfInit();

    struct option long_opts[] = {
            {"dump-config",         0,                 &dump_config,    1},
            {"pfring-int",          required_argument, 0,               0},
            {"pfring-cluster-id",   required_argument, 0,               0},
            {"pfring-cluster-type", required_argument, 0,               0},
            {"pcap-buffer-size",    required_argument, 0,               0},
            {"unittest-filter",     required_argument, 0,               'U'},
            {"list-unittests",      0,                 &list_unittests, 1},
            {"pidfile",             required_argument, 0,               0},
            {"init-errors-fatal",   0,                 0,               0},
            {"fatal-unittests",     0,                 0,               0},
            {"user",                required_argument, 0,               0},
            {"group",               required_argument, 0,               0},
            {"erf-in",              required_argument, 0,               0},
            {"dag",                 required_argument, 0,               0},
            {NULL,                  0, NULL,                            0}
    };

    /* getopt_long stores the option index here. */
    int option_index = 0;

    char short_opts[] = "c:Dhi:l:q:d:r:us:U:V";

    while ((opt = getopt_long(argc, argv, short_opts, long_opts, &option_index)) != -1) {
        switch (opt) {
            case 'c':
                conf_filename = optarg;
                break;
            case 'q':
                if (run_mode == MODE_UNKNOWN) {
                    run_mode = MODE_NFQ;
                } else {
                    SCLogError(SC_ERR_MULTIPLE_RUN_MODE, "more than one run mode "
                                                         "has been specified");
                    usage(argv[0]);
                    exit(EXIT_SUCCESS);
                }
                nfq_id = optarg;
                break;
            default:
                usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    SetBpfString(optind, argv);

    UtilCpuPrintSummary();


    if (!CheckValidDaemonModes(daemon, run_mode)) {
        exit(EXIT_FAILURE);
    }
    /* Initializations for global vars, queues, etc (memsets, mutex init..) */
    GlobalInits();
    TimeInit();

    /* Load yaml configuration file if provided. */
    if (conf_filename != NULL) {
        if (ConfYamlLoadFile(conf_filename) != 0) {
            /* Error already displayed. */
            exit(EXIT_FAILURE);
        }
    } else if (run_mode != MODE_UNITTEST) {
        SCLogError(SC_ERR_OPENING_FILE, "Configuration file has not been provided");
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    if (dump_config) {
        ConfDump();
        exit(EXIT_SUCCESS);
    }

    /* Check for the existance of the default logging directory which we pick
     * from suricata.yaml.  If not found, shut the engine down */
    if (ConfGet("default-log-dir", &log_dir) != 1)
        log_dir = DEFAULT_LOG_DIR;
    if (stat(log_dir, &buf) != 0) {
        SCLogError(SC_ERR_LOGDIR_CONFIG, "The logging directory \"%s\" "
                                         "supplied by %s (default-log-dir) doesn't exist. "
                                         "Shutting down the engine", log_dir, conf_filename);
        exit(EXIT_FAILURE);
    }

    /* Pull the max pending packets from the config, if not found fall
     * back on a sane default. */
    if (ConfGetInt("max-pending-packets", &max_pending_packets) != 1)
        max_pending_packets = DEFAULT_MAX_PENDING_PACKETS;
    SCLogDebug("Max pending packets set to %"
                       PRIiMAX, max_pending_packets);

    /* Since our config is now loaded we can finish configurating the
     * logging module. */
    SCLogLoadConfig();

    /* Load the Host-OS lookup. */
    SCHInfoLoadFromConfig();

    if (run_mode == MODE_UNKNOWN) {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }


    /* create table for O(1) lowercase conversion lookup */
    uint8_t c = 0;
    for (; c < 255; c++) {
        if (c >= 'A' && c <= 'Z')
            g_u8_lowercasetable[c] = (c + ('a' - 'A'));
        else
            g_u8_lowercasetable[c] = c;
    }

    /* hardcoded initialization code */
    MpmTableSetup(); /* load the pattern matchers */
    SigTableSetup(); /* load the rule keywords */
    TmqhSetup();

    CIDRInit();
    SigParsePrepare();
    //PatternMatchPrepare(mpm_ctx, MPM_B2G);
    SCPerfInitCounterApi();

    SCReputationInitCtx();

    TagInitCtx();

    TmModuleReceiveNFQRegister();
    TmModuleVerdictNFQRegister();
    TmModuleDecodeNFQRegister();
    TmModuleReceivePacketQueueRegister();
    TmModuleVerdictPacketQueueRegister();
    TmModuleDecodePacketQueueRegister();
    TmModuleDetectRegister();
    TmModuleAlertFastLogRegister();
    TmModuleAlertDebugLogRegister();
    TmModuleAlertPreludeRegister();
    TmModuleRespondRejectRegister();
    TmModuleAlertFastLogIPv4Register();
    TmModuleAlertFastLogIPv6Register();
    TmModuleAlertUnifiedLogRegister();
    TmModuleAlertUnifiedAlertRegister();
    TmModuleUnified2AlertRegister();
    TmModuleStreamTcpRegister();
    TmModuleLogHttpLogRegister();
    TmModuleLogHttpLogIPv4Register();
    TmModuleLogHttpLogIPv6Register();
    TmModuleDebugList();

    /** \todo we need an api for these */
    AppLayerDetectProtoThreadInit();
    RegisterAppLayerParsers();
    RegisterHTPParsers();
    RegisterTLSParsers();
    RegisterSMBParsers();
    RegisterDCERPCParsers();
    RegisterDCERPCUDPParsers();
    RegisterFTPParsers();
    RegisterSSLParsers();
    AppLayerParsersInitPostProcess();

    if (daemon == 1) {
        Daemonize();
        if (pid_filename != NULL) {
            if (SCPidfileCreate(pid_filename) != 0) {
                pid_filename = NULL;
                exit(EXIT_FAILURE);
            }
        }
    } else {
        if (pid_filename != NULL) {
            SCLogError(SC_ERR_PIDFILE_DAEMON, "The pidfile file option applies "
                                              "only to the daemon modes");
            pid_filename = NULL;
            exit(EXIT_FAILURE);
        }
    }

    /* registering signals we use */
    SignalHandlerSetup(SIGINT, SignalHandlerSigint);
    SignalHandlerSetup(SIGTERM, SignalHandlerSigterm);

    /* SIGHUP is not implemnetd on WIN32 */
    //SignalHandlerSetup(SIGHUP, SignalHandlerSighup);
    /* Get the suricata user ID to given user ID */
    if (do_setuid == TRUE) {
        if (SCGetUserID(user_name, group_name, &userid, &groupid) != 0) {
            SCLogError(SC_ERR_UID_FAILED, "failed in getting user ID");
            exit(EXIT_FAILURE);
        }

        sc_set_caps = TRUE;
        /* Get the suricata group ID to given group ID */
    } else if (do_setgid == TRUE) {
        if (SCGetGroupID(group_name, &groupid) != 0) {
            SCLogError(SC_ERR_GID_FAILED, "failed in getting group ID");
            exit(EXIT_FAILURE);
        }

        sc_set_caps = TRUE;
    }
    /* pre allocate packets */
    SCLogDebug("preallocating packets... packet size %"
                       PRIuMAX
                       "", (uintmax_t) sizeof(Packet));
    int i = 0;
    for (i = 0; i < max_pending_packets; i++) {
        /* XXX pkt alloc function */
        Packet *p = SCMalloc(sizeof(Packet));
        if (p == NULL) {
            SCLogError(SC_ERR_FATAL, "Fatal error encountered while allocating a packet. Exiting...");
            exit(EXIT_FAILURE);
        }
        PACKET_INITIALIZE(p);

        PacketPoolStorePacket(p);
    }
    SCLogInfo("preallocated %"
                      PRIiMAX
                      " packets. Total memory %"
                      PRIuMAX
                      "",
              max_pending_packets, (uintmax_t) (max_pending_packets * sizeof(Packet)));

    FlowInitConfig(FLOW_VERBOSE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();

    SCClassConfLoadClassficationConfigFile(de_ctx);

    ActionInitConfig();
    if (SigLoadSignatures(de_ctx, sig_file) < 0) {
        if (sig_file == NULL) {
            SCLogError(SC_ERR_OPENING_FILE, "Signature file has not been provided");
        } else {
            SCLogError(SC_ERR_NO_RULES_LOADED, "Loading signatures failed.");
        }
        if (de_ctx->failure_fatal)
            exit(EXIT_FAILURE);
    }


    AppLayerHtpRegisterExtraCallbacks();
    SCThresholdConfInitContext(de_ctx, NULL);

    struct timeval start_time;
    memset(&start_time, 0, sizeof(start_time));
    gettimeofday(&start_time, NULL);
    SCDropMainThreadCaps(userid, groupid);
    RunModeInitializeOutputs();

    /* run the selected runmode */
    if (run_mode == MODE_NFQ) {
        RunModeIpsNFQAuto(de_ctx, nfq_id);
    } else {
        SCLogError(SC_ERR_UNKNOWN_RUN_MODE, "Unknown runtime mode. Aborting");
        exit(EXIT_FAILURE);
    }

    /* Spawn the flow manager thread */
    FlowManagerThreadSpawn();

    StreamTcpInitConfig(STREAM_VERBOSE);
    DefragInit();

    /* Spawn the perf counter threads.  Let these be the last one spawned */
    SCPerfSpawnThreads();

    /* Check if the alloted queues have at least 1 reader and writer */
    TmValidateQueueState();

    /* Wait till all the threads have been initialized */
    if (TmThreadWaitOnThreadInit() == TM_ECODE_FAILED) {
        SCLogError(SC_ERR_INITIALIZATION, "Engine initialization failed, "
                                          "aborting...");
        exit(EXIT_FAILURE);
    }
    /* Un-pause all the paused threads */
    TmThreadContinueThreads();


    //send init finish

    while(1) {
        if (suricata_ctl_flags != 0) {
            SCLogInfo("signal received");

            if (suricata_ctl_flags & SURICATA_STOP)  {
                SCLogInfo("EngineStop received");

                /* Stop the engine so it quits after processing the pcap file
                 * but first make sure all packets are processed by all other
                 * threads. */
                char done = 0;
                do {
                    if (suricata_ctl_flags & SURICATA_KILL)
                        break;

                    /* if all packets are returned to the packetpool
                     * we are done */
                    if (PacketPoolSize() == max_pending_packets)
                        done = 1;

                    if (done == 0) {
                        usleep(100);
                    }
                } while (done == 0);

                SCLogInfo("all packets processed by threads, stopping engine");
            }

            struct timeval end_time;
            memset(&end_time, 0, sizeof(end_time));
            gettimeofday(&end_time, NULL);

            SCLogInfo("time elapsed %" PRIuMAX "s", (uintmax_t)(end_time.tv_sec - start_time.tv_sec));

            TmThreadKillThreads();
            SCPerfReleaseResources();
            break;
        }

        TmThreadCheckThreadState();

        usleep(100);
    }


    FlowShutdown();
    FlowPrintQueueInfo();
    StreamTcpFreeConfig(STREAM_VERBOSE);
    HTPFreeConfig();
    HTPAtExitPrintStats();


    SCPidfileRemove(pid_filename);

    /** \todo review whats needed here */
    SigGroupCleanup(de_ctx);

    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    AlpProtoDestroy();

    TagDestroyCtx();

    RunModeShutDown();
    OutputDeregisterAll();
    TimeDeinit();

    exit(EXIT_SUCCESS);
}
