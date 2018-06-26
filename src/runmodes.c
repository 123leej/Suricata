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

/** \file
 *
 *  \author Victor Julien <victor@inliniac.net>
 *
 *  Pre-cooked threading runmodes.
 */

#include "suricata-common.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "tm-threads.h"
#include "util-debug.h"
#include "util-time.h"
#include "util-cpu.h"
#include "util-byte.h"
#include "conf.h"
#include "queue.h"

#include "alert-fastlog.h"
#include "alert-prelude.h"
#include "alert-unified-log.h"
#include "alert-unified-alert.h"
#include "alert-unified2-alert.h"
#include "alert-debuglog.h"

#include "log-httplog.h"

#include "output.h"


/**
 * A list of output modules that will be active for the run mode.
 */
typedef struct RunModeOutput_ {
    TmModule *tm_module;
    OutputCtx *output_ctx;

    TAILQ_ENTRY(RunModeOutput_) entries;
} RunModeOutput;
TAILQ_HEAD(, RunModeOutput_) RunModeOutputs =
    TAILQ_HEAD_INITIALIZER(RunModeOutputs);

/**
 * Cleanup the run mode.
 */
void RunModeShutDown(void)
{
    /* Close any log files. */
    RunModeOutput *output;
    while ((output = TAILQ_FIRST(&RunModeOutputs))) {
        SCLogDebug("Shutting down output %s.", output->tm_module->name);
        TAILQ_REMOVE(&RunModeOutputs, output, entries);
        if (output->output_ctx != NULL && output->output_ctx->DeInit != NULL)
            output->output_ctx->DeInit(output->output_ctx);
        SCFree(output);
    }
}

/**
 * Initialize the output modules.
 */
void RunModeInitializeOutputs(void)
{
    ConfNode *outputs = ConfGetNode("outputs");
    if (outputs == NULL) {
        /* No "outputs" section in the configuration. */
        return;
    }

    ConfNode *output, *output_config;
    TmModule *tm_module;
    const char *enabled;

    TAILQ_FOREACH(output, &outputs->head, next) {

        OutputModule *module = OutputGetModuleByConfName(output->val);
        if (module == NULL) {
            SCLogWarning(SC_ERR_INVALID_ARGUMENT,
                "No output module named %s, ignoring", output->val);
            continue;
        }

        output_config = ConfNodeLookupChild(output, module->conf_name);
        if (output_config == NULL) {
            /* Shouldn't happen. */
            SCLogError(SC_ERR_INVALID_ARGUMENT,
                "Failed to lookup configuration child node: fast");
            exit(1);
        }

        enabled = ConfNodeLookupChildValue(output_config, "enabled");
        if (enabled != NULL && strcasecmp(enabled, "yes") == 0) {
            OutputCtx *output_ctx = NULL;
            if (module->InitFunc != NULL) {
                output_ctx = module->InitFunc(output_config);
                if (output_ctx == NULL) {
                    /* In most cases the init function will have logged the
                     * error. Maybe we should exit on init errors? */
                    continue;
                }
            }
            tm_module = TmModuleGetByName(module->name);
            if (tm_module == NULL) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                    "TmModuleGetByName for %s failed", module->name);
                exit(EXIT_FAILURE);
            }
            RunModeOutput *runmode_output = SCCalloc(1, sizeof(RunModeOutput));
            if (runmode_output == NULL)
                return;
            runmode_output->tm_module = tm_module;
            runmode_output->output_ctx = output_ctx;
            TAILQ_INSERT_TAIL(&RunModeOutputs, runmode_output, entries);
        }
    }
}

/**
 * Setup the outputs for this run mode.
 *
 * \param tv The ThreadVars for the thread the outputs will be
 * appended to.
 */
static void SetupOutputs(ThreadVars *tv)
{
    RunModeOutput *output;
    TAILQ_FOREACH(output, &RunModeOutputs, entries) {
        tv->cap_flags |= output->tm_module->cap_flags;
        TmVarSlotSetFuncAppend(tv, output->tm_module, output->output_ctx);
    }
}

static int threading_set_cpu_affinity = FALSE;
static float threading_detect_ratio = 1;

/**
 * Initialize the output modules.
 */
static void RunModeInitialize(void)
{
    if ((ConfGetBool("threading.set_cpu_affinity", &threading_set_cpu_affinity)) == 0) {
        threading_set_cpu_affinity = FALSE;
    }
    if ((ConfGetFloat("threading.detect_thread_ratio", &threading_detect_ratio)) != 1) {
        threading_detect_ratio = 1;
    }

    SCLogDebug("threading_detect_ratio %f", threading_detect_ratio);
}

/**
 * \brief RunModeIpsNFQAuto set up the following thread packet handlers:
 *        - Receive thread (from NFQ)
 *        - Decode thread
 *        - Stream thread
 *        - Detect: If we have only 1 cpu, it will setup one Detect thread
 *                  If we have more than one, it will setup num_cpus - 1
 *                  starting from the second cpu available.
 *        - Veredict thread (NFQ)
 *        - Respond/Reject thread
 *        - Outputs thread
 *        By default the threads will use the first cpu available
 *        except the Detection threads if we have more than one cpu
 *
 * \param de_ctx pointer to the Detection Engine
 * \param nfqid pointer to the netfilter queue id
 * \retval 0 if all goes well. (If any problem is detected the engine will
 *           exit())
 */
//TODO Check Point 19-2
int RunModeIpsNFQAuto(DetectEngineCtx *de_ctx, char *nfq_id) {
    SCEnter();
    char tname[12];
    uint16_t cpu = 0;

    /* Available cpus */
    uint16_t ncpus = UtilCpuGetNumProcessorsOnline();

    RunModeInitialize();

    TimeModeSetLive();
    //TODO Check Point 20
    /* create the threads */
    ThreadVars *tv_receivenfq = TmThreadCreatePacketHandler("ReceiveNFQ","packetpool","packetpool","pickup-queue","simple","1slot_noinout");
    if (tv_receivenfq == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }

    //TODO Check Point 21
    TmModule *tm_module = TmModuleGetByName("ReceiveNFQ");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed for ReceiveNFQ\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_receivenfq,tm_module,nfq_id);

    if (threading_set_cpu_affinity) {
        TmThreadSetCPUAffinity(tv_receivenfq, 0);
        if (ncpus > 1)
            TmThreadSetThreadPriority(tv_receivenfq, PRIO_MEDIUM);
    }
    //TODO Check Point 22
    if (TmThreadSpawn(tv_receivenfq) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }
    //TODO Check Point 23
    ThreadVars *tv_decode1 = TmThreadCreatePacketHandler("Decode1","pickup-queue","simple","decode-queue1","simple","1slot");
    if (tv_decode1 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Decode1\n");
        exit(EXIT_FAILURE);
    }

    //TODO Check Point 24
    tm_module = TmModuleGetByName("DecodeNFQ");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName DecodeNFQ failed\n");
        exit(EXIT_FAILURE);
    }

    Tm1SlotSetFunc(tv_decode1,tm_module,NULL);

    if (threading_set_cpu_affinity) {
        TmThreadSetCPUAffinity(tv_decode1, 0);
        if (ncpus > 1)
            TmThreadSetThreadPriority(tv_decode1, PRIO_MEDIUM);
    }

    if (TmThreadSpawn(tv_decode1) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }
    //TODO Check Point 25
    ThreadVars *tv_stream1 = TmThreadCreatePacketHandler("Stream1","decode-queue1","simple","stream-queue1","simple","1slot");
    if (tv_stream1 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Stream1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("StreamTcp");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_stream1,tm_module,NULL);

    if (threading_set_cpu_affinity) {
        TmThreadSetCPUAffinity(tv_stream1, 0);
        if (ncpus > 1)
            TmThreadSetThreadPriority(tv_stream1, PRIO_MEDIUM);
    }

    if (TmThreadSpawn(tv_stream1) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    /* start with cpu 1 so that if we're creating an odd number of detect
     * threads we're not creating the most on CPU0. */
    if (ncpus > 0)
        cpu = 1;
    //TODO Check Point 26
    /* always create at least one thread */
    int thread_max = ncpus * threading_detect_ratio;
    if (thread_max < 1)
        thread_max = 1;

    int thread;
    //TODO Check Point 27
    for (thread = 0; thread < thread_max; thread++) {
        snprintf(tname, sizeof(tname),"Detect%"PRIu16, thread+1);
        if (tname == NULL)
            break;

        char *thread_name = SCStrdup(tname);
        SCLogDebug("Assigning %s affinity to cpu %u", thread_name, cpu);

        ThreadVars *tv_detect_ncpu = TmThreadCreatePacketHandler(thread_name,"stream-queue1","simple","verdict-queue","simple","1slot");
        if (tv_detect_ncpu == NULL) {
            printf("ERROR: TmThreadsCreate failed\n");
            exit(EXIT_FAILURE);
        }
        tm_module = TmModuleGetByName("Detect");
        if (tm_module == NULL) {
            printf("ERROR: TmModuleGetByName Detect failed\n");
            exit(EXIT_FAILURE);
        }
        Tm1SlotSetFunc(tv_detect_ncpu,tm_module,(void *)de_ctx);

        if (threading_set_cpu_affinity) {
            TmThreadSetCPUAffinity(tv_detect_ncpu, (int)cpu);
            /* If we have more than one core/cpu, the first Detect thread
             * (at cpu 0) will have less priority (higher 'nice' value)
             * In this case we will set the thread priority to +10 (default is 0)
             */
            if (cpu == 0 && ncpus > 1) {
                TmThreadSetThreadPriority(tv_detect_ncpu, PRIO_LOW);
            } else if (ncpus > 1) {
                TmThreadSetThreadPriority(tv_detect_ncpu, PRIO_MEDIUM);
            }
        }

        char *thread_group_name = SCStrdup("Detect");
        if (thread_group_name == NULL) {
            printf("Error allocating memory\n");
            exit(EXIT_FAILURE);
        }
        tv_detect_ncpu->thread_group_name = thread_group_name;

        if (TmThreadSpawn(tv_detect_ncpu) != TM_ECODE_OK) {
            printf("ERROR: TmThreadSpawn failed\n");
            exit(EXIT_FAILURE);
        }

        if ((cpu + 1) == ncpus)
            cpu = 0;
        else
            cpu++;
    }
    //TODO Check Point
    ThreadVars *tv_verdict = TmThreadCreatePacketHandler("Verdict","verdict-queue","simple","respond-queue","simple","1slot");
    if (tv_verdict == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("VerdictNFQ");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName VerdictNFQ failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_verdict,tm_module,nfq_id);

    if (threading_set_cpu_affinity) {
        TmThreadSetCPUAffinity(tv_verdict, 0);
        if (ncpus > 1)
            TmThreadSetThreadPriority(tv_verdict, PRIO_MEDIUM);
    }

    if (TmThreadSpawn(tv_verdict) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }
    //TODO Check Point
    ThreadVars *tv_rreject = TmThreadCreatePacketHandler("RespondReject","respond-queue","simple","alert-queue1","simple","1slot");
    if (tv_rreject == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("RespondReject");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for RespondReject failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_rreject,tm_module,NULL);

    if (threading_set_cpu_affinity) {
        TmThreadSetCPUAffinity(tv_rreject, 0);
        if (ncpus > 1)
            TmThreadSetThreadPriority(tv_rreject, PRIO_MEDIUM);
    }

    if (TmThreadSpawn(tv_rreject) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }
    //TODO Check Point
    ThreadVars *tv_outputs = TmThreadCreatePacketHandler("Outputs",
        "alert-queue1", "simple", "packetpool", "packetpool", "varslot");

    if (threading_set_cpu_affinity) {
        TmThreadSetCPUAffinity(tv_outputs, 0);
        if (ncpus > 1)
            TmThreadSetThreadPriority(tv_outputs, PRIO_MEDIUM);
    }
    SetupOutputs(tv_outputs);
    if (TmThreadSpawn(tv_outputs) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    return 0;
}
