
#include "cpuminer-config.h"
//#define _GNU_SOURCE

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
//#include <pthread.h>


#include <errno.h>
#include <signal.h>
#include <sys/resource.h>
#if HAVE_SYS_SYSCTL_H
#include <sys/types.h>
  #if HAVE_SYS_PARAM_H
    #include <sys/param.h>
  #endif
#include <sys/sysctl.h>
#endif

//TODO XXX WHich is better?
//JSON
#include <jansson.h>
//JSON2
#include <jsmn/jsmn.h>

#include "miner.h"
#include "compat.h"
#include "elist.h"

bool miner_init = false;

static unsigned int opt_nfactor = 6;
const int opt_n_threads = 1;
bool jsonrpc_2 = false;



#ifdef DEBUG
const bool opt_benchmark = true;
const bool opt_debug = true;
const bool opt_debug_diff = true;
#else
const bool opt_benchmark = false;
const bool opt_debug = false;
const bool opt_debug_diff = false;
#endif

double opt_max_diff = 0.0;
int opt_scrypt_n = 1024;

const int opt_time_limit = 0;
double opt_diff_factor = 1.0;

double net_diff = 0.;


bool have_gbt = false;
bool aes_ni_supported = false;

bool opt_extranonce = false;

struct work_restart *work_restart = NULL;

struct stratum_ctx sctx;

//This is needed for the commit solution
char *rpc_user = "IRGENDEINE ADDR";
char rpc2_id[64] = "";

//EXPORTED STUFF
uint64_t hashes_done = 0;
static double thr_hashrate;

void (*gCallbackJob)(int, double);
void (*gCallbackAddHash)(void);
void (*gCallbackSubmitSolution)(char*);

#define min(a, b) ((a) < (b) ? a : b)
#define max(a, b) ((a) > (b) ? a : b)

uint64_t getHashes(){
  return hashes_done;
}

double getHashRate(){
  return thr_hashrate;
}

char* getJob(){
    char *test = "C: Internal Test\n";
    return test;
}

void registerJobCallBack(const char *c){
    int fp = atoi(c);
    void (*f)(int, double) = (void (*)(int, double))(fp);
    gCallbackJob = f;
    LOG("%s", "C: Registered jobCallBack\n");
}


void registerAddHashCallBack(const char *c){
    int fp = atoi(c);
    void (*f)(void) = (void (*)(void))(fp);
    gCallbackAddHash = f;
    LOG("C: Registered AddHashCallBack\n");
}

void registerSubmitSolutionCallBack(const char *c){
	int fp = atoi(c);
	void (*f)(char*) = (void (*)(char*))(fp);
	gCallbackSubmitSolution = f;
	LOG("C: Registered SubmitSolutionCallBack\n");
}

void updateStats(){
  LOG("C: Updated Stats\n");
  work_restart[0].restart = true;
}

void init_SCTX(struct stratum_ctx *sctx)
{
    //TODO FREE UND SO
    sctx->job.job_id = (char *)malloc(10);
    sctx->job.coinbase = NULL;//(unsigned char *)malloc(128); //TODO size bestimmen
    sctx->xnonce2_size = 4; //KP warum 4
    sctx->job.xnonce2 = (unsigned char *)calloc(sctx->xnonce2_size = 4, 1);
    sctx->next_diff = 1024; //This is actual unused, because its will be overwritten. Its only usefull if the miner is started from main(); Otherwise the miner will use the given stratum diff
}

static void calc_network_diff(struct work *work)
{
    //Curretly not in use

	// sample for diff 43.281 : 1c05ea29
	// TODO: endian reversed on longpoll could be zr5 specific...
	//uint32_t nbits = have_longpoll ? work->data[18] : swab32(work->data[18]);
    uint32_t nbits = swab32(work->data[18]);
#if defined(lbry)
    nbits = swab32(work->data[26]);
#elif defined(decred)
    nbits = work->data[29];
#elif defined(sia)
    nbits = work->data[11]; //TODO unsure if correct
#endif
	uint32_t bits = (nbits & 0xffffff);
	int16_t shift = (swab32(nbits) & 0xff); // 0x1c = 28

	double d = (double)0x0000ffff / (double)bits;
	for (int m=shift; m < 29; m++) d *= 256.0;
	for (int m=29; m < shift; m++) d /= 256.0;
#if defined(decred)
    if(shift == 28)  d *= 256.0; // testnet
#endif
	if (opt_debug_diff)
		LOG("C: net diff: %f -> shift %u, bits %08x\n", d, shift, bits);
	net_diff = d;
}

bool get_work(struct thr_info *thr, struct work *work, const char *job_str){
    json_t *params, *val;
    bool ret;
    json_error_t err;
    //LOG("Working1...\n");
    LOG("C: parsing: %s\n", job_str);

    val = JSON_LOADS(job_str, &err);
    if (!val) {
        LOG("C: JSON decode failed(%d): %s\n", err.line, err.text);
        return false;
    }
    //LOG("Still Working2...\n");
    params = json_object_get(val, "params");
    if (!params){
        LOG("C: PARSING PARAMS ERROR\n");
        return false;
    }

    ret = stratum_notify(&sctx, params);
    if (!ret){
        LOG("C: PARSING JOB ERROR\n");
        return false;
    }

    //LOG("Still Working3..\n")
    ret = stratum_gen_work(&sctx, work);
    if (ret == false){
        LOG("C: GEN JOB ERROR\n");
        return false;
    }

    return true;
}

//Currently unused, but maybe in a time....
bool stratum_parse_extranonce(struct stratum_ctx *sctx, json_t *params, int pndx)
{
	const char* xnonce1;
	int xn2_size;

	xnonce1 = json_string_value(json_array_get(params, pndx));
	if (!xnonce1) {
		LOG("C: Failed to get extranonce1");
		goto out;
	}
	xn2_size = (int) json_integer_value(json_array_get(params, pndx+1));
	if (!xn2_size) {
		LOG("C: Failed to get extranonce2_size");
		goto out;
	}
	if (xn2_size < 2 || xn2_size > 16) {
		LOG("C: Failed to get valid n2size in parse_extranonce");
		goto out;
	}

	//pthread_mutex_lock(&sctx->work_lock);
	if (sctx->xnonce1)
		free(sctx->xnonce1);
	sctx->xnonce1_size = strlen(xnonce1) / 2;
	sctx->xnonce1 = (uchar*) calloc(1, sctx->xnonce1_size);
	if (unlikely(!sctx->xnonce1)) {
		LOG("C: Failed to alloc xnonce1");
		//pthread_mutex_unlock(&sctx->work_lock);
		goto out;
	}
	hex2bin(sctx->xnonce1, xnonce1, sctx->xnonce1_size);
	sctx->xnonce2_size = xn2_size;
	//pthread_mutex_unlock(&sctx->work_lock);

	if (pndx == 0 && opt_debug) /* pool dynamic change */
		LOG("C: Stratum set nonce %s with extranonce2 size=%d",
			xnonce1, xn2_size);

	return true;
out:
	return false;
}

bool stratum_gen_work(struct stratum_ctx *sctx, struct work *work)
{
    //some local vars
    uint32_t extraheader[32] = { 0 };
    uchar merkle_root[64] = { 0 };
    int i, headersize = 0;

    free(work->job_id);
    work->job_id = strdup(sctx->job.job_id);
    work->xnonce2_len = sctx->xnonce2_size;
    work->xnonce2 = (uchar*) realloc(work->xnonce2, sctx->xnonce2_size);
    memcpy(work->xnonce2, sctx->job.xnonce2, sctx->xnonce2_size);

/* Generate merkle root */
#if defined(decred)
    // getwork over stratum, getwork merkle + header passed in coinb1
    memcpy(merkle_root, sctx->job.coinbase, 32);
    headersize = min((int)sctx->job.coinbase_size - 32, sizeof(extraheader));
    memcpy(extraheader, &sctx->job.coinbase[32], headersize);
#elif defined(heavy)
    heavyhash(merkle_root, sctx->job.coinbase, (int)sctx->job.coinbase_size);
#elif defined(groestl) || defined(keccak) || defined(blakecoin)
    //TODO ist das richtig?
    sph_shabal256_context ctx;

    sph_shabal256_init(&ctx);
    sph_shabal256(&ctx, sctx->job.coinbase, (int) sctx->job.coinbase_size);
    sph_shabal256_close(&ctx, merkle_root);

    //SHA256(sctx->job.coinbase, (int) sctx->job.coinbase_size, merkle_root);
#elif defined(sia)
    // getwork over stratum, getwork merkle + header passed in coinb1
    memcpy(merkle_root, sctx->job.coinbase, 32);
    headersize = min((int)sctx->job.coinbase_size - 32, sizeof(extraheader));
    memcpy(extraheader, &sctx->job.coinbase[32], headersize);
#else //default
    sha256d(merkle_root, sctx->job.coinbase, (int) sctx->job.coinbase_size);
    //LOG("Still Working4...\n")
#endif

    if (!headersize)
    for (i = 0; i < sctx->job.merkle_count; i++) {
        memcpy(merkle_root + 32, sctx->job.merkle[i], 32);
#ifdef heavy
        heavyhash(merkle_root, merkle_root, 64);
#else
        sha256d(merkle_root, merkle_root, 64);
#endif
    }
    //LOG("Still Working5.....\n")
    /* Increment extranonce2 */
    for (size_t t = 0; t < sctx->xnonce2_size && !(++sctx->job.xnonce2[t]); t++);
    //LOG("Still Working6\n")
    /* Assemble block header */
    memset(work->data, 0, 128);
    work->data[0] = le32dec(sctx->job.version);
    for (i = 0; i < 8; i++)
        work->data[1 + i] = le32dec((uint32_t *) sctx->job.prevhash + i);
    for (i = 0; i < 8; i++)
        work->data[9 + i] = be32dec((uint32_t *) merkle_root + i);

    //LOG("Still Working7\n")
#if defined(decred)
    uint32_t* extradata = (uint32_t*) sctx->xnonce1;
    for (i = 0; i < 8; i++) // prevhash
        work->data[1 + i] = swab32(work->data[1 + i]);
    for (i = 0; i < 8; i++) // merkle
        work->data[9 + i] = swab32(work->data[9 + i]);
    for (i = 0; i < headersize/4; i++) // header
        work->data[17 + i] = extraheader[i];
    // extradata
    for (i = 0; i < sctx->xnonce1_size/4; i++)
        work->data[36 + i] = extradata[i];
    for (i = 36 + (int) sctx->xnonce1_size/4; i < 45; i++)
        work->data[i] = 0;
    work->data[37] = (rand()*4) << 8;
    sctx->bloc_height = work->data[32];
    //applog_hex(work->data, 180);
    //applog_hex(&work->data[36], 36);
#elif defined(lbry)
    for (i = 0; i < 8; i++)
        work->data[17 + i] = ((uint32_t*)sctx->job.claim)[i];
    work->data[25] = le32dec(sctx->job.ntime);
    work->data[26] = le32dec(sctx->job.nbits);
    work->data[28] = 0x80000000;
#elif defined(sia)
    for (i = 0; i < 8; i++) // prevhash
        work->data[i] = ((uint32_t*)sctx->job.prevhash)[7-i];
    work->data[8] = 0; // nonce
    work->data[9] = swab32(extraheader[0]);
    work->data[9] |= rand() & 0xF0;
    work->data[10] = be32dec(sctx->job.ntime);
    work->data[11] = be32dec(sctx->job.nbits);
    for (i = 0; i < 8; i++) // prevhash
        work->data[12+i] = ((uint32_t*)merkle_root)[i];
    //applog_hex(&work->data[0], 80);
#elif defined(ethash)
	work->data[21] = sctx->bloc_height;
#else

    work->data[17] = le32dec(sctx->job.ntime);
    work->data[18] = le32dec(sctx->job.nbits);
    // required ?
    work->data[20] = 0x80000000;
    work->data[31] = 0x00000280;
    //LOG("Still Working8\n")
#endif
    if (opt_showdiff || opt_max_diff > 0.) //unneeded opt_max_diff is defined as 0
        calc_network_diff(work);

#if defined(drop) || defined(neoscrypt) || defined(zr5)
    /* reversed endian */
    for (i = 0; i <= 18; i++)
        work->data[i] = swab32(work->data[i]);
#endif



#if !defined(decred) || !defined(sia)
    if (opt_debug) {
        char *xnonce2str = abin2hex(work->xnonce2, work->xnonce2_len);
        LOG("C: DEBUG: job_id='%s' extranonce2=%s ntime=%08x\n",
                work->job_id, xnonce2str, swab32(work->data[17]));
        free(xnonce2str);
    }
#endif
    //LOG("Still Working9\n")

#if defined(drop) || defined(jha) || defined(scrypt) || defined(scryptjane) || defined(neoscrypt) || defined(pluck) || defined(yescrypt)
    work_set_target(work, sctx->job.diff / (65536.0 * opt_diff_factor));
#elif defined(fresh) || defined(dmdgr) || defined(groestl) || defined(lbry) || defined(lyra2rev2) || defined(timetravel) || defined(btcore) || defined(xevan)
    work_set_target(work, sctx->job.diff / (256.0 * opt_diff_factor));
#elif defined(keccak) || defined(lyra2)
    work_set_target(work, sctx->job.diff / (128.0 * opt_diff_factor));
#elif defined(x16r)
	work_set_target(work, sctx->job.diff / (256.0 * opt_diff_factor));
#elif defined(equihash)
	work_set_target(work, sctx->job.diff / 65536.0);
	//WRONG diff_to_target(work->target, sctx->job.diff / 65536.0); //TODO equihash
#else
    work_set_target(work, sctx->job.diff / opt_diff_factor);
#endif

/*TODO XXX I Think Useless
    if (stratum_diff != sctx->job.diff) {
        char sdiff[32] = { 0 };
        // store for api stats
        stratum_diff = sctx->job.diff;
        if (opt_showdiff && work->targetdiff != stratum_diff)
            snprintf(sdiff, 32, " (%.5f)", work->targetdiff);
        LOG("Stratum difficulty set to %g%s", stratum_diff, sdiff);
    }
*/


	unsigned char *hash_str = malloc((48*4*2) +1);
	bin2hex(hash_str, (unsigned char *)work->data, 48*4);

	LOG("DATA: ");
	LOG("%s", hash_str);
	LOG("\n");

	free(hash_str);

	LOG("Stratum difficulty %f, targetDiff %f, sharediff %f\n", 1024.0, work->targetdiff, work->sharediff);

    return true;
}


static bool submit_upstream_work(/*CURL *curl, */struct work *work)
{
	json_t *val, *res, *reason;
	char s[JSON_BUF_LEN];
	int i;
	bool rc = false;

	/* pass if the previous hash is not the current previous hash */
	//if (opt_algo != ALGO_SIA && !submit_old && memcmp(&work->data[1], &g_work.data[1], 32)) {
#ifndef sia
	/*TODO enable und gucken was submit old ist
	if(!submit_old && memcmp(&work->data[1], &g_work.data[1], 32)){
		if (opt_debug)
			LOG("DEBUG: stale work detected, discarding");
		return true;
	}*/
#endif

/* OWN wird nicht genutzt da have_stratum == True
	if (!have_stratum && allow_mininginfo) {
		struct work wheight;
		get_mininginfo(curl, &wheight);
		if (work->height && work->height <= net_blocks) {
			if (opt_debug)
				applog(LOG_WARNING, "block %u was already solved", work->height);
			return true;
		}
	}
*/
	//OWN: Allways true  if (have_stratum) {
		uint32_t ntime, nonce;
		unsigned char ntimestr[9], noncestr[9];


		//Habe hier mal nur jsonrpc2 verwednet kp ob das richtig ist
		if (jsonrpc_2) { //wird nicht aktiviert auser beu cryptolight, cryptonight
			uchar hash[32];

			bin2hex(noncestr, (const unsigned char *)work->data + 39, 4);
//			switch(opt_algo) {
#if defined(cryptolight)
//			case ALGO_CRYPTOLIGHT:
				cryptolight_hash(hash, work->data, 76);
#endif
#if defined(cryptonight)
			//case ALGO_CRYPTONIGHT:
				cryptonight_hash(hash, work->data, 76);
#endif

//			default:
//				break;
//			}
			char *hashhex = abin2hex(hash, 32);
			snprintf(s, JSON_BUF_LEN,
					"{\"method\": \"submit\", \"params\": {\"id\": \"%s\", \"job_id\": \"%s\", \"nonce\": \"%s\", \"result\": \"%s\"}, \"id\":4}\r\n",
					rpc2_id, work->job_id, noncestr, hashhex);
			free(hashhex);
		} else {
			char *xnonce2str;

//			switch (opt_algo) {
#if defined(devred)
//			case ALGO_DECRED:
				/* reversed */
				be32enc(&ntime, work->data[34]);
				be32enc(&nonce, work->data[35]);
#elif defined(lbry)
			//case ALGO_LBRY:
				le32enc(&ntime, work->data[25]);
				le32enc(&nonce, work->data[27]);
#elif defined(drop) || defined(neoscrypt) || defined(zr5)
			//case ALGO_DROP:
			//case ALGO_NEOSCRYPT:
			//case ALGO_ZR5:
				/* reversed */
				be32enc(&ntime, work->data[17]);
				be32enc(&nonce, work->data[19]);
#elif defined(sia)
			//case ALGO_SIA:
				/* reversed */
				be32enc(&ntime, work->data[10]);
				be32enc(&nonce, work->data[8]);
#else
				le32enc(&ntime, work->data[17]);
				le32enc(&nonce, work->data[19]);
#endif
//			}

			bin2hex(ntimestr, (const unsigned char *)(&ntime), 4);
			bin2hex(noncestr, (const unsigned char *)(&nonce), 4);

			//if (opt_algo == ALGO_DECRED) {
#if defined(decred)
				//xnonce2str = abin2hex((unsigned char*)(&work->data[36]), stratum.xnonce1_size);
				xnonce2str = abin2hex((unsigned char*)(&work->data[36]), sctx.xnonce1_size); //OWN
			//} else if (opt_algo == ALGO_SIA) {
#elif defined(sia)
				uint16_t high_nonce = swab32(work->data[9]) >> 16;
				xnonce2str = abin2hex((unsigned char*)(&high_nonce), 2);
			//} else {
#else
				xnonce2str = abin2hex(work->xnonce2, work->xnonce2_len);
			//}
#endif

			snprintf(s, JSON_BUF_LEN,
					"{\"method\": \"mining.submit\", \"params\": [\"%s\", \"%s\", \"%s\", \"%s\", \"%s\"], \"id\":4}",
					rpc_user, work->job_id, xnonce2str, ntimestr, noncestr);
			free(xnonce2str);
		//}

		// store to keep/display solved blocs (work struct not linked on accept notification)
		//REENABLE WAS IST stratum? stratum.sharediff = work->sharediff;

		/*
		if (unlikely(!stratum_send_line(&stratum, s))) {
			applog(LOG_ERR, "submit_upstream_work stratum_send_line failed");
			goto out;
		}
		*/

	}

	LOG("C: mining.submit: %s\n", s);
	rc = true;

	gCallbackSubmitSolution(s);

out:
	return rc;
}

static void *miner_thread(void *userdata, char *job_str) {
    struct thr_info *mythr = (struct thr_info*)userdata;
    int thr_id = mythr->id;
    struct work work = { { 0 } };
    uint32_t max_nonce;
    uint32_t end_nonce = 0xffffffffU / opt_n_threads * (thr_id + 1) - 0x20;
    char s[16];
    int i;

    time_t firstwork_time = 0;

    struct timeval tv_start, tv_end, diff;
    int64_t max64;
    bool regen_work = false;
    int wkcmp_offset = 0;
    int nonce_oft = 19*sizeof(uint32_t); // 76
    int wkcmp_sz = nonce_oft;
    int rc = 0;

#ifdef scrypt
    unsigned char *scratchbuf = scrypt_buffer_alloc(opt_scrypt_n);

    if (!scratchbuf) {
    		LOG("C: miner_thread: scrypt buffer allocation failed\n");
    		exit(1);
    }
#endif

#ifdef pluck
    static int opt_pluck_n = 128;
	unsigned char *scratchbuf = malloc(opt_pluck_n * 1024);
	if (!scratchbuf) {
		LOG("C: miner_thread: pluck buffer allocation failed\n");
		exit(1);
	}
#endif

    LOG("C: miner_thread: Start Miner: %s\n", PROGRAM_NAME);
    while (1) {
        #if defined(drop) || defined(zr5)
            // Duplicates: ignore pok in data[0]
            wkcmp_sz -= sizeof(uint32_t);
            wkcmp_offset = 1;
        #elif defined(decred)
            wkcmp_sz = nonce_oft = 140; // 35 * 4
            regen_work = true; // ntime not changed ?
        #elif defined(lbry)
            wkcmp_sz = nonce_oft = 108; // 27
            //regen_work = true;
        #elif defined(sia)
            nonce_oft = 32;
            wkcmp_offset = 32 + 16;
            wkcmp_sz = 32; // 35 * 4
        #endif

        uint32_t *nonceptr = (uint32_t*) (((char*)work.data) + (jsonrpc_2 ? 39 : 76));


        // to clean: is g_work loaded before the memcmp ?
        //regen_work = true;
        //uncomment her to activate real mining. Still need to implement the RPC Comm.
        /*regen_work = regen_work || ( (*nonceptr) >= end_nonce
            && !( memcmp(&work.data[wkcmp_offset], &g_work.data[wkcmp_offset], wkcmp_sz) ||
             jsonrpc_2 ? memcmp(((uint8_t*) work.data) + 43, ((uint8_t*) g_work.data) + 43, 33) : 0)); //unused because jsonrpc_2 = false
        */


        if (!regen_work) {
            regen_work = true;
        }else{
            LOG("C: miner_thread: Stop Worker and get new Job\n");
            gCallbackJob(hashes_done, thr_hashrate);
            break;
        }

        LOG("C: miner_thread: get new Work\n");
        get_work(mythr, &work, job_str);

        //WTF IS this shit
        /*if (memcmp(&work.data[wkcmp_offset], &g_work.data[wkcmp_offset], wkcmp_sz) ||
            jsonrpc_2 ? memcmp(((uint8_t*) work.data) + 43, ((uint8_t*) g_work.data) + 43, 33) : 0) //unused because jsonrpc_2
        {
            //work_free(&work);
            //work_copy(&work, &g_work);
            nonceptr = (uint32_t*) (((char*)work.data) + nonce_oft);
            *nonceptr = 0xffffffffU / opt_n_threads * thr_id;
            //if (opt_randomize)
            //    nonceptr[0] += ((rand()*4) & UINT32_MAX) / opt_n_threads;
        } else*/
            ++(*nonceptr);

        work_restart[thr_id].restart = 0;


        /* adjust max_nonce to meet target scan time */
        max64 = LP_SCANTIME; //Assumes have_stratum = True

        /* time limit */
		if (opt_time_limit && firstwork_time) {
			int passed = (int)(time(NULL) - firstwork_time);
			int remain = (int)(opt_time_limit - passed);
			if (remain < 0) {
				if (thr_id != 0) {
					sleep(1);
					continue;
				}
				if (opt_benchmark) {
					char rate[32];
					format_hashrate((double)global_hashrate, rate);
					LOG("C: miner_thread: Benchmark: %s\n", rate);
					fprintf(stderr, "%llu\n", (long long unsigned int) global_hashrate);
				} else {
					LOG("C: miner_thread: Mining timeout of %ds reached, exiting...\n", opt_time_limit);
				}

				LOG("C: WHAT IS THIS EXIT\n");
				exit(0);
			}
			if (remain < max64) max64 = remain;
		}

        max64 *= thr_hashrate;

        if (max64 <= 0) {
            max64 = 0x1fffffLL;
#if defined(scrypt) || defined(ALGO_NEOSCRYPT)
            max64 = opt_scrypt_n < 16 ? 0x3ffff : 0x3fffff / opt_scrypt_n;
            if (opt_nfactor > 3)
                max64 >>= (opt_nfactor - 3);
            else if (opt_nfactor > 16)
                max64 = 0xF;
#endif
#if defined(axiom) || defined(cryptonight) || defined(cryptolight) || defined(scryptjane)
                max64 = 0x40LL;
#endif
#if defined(drop) || defined(pluck) || defined(yescrypt)
                max64 = 0x1ff;
#endif
#if defined(lyra2) || defined(lyra2rev2) || defined(timetravel) || defined(bitcore) || defined(xevan)
                max64 = 0xffff;
#endif
#if defined(c11) || defined(dmdgr) || defined(fresh) || defined(groestl) || defined(myrgr) || defined(sib) || defined(veltor) || defined(x11evo) || defined(x11) || defined(x13) || defined(x14)
                max64 = 0x3ffff;
#endif
#if defined(lbry) || defined(tribus) || defined(x15) || defined(x17) || defined(zr5) || defined(x16r)
                max64 = 0x1ffff;
#endif
#if defined(bmw) || defined(pentablake)
                max64 = 0x3ffff;
#endif
#if defined(skein) || defined(skein2)
                max64 = 0x7ffffLL;
#endif
#if defined(blake) || defined(blakecoin) || defined(decred) || defined(vanilla)
                max64 = 0x3fffffLL;
#endif
#if defined(sia)
            	max64 = 0x1fffffLL;
#endif
#if defined(equihash)
				max64 = 0x1fffff;
				// TODO equihash max64 = opt_scrypt_n < 16 ? 0x3ffff : 0x3fffff / opt_scrypt_n;
#endif
#if defined(equihash)
				max64 = 0x11;//TODO
#endif
        }

        if (*nonceptr + max64 > end_nonce)
            max_nonce = end_nonce;
        else
            max_nonce = *nonceptr + max64;

        hashes_done = 0;
        gettimeofday(&tv_start, NULL );


        /* scan nonces for a proof-of-work hash */
        #if   defined(scrypt)
            rc = hash(thr_id, &work, max_nonce, &hashes_done, scratchbuf, opt_scrypt_n);
        #elif defined(scryptjane)
            rc = hash(opt_scrypt_n, thr_id, &work, max_nonce, &hashes_done);
        #elif defined(neoscrypt)
            rc = hash(thr_id, &work, max_nonce, &hashes_done, 0x80000020 | (opt_nfactor << 8));
        #elif defined(pluck)
            rc = hash(thr_id, &work, max_nonce, &hashes_done, scratchbuf, opt_pluck_n);
        #else
            rc = hash(thr_id, &work, max_nonce, &hashes_done);
        #endif

        gettimeofday(&tv_end, NULL);
        timeval_subtract(&diff, &tv_end, &tv_start);
        if (diff.tv_usec || diff.tv_sec) {
            thr_hashrate = hashes_done / (diff.tv_sec + diff.tv_usec * 1e-6);
        }

        sprintf(s, thr_hashrate >= 1e6 ? "%.0f" : "%.2f", thr_hashrate / 1e3);
        LOG("C: miner_thread: rate: %llu hashes, %s khash/s\n", hashes_done, s);

        /* if nonce found, submit work */
        if (rc){
			LOG("C: miner_thread: NOUNCE FOUND\n");
			submit_upstream_work(&work);

            //TODO was hier tun? return oder restart
			return NULL;
        }
      }

    //out: tq_freeze(mythr->q);
    out:
    return NULL;
}



int init(char *job_str, double diff){
    struct thr_info *thr;

    if (!miner_init){
#if defined(quark)
        init_quarkhash_contexts();
#elif defined(cryptonight) || defined(cryptonight)
        jsonrpc_2 = true;
        opt_extranonce = false;
        aes_ni_supported = has_aes_ni();
#elif defined(decred) || defined(sia)
        have_gbt = false;
#endif

        //INIT Main stratum stratum_ctx
        init_SCTX(&sctx);

        thr = (struct thr_info *)malloc(sizeof(thr_info));
        thr->id = 0;

        work_restart = (struct work_restart*)calloc(opt_n_threads, sizeof(*work_restart));
        if (!work_restart){
            LOG("C: init: %s\n", "could not calloc work_restart");
            return 1;
        }

/*		TODO wait for working pthreads
		int x = 0, y = 0;
		pthread_t inc_x_thread;

		if(pthread_create(&inc_x_thread, NULL, inc_x, &x)) {

			fprintf(stderr, "Error creating thread\n");
			return 1;

		}
*/
        //Damit die funktion nicht rausoptimiert wird
        //updateStats();
        //registerAddHashCallBack("getHashRate");
        //registerJobCallBack("getJob");
    }

    //LOG("C: init: new job: %s\n", job_str);
    //LOG("DIFF: %f\n", diff);
    stratum_set_difficulty(&sctx, diff);
    miner_thread(thr, job_str);
    return 0;
}




int main() {
	return 0;
    //init some Stuff
#if defined(quark)
        init_quarkhash_contexts();
#elif defined(cryptonight) || defined(cryptonight)
        jsonrpc_2 = true;
        opt_extranonce = false;
        aes_ni_supported = has_aes_ni();
#elif defined(decred) || defined(sia)
        have_gbt = false;
#endif

    //INIT Main stratum stratum_ctx
    init_SCTX(&sctx);


    struct thr_info *thr = (struct thr_info *)malloc(sizeof(thr_info));
    thr->id = 0;

    work_restart = (struct work_restart*)calloc(opt_n_threads, sizeof(*work_restart));
    if (!work_restart){
        LOG("C: %s\n", "could not calloc work_restart");
        return 1;
    }

    miner_thread(thr, "");
}
