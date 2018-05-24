#ifndef __MINER_H__
#define __MINER_H__

#include <cpuminer-config.h>



//LOG MACRO
#ifdef DEBUG
#define LOG(message, args...)           printf(message, ## args);
#else
#define LOG(message, args...)
#endif

#define USER_AGENT PACKAGE_NAME "/" PACKAGE_VERSION
#define MAX_CPUS 16

#undef USE_ASM  /* to fix */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include <sys/time.h>
#include <alloca.h>

#include "compat.h"
#include <jansson.h>

#include "sha3/sph_shabal.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

static inline bool is_windows(void) {
#ifdef WIN32
	return 1;
#else
	return 0;
#endif
}

#if ((__GNUC__ > 4) || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3))
#define WANT_BUILTIN_BSWAP
#else
#define bswap_32(x) ((((x) << 24) & 0xff000000u) | (((x) << 8) & 0x00ff0000u) \
                   | (((x) >> 8) & 0x0000ff00u) | (((x) >> 24) & 0x000000ffu))
#endif

static inline uint32_t swab32(uint32_t v)
{
#ifdef WANT_BUILTIN_BSWAP
	return __builtin_bswap32(v);
#else
	return bswap_32(v);
#endif
}

#ifdef HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif

typedef unsigned char uchar;

#if !HAVE_DECL_BE32DEC
static inline uint32_t be32dec(const void *pp)
{
	const uint8_t *p = (uint8_t const *)pp;
	return ((uint32_t)(p[3]) + ((uint32_t)(p[2]) << 8) +
	    ((uint32_t)(p[1]) << 16) + ((uint32_t)(p[0]) << 24));
}
#endif

#if !HAVE_DECL_LE32DEC
static inline uint32_t le32dec(const void *pp)
{
	const uint8_t *p = (uint8_t const *)pp;
	return ((uint32_t)(p[0]) + ((uint32_t)(p[1]) << 8) +
	    ((uint32_t)(p[2]) << 16) + ((uint32_t)(p[3]) << 24));
}
#endif

#if !HAVE_DECL_BE32ENC
static inline void be32enc(void *pp, uint32_t x)
{
	uint8_t *p = (uint8_t *)pp;
	p[3] = x & 0xff;
	p[2] = (x >> 8) & 0xff;
	p[1] = (x >> 16) & 0xff;
	p[0] = (x >> 24) & 0xff;
}
#endif

#if !HAVE_DECL_LE32ENC
static inline void le32enc(void *pp, uint32_t x)
{
	uint8_t *p = (uint8_t *)pp;
	p[0] = x & 0xff;
	p[1] = (x >> 8) & 0xff;
	p[2] = (x >> 16) & 0xff;
	p[3] = (x >> 24) & 0xff;
}
#endif

#if !HAVE_DECL_LE16DEC
static inline uint16_t le16dec(const void *pp)
{
	const uint8_t *p = (uint8_t const *)pp;
	return ((uint16_t)(p[0]) + ((uint16_t)(p[1]) << 8));
}
#endif

#if !HAVE_DECL_LE16ENC
static inline void le16enc(void *pp, uint16_t x)
{
	uint8_t *p = (uint8_t *)pp;
	p[0] = x & 0xff;
	p[1] = (x >> 8) & 0xff;
}
#endif


#if JANSSON_MAJOR_VERSION >= 2
#define JSON_LOADS(str, err_ptr) json_loads(str, 0, err_ptr)
#define JSON_LOADF(path, err_ptr) json_load_file(path, 0, err_ptr)
#else
#define JSON_LOADS(str, err_ptr) json_loads(str, err_ptr)
#define JSON_LOADF(path, err_ptr) json_load_file(path, err_ptr)
#endif

json_t* json_load_url(char* cfg_url, json_error_t *err);


void sha256_init(uint32_t *state);
void sha256_transform(uint32_t *state, const uint32_t *block, int swap);
void sha256d(unsigned char *hash, const unsigned char *data, int len);

struct work;
int scanhash_ethash(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_equihash(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_axiom(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_bastion(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_blake(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_blakecoin(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_blake2s(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_bmw(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_cryptolight(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_cryptonight(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_c11(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_decred(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_drop(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_fresh(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_groestl(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_heavy(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_ink(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_keccak(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_jha(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_lbry(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_luffa(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_lyra2(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_lyra2rev2(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_myriad(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_neoscrypt(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done, uint32_t profile);
int scanhash_nist5(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_pentablake(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_pluck(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done,
					unsigned char *scratchbuf, int N);
int scanhash_quark(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
void init_quarkhash_contexts();
int scanhash_qubit(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_sha256d(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
unsigned char *scrypt_buffer_alloc(int N);
int scanhash_scrypt(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done,
					unsigned char *scratchbuf, uint32_t N);
int scanhash_scryptjane(int Nfactor, int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_sia(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_sib(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_skein(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_skein2(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_s3(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_timetravel(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_bitcore(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_tribus(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_veltor(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_x11evo(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_x11(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_x13(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_x14(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_x15(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_x16r(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_x17(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_xevan(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_yescrypt(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_zr5(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);

/* api related */
void *api_thread(void *userdata);

struct cpu_info {
	int thr_id;
	int accepted;
	int rejected;
	double khashes;
	bool has_monitoring;
	float cpu_temp;
	int cpu_fan;
	uint32_t cpu_clock;
};

struct thr_api {
	int id;
	//pthread_t pth;
	struct thread_q	*q;
};
/* end of api */

struct thr_info {
	int id;
	//pthread_t pth;
	//pthread_attr_t attr;
	struct thread_q	*q;
	struct cpu_info cpu;
};

struct work_restart {
	volatile uint8_t restart;
	char padding[128 - sizeof(uint8_t)];
};


extern const bool opt_debug;
extern const bool opt_benchmark;
extern bool opt_showdiff;
extern bool opt_protocol;
extern bool opt_redirect;
extern int opt_priority;
extern int opt_timeout;
extern bool want_longpoll;
extern bool have_longpoll;
extern bool have_gbt;
extern bool allow_getwork;
extern bool want_stratum;
extern bool have_stratum;
extern const bool opt_stratum_stats;
extern char *opt_cert;
extern char *opt_proxy;
extern long opt_proxy_type;
extern bool use_syslog;
extern bool use_colors;
//extern pthread_mutex_t applog_lock;
extern struct thr_info *thr_info;
extern int longpoll_thr_id;
extern int stratum_thr_id;
extern int api_thr_id;
extern const int opt_n_threads;
extern int num_cpus;
extern struct work_restart *work_restart;
extern uint32_t opt_work_size;
extern double *thr_hashrates;
extern uint64_t global_hashrate;
extern double stratum_diff;
extern double net_diff;
extern double net_hashrate;

#define JSON_RPC_LONGPOLL	(1 << 0)
#define JSON_RPC_QUIET_404	(1 << 1)
#define JSON_RPC_IGNOREERR  (1 << 2)

#define JSON_BUF_LEN 512

#define CL_N    "\x1B[0m"
#define CL_RED  "\x1B[31m"
#define CL_GRN  "\x1B[32m"
#define CL_YLW  "\x1B[33m"
#define CL_BLU  "\x1B[34m"
#define CL_MAG  "\x1B[35m"
#define CL_CYN  "\x1B[36m"

#define CL_BLK  "\x1B[22;30m" /* black */
#define CL_RD2  "\x1B[22;31m" /* red */
#define CL_GR2  "\x1B[22;32m" /* green */
#define CL_BRW  "\x1B[22;33m" /* brown */
#define CL_BL2  "\x1B[22;34m" /* blue */
#define CL_MA2  "\x1B[22;35m" /* magenta */
#define CL_CY2  "\x1B[22;36m" /* cyan */
#define CL_SIL  "\x1B[22;37m" /* gray */

#ifdef WIN32
#define CL_GRY  "\x1B[01;30m" /* dark gray */
#else
#define CL_GRY  "\x1B[90m"    /* dark gray selectable in putty */
#endif
#define CL_LRD  "\x1B[01;31m" /* light red */
#define CL_LGR  "\x1B[01;32m" /* light green */
#define CL_YL2  "\x1B[01;33m" /* yellow */
#define CL_LBL  "\x1B[01;34m" /* light blue */
#define CL_LMA  "\x1B[01;35m" /* light magenta */
#define CL_LCY  "\x1B[01;36m" /* light cyan */

#define CL_WHT  "\x1B[01;37m" /* white */

char *strdup(const char *s);
void format_hashrate(double hashrate, char *output);


void applog(int prio, const char *fmt, ...);
void restart_threads(void);
//extern json_t *json_rpc_call(CURL *curl, const char *url, const char *userpass,
//	const char *rpc_req, int *curl_err, int flags);
void bin2hex(unsigned char *s, const unsigned char *p, size_t len);
char *abin2hex(const unsigned char *p, size_t len);
bool hex2bin(unsigned char *p, const char *hexstr, size_t len);
//bool jobj_binary(const json_t *obj, const char *key, void *buf, size_t buflen);
int varint_encode(unsigned char *p, uint64_t n);
size_t address_to_script(unsigned char *out, size_t outsz, const char *addr);
int timeval_subtract(struct timeval *result, struct timeval *x, struct timeval *y);
bool fulltest(const uint32_t *hash, const uint32_t *target);
void work_set_target(struct work* work, double diff);
double target_to_diff(uint32_t* target);

double hash_target_ratio(uint32_t* hash, uint32_t* target);
void work_set_target_ratio(struct work* work, uint32_t* hash);

void get_currentalgo(char* buf, int sz);
bool has_aes_ni(void);
void cpu_bestfeature(char *outbuf, size_t maxsz);
void cpu_getname(char *outbuf, size_t maxsz);
void cpu_getmodelid(char *outbuf, size_t maxsz);
float cpu_temp(int core);


void applog_compare_hash(void *hash, void *hash_ref);
void applog_hex(void *data, int len);
void applog_hash(void *hash);
void applog_hash64(void *hash);
void format_hashrate(double hashrate, char *output);
void print_hash_tests(void);


struct work {
	uint32_t data[48];
	uint32_t target[8];

	double targetdiff;
	double shareratio;
	double sharediff;
	uint32_t resnonce;

	int height;
	char *txs;
	char *workid;

	char *job_id;
	size_t xnonce2_len;
	unsigned char *xnonce2;
};

struct stratum_job {
	char *job_id;
	unsigned char prevhash[32];
	size_t coinbase_size;
	unsigned char *coinbase;
	unsigned char *xnonce2;
	int merkle_count;
	unsigned char **merkle;
	unsigned char version[4];
	unsigned char nbits[4];
	unsigned char ntime[4];
	unsigned char claim[32]; // lbry
	bool clean;
	double diff;
};

struct stratum_ctx {
	char *url;

	//CURL *curl;
	char *curl_url;
	//char curl_err_str[CURL_ERROR_SIZE];
	//curl_socket_t sock;
	size_t sockbuf_size;
	char *sockbuf;
	//pthread_mutex_t sock_lock;

	double next_diff;
	double sharediff;

	char *session_id;
	size_t xnonce1_size;
	unsigned char *xnonce1;
	size_t xnonce2_size;
	struct stratum_job job;
	struct work work;
	//pthread_mutex_t work_lock;

	int bloc_height;
};

bool stratum_socket_full(struct stratum_ctx *sctx, int timeout);
bool stratum_send_line(struct stratum_ctx *sctx, char *s);
char *stratum_recv_line(struct stratum_ctx *sctx);
bool stratum_connect(struct stratum_ctx *sctx, const char *url);
void stratum_disconnect(struct stratum_ctx *sctx);
bool stratum_subscribe(struct stratum_ctx *sctx);
bool stratum_authorize(struct stratum_ctx *sctx, const char *user, const char *pass);
bool stratum_handle_method(struct stratum_ctx *sctx, const char *s);
bool stratum_notify(struct stratum_ctx *sctx, json_t *params);
/* rpc 2.0 (xmr) */
extern bool jsonrpc_2;
extern bool aes_ni_supported;
extern char rpc2_id[64];
extern char *rpc2_blob;
extern size_t rpc2_bloblen;
extern uint32_t rpc2_target;
extern char *rpc2_job_id;

struct thread_q;

void sha256d(unsigned char *hash, const unsigned char *data, int len);
void axiomhash(void *state, const void *input);
void bastionhash(void *output, const void *input);
void blakehash(void *state, const void *input);
void blakecoinhash(void *state, const void *input);
void blake2s_hash(void *output, const void *input);
void blake2b_hash(void *output, const void *input);
void bmwhash(void *output, const void *input);
void c11hash(void *output, const void *input);
void cryptolight_hash(void* output, const void* input, int len);
void cryptonight_hash(void* output, const void* input, int len);
void decred_hash(void *output, const void *input);
void droplp_hash(void *output, const void *input);
void groestlhash(void *output, const void *input);
void heavyhash(unsigned char* output, const unsigned char* input, int len);
void quarkhash(void *state, const void *input);
void freshhash(void* output, const void* input, uint32_t len);
void keccakhash(void *state, const void *input);
void inkhash(void *state, const void *input); /* shavite */
void jha_hash(void *output, const void *input);
void lbry_hash(void *output, const void *input);
void luffahash(void *output, const void *input);
void lyra2_hash(void *state, const void *input);
void lyra2rev2_hash(void *state, const void *input);
void myriadhash(void *output, const void *input);
void neoscrypthash(unsigned char *output, const unsigned char *password, uint32_t profile);
void nist5hash(void *output, const void *input);
void pluck_hash(uint32_t *hash, const uint32_t *data, uchar *hashbuffer, const int N);
void pentablakehash(void *output, const void *input);
void qubithash(void *output, const void *input);
void scrypthash(void *output, const void *input, uint32_t N);
void scryptjanehash(void *output, const void *input, uint32_t Nfactor);
void sibhash(void *output, const void *input);
void skeinhash(void *state, const void *input);
void skein2hash(void *state, const void *input);
void s3hash(void *output, const void *input);
void timetravel_hash(void *output, const void *input);
void bitcore_hash(void *output, const void *input);
void tribus_hash(void *output, const void *input);
void veltor_hash(void *output, const void *input);
void xevan_hash(void *output, const void *input);
void x11evo_hash(void *output, const void *input);
void x11hash(void *output, const void *input);
void x13hash(void *output, const void *input);
void x14hash(void *output, const void *input);
void x15hash(void *output, const void *input);
void x16r_hash(void *output, const void *input);
void x17hash(void *output, const void *input);
void zr5hash(void *output, const void *input);
void yescrypthash(void *output, const void *input);
void zr5hash_pok(void *output, uint32_t *pdata);


//Some helpers To compiled
uint32_t htonl(uint32_t x);
bool stratum_gen_work(struct stratum_ctx *sctx, struct work *work);
bool stratum_set_difficulty(struct stratum_ctx *sctx, double diff);
double get_tttime();


#define likely(x)      __builtin_expect(!!(x), 1)
#define unlikely(x)    __builtin_expect(!!(x), 0)
#define _ALIGN(x) __attribute__ ((aligned(x)))

#define LP_SCANTIME		10 //TODO find right time, maybe of each algo diffrent?

#ifdef ethash
#define PROGRAM_NAME		"ethash_miner"
#define hash scanhash_ethash //TODO
#endif
#ifdef equihash
#define PROGRAM_NAME		"equihash_miner"
#define hash scanhash_equihash //TODO
#endif
#ifdef xevan
#define PROGRAM_NAME		"xevan_miner"
#define hash scanhash_xevan
#endif
#ifdef neoscrypt
#define PROGRAM_NAME		"neoscrypt_miner"
#define hash scanhash_neoscrypt
#endif
#ifdef axiom
#define PROGRAM_NAME		"axiom_miner"
#define hash scanhash_axiom
#endif
#ifdef bastion
#define PROGRAM_NAME		"bastion_miner"
#define hash scanhash_bastion
#endif
#ifdef blakecoin
#define PROGRAM_NAME		"blakecoin_miner"
#define hash scanhash_blakecoin
#endif
#ifdef blake2s
#define PROGRAM_NAME		"blake2s_miner"
#define hash scanhash_blake2s
#endif
#ifdef bmw
#define PROGRAM_NAME		"bmw_miner"
#define hash scanhash_bmw
#endif
#ifdef c11
#define PROGRAM_NAME		"c11_miner"
#define hash scanhash_c11
#endif
#ifdef cryptolight
#define PROGRAM_NAME		"cryptolight_miner"
#define hash scanhash_cryptolight
#endif
#ifdef decred
#define PROGRAM_NAME		"decred_miner"
#define hash scanhash_decred
#endif
#ifdef dmdgr //TODO I thinks thats right.
#define PROGRAM_NAME		"dmdgr_miner"
#define hash scanhash_groestl
#endif
#ifdef drop
#define PROGRAM_NAME		"drop_miner"
#define hash scanhash_drop
#endif
#ifdef x11evo
#define PROGRAM_NAME		"x11evo_miner"
#define hash scanhash_x11evo
#endif
#ifdef groestl
#define PROGRAM_NAME		"groestl_miner"
#define hash scanhash_groestl
#endif
#ifdef jha
#define PROGRAM_NAME		"jha_miner"
#define hash scanhash_jha
#endif
#ifdef lbry
#define PROGRAM_NAME		"lbry_miner"
#define hash scanhash_lbry
#endif
#ifdef luffa
#define PROGRAM_NAME		"luffa_miner"
#define hash scanhash_luffa
#endif
#ifdef lyra2re
#define PROGRAM_NAME		"lyra2re_miner"
#define hash scanhash_lyra2 //TODO XXX Rihtig? //oder scanhash_lyra2re ?
#endif
#ifdef lyra2rev2
#define PROGRAM_NAME		"lyra2rev2_miner"
#define hash scanhash_lyra2rev2
#endif
#ifdef myrgr
#define PROGRAM_NAME		"myrgr_miner"
#define hash scanhash_myriad
#endif
#ifdef nist5
#define PROGRAM_NAME		"nist5_miner"
#define hash scanhash_nist5
#endif
#ifdef pentablake
#define PROGRAM_NAME		"pentablake_miner"
#define hash scanhash_pentablake
#endif
#ifdef pluck
#define PROGRAM_NAME		"pluck_miner"
#define hash scanhash_pluck
#endif
#ifdef qubit
#define PROGRAM_NAME		"qubit_miner"
#define hash scanhash_qubit
#endif
#ifdef scryptjane
#define PROGRAM_NAME		"scryptjane_miner"
#define hash scanhash_scryptjane
#endif
#ifdef shavite3 //ist das gleiche wie ink
#define PROGRAM_NAME		"shavite3_miner"
#define hash scanhash_ink
#endif
#ifdef sia
#define PROGRAM_NAME		"sia_miner"
#define hash scanhash_sia
#endif
#ifdef sib
#define PROGRAM_NAME		"sib_miner"
#define hash scanhash_sib
#endif
#ifdef skein2
#define PROGRAM_NAME		"skein2_miner"
#define hash scanhash_skein2
#endif
#ifdef s3
#define PROGRAM_NAME		"s3_miner"
#define hash scanhash_s3
#endif
#ifdef timetravel
#define PROGRAM_NAME		"timetravel_miner"
#define hash scanhash_timetravel
#endif
#ifdef bitcore
#define PROGRAM_NAME		"bitcore_miner"
#define hash scanhash_bitcore
#endif
#ifdef tribus
#define PROGRAM_NAME		"tribus_miner"
#define hash scanhash_tribus
#endif
#ifdef vanilla
#define PROGRAM_NAME		"vanilla_miner"
#define hash scanhash_blakecoin
#endif
#ifdef veltor
#define PROGRAM_NAME		"veltor_miner"
#define hash scanhash_veltor
#endif
#ifdef xevon
#define PROGRAM_NAME		"xevon_miner"
#define hash scanhash_xevor
#endif
#ifdef yescrypt
#define PROGRAM_NAME		"yescrypt_miner"
#define hash scanhash_yescrypt
#endif
#ifdef zr5
#define PROGRAM_NAME		"zr5_miner"
#define hash scanhash_zr5
#endif

#ifdef scrypt
#define PROGRAM_NAME		"scrypt_miner"
#define hash scanhash_scrypt
#endif

#ifdef sha256d_
#define PROGRAM_NAME		"sha256d_miner"
#define hash scanhash_sha256d
#endif

#ifdef keccak
#define PROGRAM_NAME		"keccak_miner"
#define hash scanhash_keccak
#endif

#ifdef heavy
#define PROGRAM_NAME		"heavy_miner"
#define hash scanhash_heavy
#endif

#ifdef quark
#define PROGRAM_NAME		"quark_miner"
#define hash scanhash_quark
#endif

#ifdef skein
#define PROGRAM_NAME		"skein_miner"
#define hash scanhash_skein
#endif

#ifdef ink
#define PROGRAM_NAME		"ink_miner"
#define hash scanhash_ink
#endif

#ifdef blake
#define PROGRAM_NAME		"blake_miner"
#define hash scanhash_blake
#endif

#ifdef fresh
#define PROGRAM_NAME		"fresh_miner"
#define hash scanhash_fresh
#endif

#ifdef x11
#define PROGRAM_NAME		"x11_miner"
#define hash scanhash_x11
#endif

#ifdef x13
#define PROGRAM_NAME		"x13_miner"
#define hash scanhash_x13
#endif

#ifdef x14
#define PROGRAM_NAME		"x14_miner"
#define hash scanhash_x14
#endif

#ifdef x15
#define PROGRAM_NAME		"x15_miner"
#define hash scanhash_x15
#endif

#ifdef x16r
#define PROGRAM_NAME		"x16r_miner"
#define hash scanhash_x16r
#endif

#ifdef x17
#define PROGRAM_NAME		"x17_miner"
#define hash scanhash_x17
#endif

#ifdef cryptonight
#define PROGRAM_NAME		"cryptonight_miner"
#define hash scanhash_cryptonight
#endif


#endif /* __MINER_H__ */
