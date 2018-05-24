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


#include "uint256.h"
#include "miner.h"
bool opt_showdiff = true;

double get_tttime()
{
  struct timeval ts;
  gettimeofday(&ts, NULL);
  return ts.tv_sec + ts.tv_usec / 1000000.0;
}


//TODO Irgendwie muss ich noch diese org funktionen her holen
char *strdup(const char *s)
{
	size_t l = strlen(s);
	char *d = malloc(l+1);
	if (!d) return NULL;
	return memcpy(d, s, l+1);
}

double uint256_getdouble(uint256 *s)
{
    double ret = 0.0;
    double fact = 1.0;
    for (int i = 0; i < 8; i++) {
        ret += fact * s->pn[i];
        fact *= 4294967296.0;
    }
    return ret;
}

// compute the diff ratio between a found hash and the target
double hash_target_ratio(uint32_t* hash, uint32_t* target)
{
	uint256 h, t;
	double dhash;

	if (!opt_showdiff)
		return 0.0;

	memcpy(&t, (void*) target, 32);
	memcpy(&h, (void*) hash, 32);

	dhash = uint256_getdouble(&h);
	if (dhash > 0.)
		return uint256_getdouble(&t) / dhash;
	else
		return dhash;

	/*org Code
	dhash = h.getdouble();
	if (dhash > 0.)
		return t.getdouble() / dhash;
	else
		return dhash;
	*/
}

void work_set_target_ratio(struct work* work, uint32_t* hash)
{
	// only if the option is enabled (to reduce cpu usage)
	if (opt_showdiff && work) {
		work->shareratio = hash_target_ratio(hash, work->target);
		work->sharediff = work->targetdiff * work->shareratio;
		if (opt_debug)
			LOG("C: share diff %.5f (%.1fx)\n", work->sharediff, work->shareratio);
	}
	return;
}
int timeval_subtract(struct timeval *result, struct timeval *x,
	struct timeval *y)
{
	/* Perform the carry for the later subtraction by updating Y. */
	if (x->tv_usec < y->tv_usec) {
		int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
		y->tv_usec -= 1000000 * nsec;
		y->tv_sec += nsec;
	}
	if (x->tv_usec - y->tv_usec > 1000000) {
		int nsec = (x->tv_usec - y->tv_usec) / 1000000;
		y->tv_usec += 1000000 * nsec;
		y->tv_sec -= nsec;
	}

	/* Compute the time remaining to wait.
	 * `tv_usec' is certainly positive. */
	result->tv_sec = x->tv_sec - y->tv_sec;
	result->tv_usec = x->tv_usec - y->tv_usec;

	/* Return 1 if result is negative. */
	return x->tv_sec < y->tv_sec;
}

/* sprintf can be used in applog */
static char* format_hash(char* buf, uint8_t *hash)
{
	int len = 0;
	for (int i=0; i < 32; i += 4) {
		len += sprintf(buf+len, "%02x%02x%02x%02x ",
			hash[i], hash[i+1], hash[i+2], hash[i+3]);
	}
	return buf;
}

void format_hashrate(double hashrate, char *output)
{
	char prefix = '\0';

	if (hashrate < 10000) {
		// nop
	}
	else if (hashrate < 1e7) {
		prefix = 'k';
		hashrate *= 1e-3;
	}
	else if (hashrate < 1e10) {
		prefix = 'M';
		hashrate *= 1e-6;
	}
	else if (hashrate < 1e13) {
		prefix = 'G';
		hashrate *= 1e-9;
	}
	else {
		prefix = 'T';
		hashrate *= 1e-12;
	}

	sprintf(
		output,
		prefix ? "%.2f %cH/s" : "%.2f H/s%c",
		hashrate, prefix
	);
}

char *abin2hex(const unsigned char *p, size_t len)
{
	unsigned char *s = (unsigned char*) malloc((len * 2) + 1);
	if (!s)
		return NULL;
	bin2hex(s, p, len);
	return (char *)s;
}


void bin2hex(unsigned char *s, const unsigned char *p, size_t len)
{
	int i;
	if (!s)
		return;

	for (i = 0; i < len; i++)
		sprintf((char *)(s + (i * 2)), "%02x", (unsigned int) p[i]);

	return;
}

bool hex2bin(unsigned char *p, const char *hexstr, size_t len)
{
	char hex_byte[3];
	char *ep;

	hex_byte[2] = '\0';

	while (*hexstr && len) {
		if (!hexstr[1]) {
			printf("hex2bin str truncated\n");
			return false;
		}
		hex_byte[0] = hexstr[0];
		hex_byte[1] = hexstr[1];
		*p = (unsigned char) strtol(hex_byte, &ep, 16);
		if (*ep) {
			printf("hex2bin failed on '%s'", hex_byte);
			return false;
		}
		p++;
		hexstr += 2;
		len--;
	}

	return(!len) ? true : false;
/*	return (len == 0 && *hexstr == 0) ? true : false; */
}


void applog_compare_hash(void *hash, void *hash_ref)
{
	char s[256] = "";
	int len = 0;
	uchar* hash1 = (uchar*)hash;
	uchar* hash2 = (uchar*)hash_ref;
	for (int i=0; i < 32; i += 4) {
		const char *color = memcmp(hash1+i, hash2+i, 4) ? CL_WHT : CL_GRY;
		len += sprintf(s+len, "%s%02x%02x%02x%02x " CL_GRY, color,
			hash1[i], hash1[i+1], hash1[i+2], hash1[i+3]);
		s[len] = '\0';
	}
	LOG("C: %s\n", s);
}

void applog_hash(void *hash)
{
	char s[128] = {'\0'};
	LOG("C: %s", format_hash(s, (uchar*) hash));
}

void applog_hex(void *data, int len)
{
	char* hex = abin2hex((uchar*)data, len);
	LOG("C: %s", hex);
	free(hex);
}

void applog_hash64(void *hash)
{
	char s[128] = {'\0'};
	char t[128] = {'\0'};
	LOG("C: %s %s\n", format_hash(s, (uchar*)hash), format_hash(t, &((uchar*)hash)[32]));
}


bool fulltest(const uint32_t *hash, const uint32_t *target)
{
	int i;
	bool rc = true;

	for (i = 7; i >= 0; i--) {
		if (hash[i] > target[i]) {
			rc = false;
			break;
		}
		if (hash[i] < target[i]) {
			rc = true;
			break;
		}
	}

	if (opt_debug) {
		uint32_t hash_be[8], target_be[8];
		unsigned char *hash_str = malloc((32 * 2) + 1);
        unsigned char *target_str = malloc((32 * 2) + 1);;

		for (i = 0; i < 8; i++) {
			be32enc(hash_be + i, hash[7 - i]);
			be32enc(target_be + i, target[7 - i]);
		}
		bin2hex(hash_str, (unsigned char *)hash_be, 32);
		bin2hex(target_str, (unsigned char *)target_be, 32);

		LOG("DEBUG: %s\nHash:   %s\nTarget: %s",
			rc ? "hash <= target\n"
			   : "hash > target (false positive)\n",
			hash_str,
			target_str);

		free(hash_str);
		free(target_str);
	}

	return rc;
}

bool has_aes_ni()
{
  return false;
}

static const char b58digits[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static bool b58dec(unsigned char *bin, size_t binsz, const char *b58)
{
	size_t i, j;
	uint64_t t;
	uint32_t c;
	uint32_t *outi;
	size_t outisz = (binsz + 3) / 4;
	int rem = binsz % 4;
	uint32_t remmask = 0xffffffff << (8 * rem);
	size_t b58sz = strlen(b58);
	bool rc = false;

	outi = (uint32_t *) calloc(outisz, sizeof(*outi));

	for (i = 0; i < b58sz; ++i) {
		for (c = 0; b58digits[c] != b58[i]; c++)
			if (!b58digits[c])
				goto out;
		for (j = outisz; j--; ) {
			t = (uint64_t)outi[j] * 58 + c;
			c = t >> 32;
			outi[j] = t & 0xffffffff;
		}
		if (c || outi[0] & remmask)
			goto out;
	}

	j = 0;
	switch (rem) {
		case 3:
			*(bin++) = (outi[0] >> 16) & 0xff;
		case 2:
			*(bin++) = (outi[0] >> 8) & 0xff;
		case 1:
			*(bin++) = outi[0] & 0xff;
			++j;
		default:
			break;
	}
	for (; j < outisz; ++j) {
		be32enc((uint32_t *)bin, outi[j]);
		bin += sizeof(uint32_t);
	}

	rc = true;
out:
	free(outi);
	return rc;
}

static int b58check(unsigned char *bin, size_t binsz, const char *b58)
{
	unsigned char buf[32];
	int i;

	sha256d(buf, bin, (int) (binsz - 4));
	if (memcmp(&bin[binsz - 4], buf, 4))
		return -1;

	/* Check number of zeros is correct AFTER verifying checksum
	 * (to avoid possibility of accessing the string beyond the end) */
	for (i = 0; bin[i] == '\0' && b58[i] == '1'; ++i);
	if (bin[i] == '\0' || b58[i] == '1')
		return -3;

	return bin[0];
}

//TODO
void diff_to_target(uint32_t *target, double diff)
{
	uint64_t m;
	int k;

	for (k = 6; k > 0 && diff > 1.0; k--)
		diff /= 4294967296.0;

	m = (uint64_t)(4294901760.0 / diff);
	if (m == 0 && k == 6)
		memset(target, 0xff, 32);
	else {
		memset(target, 0, 32);
		target[k] = (uint32_t)m;
		target[k + 1] = (uint32_t)(m >> 32);
	}
}

// Only used by stratum pools
void work_set_target(struct work* work, double diff)
{
	LOG("TODO incoming diff: %f\n", diff);
	//diff = diff/1e5; //TODO muss irgendie halt richtig angepasst werden
	diff_to_target(work->target, diff);
	work->targetdiff = diff;
	LOG("TODO SIMPLYFIED FOR CAPTCHA targetdiff: %f\n", work->targetdiff);
	LOG("TODO setzen sharediff : %f\n", work->sharediff);

	unsigned char *hash_str = malloc((32*2) +1);
	bin2hex(hash_str, (unsigned char *)work->target, 32);

	LOG("TARGET: ");
	LOG("%s", hash_str);
	LOG("\n");

	free(hash_str);
}

// Only used by longpoll pools
double target_to_diff(uint32_t* target)
{
	uchar* tgt = (uchar*) target;
	uint64_t m =
		(uint64_t)tgt[29] << 56 |
		(uint64_t)tgt[28] << 48 |
		(uint64_t)tgt[27] << 40 |
		(uint64_t)tgt[26] << 32 |
		(uint64_t)tgt[25] << 24 |
		(uint64_t)tgt[24] << 16 |
		(uint64_t)tgt[23] << 8  |
		(uint64_t)tgt[22] << 0;

	if (!m)
		return 0.;
	else
		return (double)0x0000ffff00000000/m;
}

/**
 * Extract bloc height     L H... here len=3, height=0x1333e8
 * "...0000000000ffffffff2703e83313062f503253482f043d61105408"
 */
static uint32_t getblocheight(struct stratum_ctx *sctx)
{
	uint32_t height = 0;
	uint8_t hlen = 0, *p, *m;

	// find 0xffff tag
	p = (uint8_t*) sctx->job.coinbase + 32;
	m = p + 128;
	while (*p != 0xff && p < m) p++;
	while (*p == 0xff && p < m) p++;
	if (*(p-1) == 0xff && *(p-2) == 0xff) {
		p++; hlen = *p;
		p++; height = le16dec(p);
		p += 2;
		switch (hlen) {
			case 4:
				height += 0x10000UL * le16dec(p);
				break;
			case 3:
				height += 0x10000UL * (*p);
				break;
		}
	}
	return height;
}

bool stratum_set_difficulty(struct stratum_ctx *sctx, double diff)
{
	//double diff;

	//diff = json_number_value(json_array_get(params, 0));
	if (diff == 0){
		LOG("C: stratum_set_difficulty: ERROR diff=0\n");
		return false;
	}

	//pthread_mutex_lock(&sctx->work_lock);
	//LOG("C: stratum_set_difficulty: TODO DIFF =%f\n", diff/1000);
	sctx->next_diff = diff;
	//pthread_mutex_unlock(&sctx->work_lock);

	return true;
}

bool stratum_notify(struct stratum_ctx *sctx, json_t *params)
{
	const char *job_id, *prevhash, *coinb1, *coinb2, *version, *nbits, *ntime;
	const char *claim = NULL;
	size_t coinb1_size, coinb2_size;
	bool clean, ret = false;
	int merkle_count, i, p=0;
	bool has_claim = json_array_size(params) == 10; // todo: use opt_algo
	json_t *merkle_arr;
	uchar **merkle;

	job_id = json_string_value(json_array_get(params, p++));
	prevhash = json_string_value(json_array_get(params, p++));
	if (has_claim) {
		claim = json_string_value(json_array_get(params, p++));
		if (!claim || strlen(claim) != 64) {
			LOG("C: Stratum notify: invalid claim parameter\n");
			goto out;
		}
	}
	coinb1 = json_string_value(json_array_get(params, p++));
	coinb2 = json_string_value(json_array_get(params, p++));
	merkle_arr = json_array_get(params, p++);
	if (!merkle_arr || !json_is_array(merkle_arr))
		goto out;

	merkle_count = (int) json_array_size(merkle_arr);
	version = json_string_value(json_array_get(params, p++));
	nbits = json_string_value(json_array_get(params, p++));
	ntime = json_string_value(json_array_get(params, p++));
	clean = json_is_true(json_array_get(params, p));

	if (!job_id || !prevhash || !coinb1 || !coinb2 || !version || !nbits || !ntime){
		LOG("C: Stratum notify: invalid parameters\n");
		goto out;
	}
	if (strlen(prevhash) != 64){
		LOG("C: Stratum notify: invalid prevhash\n");
		goto out;
	}
	if (strlen(version) != 8){
		LOG("C: Stratum notify: invalid version\n");
		goto out;
	}
	if (strlen(nbits) != 8){
		LOG("C: Stratum notify: invalid nbits\n");
		goto out;
	}
	if (strlen(ntime) != 8){
		LOG("C: Stratum notify: invalid ntime\n");
		goto out;
	}

	merkle = (uchar**) malloc(merkle_count * sizeof(char *));
	for (i = 0; i < merkle_count; i++) {
		const char *s = json_string_value(json_array_get(merkle_arr, i));
		if (!s || strlen(s) != 64) {
			while (i--)
				free(merkle[i]);
			free(merkle);
			LOG("C: Stratum notify: invalid Merkle branch\n");
			goto out;
		}
		merkle[i] = (uchar*) malloc(32);
		hex2bin(merkle[i], s, 32);
	}

	//pthread_mutex_lock(&sctx->work_lock);

	coinb1_size = strlen(coinb1) / 2;
	coinb2_size = strlen(coinb2) / 2;
	sctx->job.coinbase_size = coinb1_size + sctx->xnonce1_size +
	                          sctx->xnonce2_size + coinb2_size;
	sctx->job.coinbase = (uchar*) realloc(sctx->job.coinbase, sctx->job.coinbase_size);
	sctx->job.xnonce2 = sctx->job.coinbase + coinb1_size + sctx->xnonce1_size;
	hex2bin(sctx->job.coinbase, coinb1, coinb1_size);
	memcpy(sctx->job.coinbase + coinb1_size, sctx->xnonce1, sctx->xnonce1_size);
	if (!sctx->job.job_id || strcmp(sctx->job.job_id, job_id))
		memset(sctx->job.xnonce2, 0, sctx->xnonce2_size);

	hex2bin(sctx->job.xnonce2 + sctx->xnonce2_size, coinb2, coinb2_size);

	free(sctx->job.job_id);
	sctx->job.job_id = strdup(job_id);
	hex2bin(sctx->job.prevhash, prevhash, 32);

	if (has_claim) hex2bin(sctx->job.claim, claim, 32);

	sctx->bloc_height = getblocheight(sctx);

	for (i = 0; i < sctx->job.merkle_count; i++)
		free(sctx->job.merkle[i]);
	free(sctx->job.merkle);
	sctx->job.merkle = merkle;
	sctx->job.merkle_count = merkle_count;

	hex2bin(sctx->job.version, version, 4);
	hex2bin(sctx->job.nbits, nbits, 4);
	hex2bin(sctx->job.ntime, ntime, 4);
	sctx->job.clean = clean;

	sctx->job.diff = sctx->next_diff;

	LOG("JOB:\n");
	LOG("diff: 			%f\n", sctx->job.diff);
	LOG("job_id: 		%s\n", job_id);
	LOG("prevhash: 		%s\n", prevhash);
	LOG("coinb1: 		%s\n", coinb1);
	LOG("coinb2: 		%s\n", coinb2);
	LOG("CoinBase: 		%s\n", sctx->job.coinbase);
	LOG("xnonce2_size: 	%u\n", sctx->xnonce2_size);
	LOG("xcnonce2: 		%s\n", sctx->job.xnonce2);
	LOG("merkle_count: 	%d\n", sctx->job.merkle_count);
	LOG("version: 		%s\n", version); //->version not working, because its in bin.
	LOG("nbits: 			%s\n", nbits);
	LOG("ntime: 			%s\n", ntime);
	LOG("clean: 			%d\n", sctx->job.clean);

	//pthread_mutex_unlock(&sctx->work_lock);
	ret = true;

out:
	return ret;
}
