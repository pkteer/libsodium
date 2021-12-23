
#include "poly1305_avx2.h"
#include "crypto_verify_16.h"
#include "private/common.h"
#include "utils.h"
#include <string.h>

#include "../onetimeauth_poly1305.h"

typedef struct poly1305_state_internal_t {
	unsigned char opaque[192]; /* largest state required (AVX2) */
	size_t leftover, block_size;
	unsigned char buffer[64]; /* largest blocksize (AVX2) */
} poly1305_state_internal;

typedef struct poly1305_key {
	unsigned char b[32];
} poly1305_key;

/* functions implemented in assembly */
size_t poly1305_block_size_avx2(void);
void poly1305_init_ext_avx2(void *state, const poly1305_key *key, size_t bytes_hint);
void poly1305_blocks_avx2(void *state, const unsigned char *in, size_t inlen);
void poly1305_finish_ext_avx2(void *state, const unsigned char *in, size_t remaining, unsigned char *mac);
void poly1305_auth_avx2(unsigned char *mac, const unsigned char *m, size_t inlen, const poly1305_key *key);

/* helper functions */
/* is the pointer aligned on a word boundary? */
static int
poly1305_is_aligned(const void *p) {
	return ((size_t)p & (sizeof(size_t) - 1)) == 0;
}

/* processes inlen bytes (full blocks only), handling input alignment */
static void
poly1305_consume(poly1305_state_internal *state, const unsigned char *in, size_t inlen) {
	int in_aligned;

	/* it's ok to call with 0 bytes */
	if (!inlen)
		return;

	/* if everything is aligned, handle directly */
	in_aligned = poly1305_is_aligned(in);
	if (in_aligned) {
		poly1305_blocks_avx2(state->opaque, in, inlen);
		return;
	}

	/* copy the unaligned data to an aligned buffer and process in chunks */
	while (inlen) {
		unsigned char buffer[1024];
		const size_t bytes = (inlen > sizeof(buffer)) ? sizeof(buffer) : inlen;
		memcpy(buffer, in, bytes);
		poly1305_blocks_avx2(state->opaque, buffer, bytes);
		in += bytes;
		inlen -= bytes;
	}
}

/* poly1305 impl */
static int
crypto_onetimeauth_poly1305_avx2(unsigned char *out, const unsigned char *m,
                                  unsigned long long   inlen,
                                  const unsigned char *key)
{
    poly1305_auth_avx2(out, m, inlen, key);

    return 0;
}

static int
crypto_onetimeauth_poly1305_avx2_init(crypto_onetimeauth_poly1305_state *state,
                                       const unsigned char *key)
{
    COMPILER_ASSERT(sizeof(crypto_onetimeauth_poly1305_state) >=
                    sizeof(poly1305_state_internal));
    poly1305_init_ext_avx2(state, key, 0);
    poly1305_state_internal* st_internal = (poly1305_state_internal*) state;
	st_internal->leftover = 0;
	st_internal->block_size = poly1305_block_size_avx2();

    return 0;
}

static int
crypto_onetimeauth_poly1305_avx2_update(
    crypto_onetimeauth_poly1305_state *S, const unsigned char *in,
    unsigned long long inlen)
{
	poly1305_state_internal *state = (poly1305_state_internal *)S;

	/* handle leftover */
	if (state->leftover) {
		size_t want = (state->block_size - state->leftover);
		if (want > inlen)
			want = inlen;
		memcpy(state->buffer + state->leftover, in, want);
		inlen -= want;
		in += want;
		state->leftover += want;
		if (state->leftover < state->block_size)
			return 0;
		poly1305_blocks_avx2(state->opaque, state->buffer, state->block_size);
		state->leftover = 0;
	}

	/* process full blocks */
	if (inlen >= state->block_size) {
		size_t want = (inlen & ~(state->block_size - 1));
		poly1305_consume(state, in, want);
		in += want;
		inlen -= want;
	}

	/* store leftover */
	if (inlen) {
		memcpy(state->buffer + state->leftover, in, inlen);
		state->leftover += inlen;
	}

    return 0;
}

static int
crypto_onetimeauth_poly1305_avx2_final(
    crypto_onetimeauth_poly1305_state *S, unsigned char *out)
{
	poly1305_state_internal *state = (poly1305_state_internal *)S;
	poly1305_finish_ext_avx2(state->opaque, state->buffer, state->leftover, out);

    return 0;
}

static int
crypto_onetimeauth_poly1305_avx2_verify(const unsigned char *h,
                                         const unsigned char *in,
                                         unsigned long long   inlen,
                                         const unsigned char *k)
{
    unsigned char correct[16];

    crypto_onetimeauth_poly1305_avx2(correct, in, inlen, k);

    return crypto_verify_16(h, correct);
}

struct crypto_onetimeauth_poly1305_implementation
    crypto_onetimeauth_poly1305_avx2_implementation = {
        SODIUM_C99(.onetimeauth =) crypto_onetimeauth_poly1305_avx2,
        SODIUM_C99(.onetimeauth_verify =)
            crypto_onetimeauth_poly1305_avx2_verify,
        SODIUM_C99(.onetimeauth_init =) crypto_onetimeauth_poly1305_avx2_init,
        SODIUM_C99(.onetimeauth_update =)
            crypto_onetimeauth_poly1305_avx2_update,
        SODIUM_C99(.onetimeauth_final =) crypto_onetimeauth_poly1305_avx2_final
    };
