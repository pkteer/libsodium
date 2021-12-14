
#include "poly1305_avx2.h"
#include "crypto_verify_16.h"
#include "private/common.h"
#include "utils.h"

#include "../onetimeauth_poly1305.h"

typedef struct poly1305_state_internal_t {
	unsigned char opaque[192]; /* largest state required (AVX2) */
	size_t leftover, block_size;
	unsigned char buffer[64]; /* largest blocksize (AVX2) */
} poly1305_state_internal;

/* functions implemented in assembly */
size_t poly1305_block_size_avx2(void);
void poly1305_init_ext_avx2(void *state, const poly1305_key *key, size_t bytes_hint);
void poly1305_blocks_avx2(void *state, const unsigned char *in, size_t inlen);
void poly1305_finish_ext_avx2(void *state, const unsigned char *in, size_t remaining, unsigned char *mac);
void poly1305_auth_avx2(unsigned char *mac, const unsigned char *m, size_t inlen, const poly1305_key *key);

static void
poly1305_update(poly1305_state_internal_t *st, const unsigned char *m,
                unsigned long long bytes)
{
    unsigned long long i;

    /* handle leftover */
    if (st->leftover) {
        unsigned long long want = (poly1305_block_size - st->leftover);

        if (want > bytes) {
            want = bytes;
        }
        for (i = 0; i < want; i++) {
            st->buffer[st->leftover + i] = m[i];
        }
        bytes -= want;
        m += want;
        st->leftover += want;
        if (st->leftover < poly1305_block_size) {
            return;
        }
        poly1305_blocks(st, st->buffer, poly1305_block_size);
        st->leftover = 0;
    }

    /* process full blocks */
    if (bytes >= poly1305_block_size) {
        unsigned long long want = (bytes & ~(poly1305_block_size - 1));

        poly1305_blocks(st, m, want);
        m += want;
        bytes -= want;
    }

    /* store leftover */
    if (bytes) {
        for (i = 0; i < bytes; i++) {
            st->buffer[st->leftover + i] = m[i];
        }
        st->leftover += bytes;
    }
}

static int
crypto_onetimeauth_poly1305_avx2(unsigned char *out, const unsigned char *m,
                                  unsigned long long   inlen,
                                  const unsigned char *key)
{
    CRYPTO_ALIGN(64) poly1305_state_internal_t state;

    poly1305_init(&state, key);
    poly1305_update(&state, m, inlen);
    poly1305_finish(&state, out);

    return 0;
}

static int
crypto_onetimeauth_poly1305_avx2_init(crypto_onetimeauth_poly1305_state *state,
                                       const unsigned char *key)
{
    COMPILER_ASSERT(sizeof(crypto_onetimeauth_poly1305_state) >=
        sizeof(poly1305_state_internal_t));
    poly1305_init((poly1305_state_internal_t *) (void *) state, key);

    return 0;
}

static int
crypto_onetimeauth_poly1305_avx2_update(
    crypto_onetimeauth_poly1305_state *state, const unsigned char *in,
    unsigned long long inlen)
{
    poly1305_update((poly1305_state_internal_t *) (void *) state, in, inlen);

    return 0;
}

static int
crypto_onetimeauth_poly1305_avx2_final(
    crypto_onetimeauth_poly1305_state *state, unsigned char *out)
{
    poly1305_finish((poly1305_state_internal_t *) (void *) state, out);

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
