#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "blake2.h"
#include "blake2-impl.h"

static const uint32_t blake2s_IV[8] = {
  UINT32_C(0x6A09E667), UINT32_C(0xBB67AE85),
  UINT32_C(0x3C6EF372), UINT32_C(0xA54FF53A),
  UINT32_C(0x510E527F), UINT32_C(0x9B05688C),
  UINT32_C(0x1F83D9AB), UINT32_C(0x5BE0CD19)
};

static const unsigned int blake2s_sigma[10][16] = {
  {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
  {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
  {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
  {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
  {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
  {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
  {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
  {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
  {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
  {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
};

static BLAKE2_INLINE void
blake2s_set_lastnode(blake2s_state *S) {
  S->f[1] = (uint32_t)-1;
}

static BLAKE2_INLINE void
blake2s_set_lastblock(blake2s_state *S) {
  if (S->last_node)
    blake2s_set_lastnode(S);
  S->f[0] = (uint32_t)-1;
}

static BLAKE2_INLINE void
blake2s_increment_counter(blake2s_state *S, uint32_t inc) {
  S->t[0] += inc;
  S->t[1] += (S->t[0] < inc);
}

static BLAKE2_INLINE void
blake2s_invalidate_state(blake2s_state * S) {
  burn(S, sizeof(*S)); /* wipe */
  blake2s_set_lastblock(S); /* invalidate for further use */
}

static BLAKE2_INLINE void
blake2s_init0(blake2s_state * S) {
  memset(S, 0, sizeof(*S));
  memcpy(S->h, blake2s_IV, sizeof(S->h));
}

int
blake2s_init_param(blake2s_state * S, const blake2s_param * P) {
  const unsigned char *p = (const unsigned char *)P;
  unsigned int i;

  if (NULL == P || NULL == S) {
    return -1;
  }

  blake2s_init0(S);
  /* IV XOR Parameter Block */
  for (i = 0; i < 8U; ++i) {
    S->h[i] ^= load32(&p[i * sizeof(S->h[i])]);
  }
  S->outlen = P->digest_length;
  return 0;
}

/* Sequential blake2s initialization */
int
blake2s_init(blake2s_state * S, size_t outlen) {
  blake2s_param P;

  if( S == NULL ) {
    return -1;
  }

  if( (outlen == 0) || (outlen > BLAKE2S_OUTBYTES) ) {
    blake2s_invalidate_state(S);
    return -1;
  }

  /* Setup Parameter Block for unkeyed BLAKE2 */
  P.digest_length = (uint8_t)outlen;
  P.key_length = 0;
  P.fanout = 1;
  P.depth = 1;
  store32(&P.leaf_length, 0);
  store48(&P.node_offset, 0);
  P.node_depth = 0;
  P.inner_length = 0;
  /* memset(P->reserved, 0, sizeof(P->reserved) ); */
  memset(P.salt, 0, sizeof(P.salt));
  memset(P.personal, 0, sizeof(P.personal));

  return blake2s_init_param(S, &P);
}

int
blake2s_init_key(blake2s_state * S, size_t outlen,
                 const void * key, size_t keylen) {
  blake2s_param P;

  if(S == NULL) {
    return -1;
  }

  if ((outlen == 0) || (outlen > BLAKE2S_OUTBYTES)) {
    blake2s_invalidate_state(S);
    return -1;
  }

  if ((key == 0) || (keylen == 0) || (keylen > BLAKE2S_KEYBYTES)) {
    blake2s_invalidate_state(S);
    return -1;
  }

  /* Setup Parameter Block for keyed BLAKE2 */
  P.digest_length = (uint8_t)outlen;
  P.key_length = (uint8_t)keylen;
  P.fanout = 1;
  P.depth = 1;
  store32(&P.leaf_length, 0);
  store48(&P.node_offset, 0);
  P.node_depth = 0;
  P.inner_length = 0;
  /* memset(P->reserved, 0, sizeof(P->reserved) ); */
  memset(P.salt, 0, sizeof(P.salt));
  memset(P.personal, 0, sizeof(P.personal));

  if (blake2s_init_param(S, &P) < 0) {
    blake2s_invalidate_state(S);
    return -1;
  }

  {
    uint8_t block[BLAKE2S_BLOCKBYTES];
    memset(block, 0, BLAKE2S_BLOCKBYTES);
    memcpy(block, key, keylen);
    blake2s_update(S, block, BLAKE2S_BLOCKBYTES);
    burn(block, BLAKE2S_BLOCKBYTES); /* Burn the key from stack */
  }
  return 0;
}


static void
blake2s_compress(blake2s_state *S, const uint8_t * block) {
  uint32_t m[16];
  uint32_t v[16];
  unsigned int i, r;

  for (i = 0; i < 16U; ++i) {
    m[i] = load32(block + i * sizeof(m[i]));
  }

  for (i = 0; i < 8U; ++i) {
    v[i] = S->h[i];
  }

  v[ 8] = blake2s_IV[0];
  v[ 9] = blake2s_IV[1];
  v[10] = blake2s_IV[2];
  v[11] = blake2s_IV[3];
  v[12] = blake2s_IV[4] ^ S->t[0];
  v[13] = blake2s_IV[5] ^ S->t[1];
  v[14] = blake2s_IV[6] ^ S->f[0];
  v[15] = blake2s_IV[7] ^ S->f[1];

#define G(r, i, a, b, c, d)                                                    \
  do {                                                                         \
    a = a + b + m[blake2s_sigma[r][2 * i + 0]];                                \
    d = rotr32(d ^ a, 16);                                                     \
    c = c + d;                                                                 \
    b = rotr32(b ^ c, 12);                                                     \
    a = a + b + m[blake2s_sigma[r][2 * i + 1]];                                \
    d = rotr32(d ^ a, 8);                                                      \
    c = c + d;                                                                 \
    b = rotr32(b ^ c, 7);                                                      \
  } while ((void)0,0)

#define ROUND(r)                                                               \
  do {                                                                         \
    G(r, 0, v[ 0], v[ 4], v[ 8], v[12]);                                       \
    G(r, 1, v[ 1], v[ 5], v[ 9], v[13]);                                       \
    G(r, 2, v[ 2], v[ 6], v[10], v[14]);                                       \
    G(r, 3, v[ 3], v[ 7], v[11], v[15]);                                       \
    G(r, 4, v[ 0], v[ 5], v[10], v[15]);                                       \
    G(r, 5, v[ 1], v[ 6], v[11], v[12]);                                       \
    G(r, 6, v[ 2], v[ 7], v[ 8], v[13]);                                       \
    G(r, 7, v[ 3], v[ 4], v[ 9], v[14]);                                       \
  } while ((void)0,0)

  for (r = 0; r < 10U; ++r) {
    ROUND(r);
  }

  for (i = 0U; i < 8U; ++i) {
    S->h[i] = S->h[i] ^ v[i] ^ v[i + 8];
  }

#undef G
#undef ROUND
}

int
blake2s_update(blake2s_state *S, const void *in, size_t inlen) {
  const uint8_t *pin = (const uint8_t *)in;

  if (inlen == 0) {
    return 0;
  }

  /* Sanity check */
  if (S == NULL || in == NULL) {
    return -1;
  }

  /* Is this a reused state? */
  if (S->f[0] != 0) {
    return -1;
  }

  if(S->buflen + inlen > BLAKE2S_BLOCKBYTES) {
    /* Complete current block */
    size_t left = S->buflen;
    size_t fill = BLAKE2S_BLOCKBYTES - left;
    memcpy(&S->buf[left], pin, fill);
    blake2s_increment_counter(S, BLAKE2S_BLOCKBYTES);
    blake2s_compress(S, S->buf);
    S->buflen = 0;
    inlen -= fill;
    pin += fill;
    /* Avoid buffer copies when possible */
    while (inlen > BLAKE2S_BLOCKBYTES) {
      blake2s_increment_counter(S, BLAKE2S_BLOCKBYTES);
      blake2s_compress(S, pin);
      inlen -= BLAKE2S_BLOCKBYTES;
      pin += BLAKE2S_BLOCKBYTES;
    }
  }
  memcpy(&S->buf[S->buflen], pin, inlen);
  S->buflen += (unsigned int)inlen;
  return 0;
}

int
blake2s_final(blake2s_state * S, void * out, size_t outlen) {
  uint8_t buffer[BLAKE2S_OUTBYTES] = {0};
  unsigned int i;

  /* Sanity checks */
  if (S == NULL || out == NULL || outlen < S->outlen) {
    return -1;
  }

  /* Is this a reused state? */
  if (S->f[0] != 0) {
    return -1;
  }

  blake2s_increment_counter(S, S->buflen);
  blake2s_set_lastblock(S);
  memset(&S->buf[S->buflen], 0, BLAKE2S_BLOCKBYTES - S->buflen); /* Padding */
  blake2s_compress(S, S->buf);

  for (i = 0U; i < 8U; ++i) { /* Output full hash to temp buffer */
    store32(buffer + sizeof(S->h[i]) * i, S->h[i]);
  }

  memcpy(out, buffer, S->outlen);
  burn(buffer, sizeof(buffer));
  burn(S->buf, sizeof(S->buf));
  burn(S->h, sizeof(S->h));
  return 0;
}

int
blake2s(void * out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen) {
  blake2s_state S;
  int ret = -1;

  /* Verify parameters */
  if (NULL == in && inlen > 0) {
    goto fail;
  }

  if (NULL == out || outlen == 0 || outlen > BLAKE2S_OUTBYTES) {
    goto fail;
  }

  if ((NULL == key && keylen > 0) || keylen > BLAKE2S_KEYBYTES) {
    goto fail;
  }

  if (keylen > 0) {
    if (blake2s_init_key(&S, outlen, key, keylen) < 0) {
      goto fail;
    }
  } else {
    if (blake2s_init(&S, outlen) < 0) {
      goto fail;
    }
  }

  if (blake2s_update(&S, in, inlen) < 0) {
    goto fail;
  }
  ret = blake2s_final(&S, out, outlen);

fail:
  burn(&S, sizeof(S));
  return ret;
}

#include "blake2-kat.h"

int blake2s_selftest(void) {
  uint8_t key[BLAKE2S_KEYBYTES];
  uint8_t buf[KAT_LENGTH];
  unsigned int i, step;

  for (i = 0; i < BLAKE2S_KEYBYTES; ++i) {
    key[i] = (uint8_t)i;
  }

  for (i = 0; i < KAT_LENGTH; ++i) {
    buf[i] = (uint8_t)i;
  }

  for (i = 0; i < KAT_LENGTH; ++i) {
    uint8_t hash[BLAKE2S_OUTBYTES];
    int err = 0;
    if ((err = blake2s(hash, BLAKE2S_OUTBYTES, buf, i, key, BLAKE2S_KEYBYTES)) < 0) {
      return -1;
    }

    if (0 != memcmp(hash, blake2s_keyed_kat[i], BLAKE2S_OUTBYTES)) {
      return -2;
    }
  }

  /* Test streaming API */
  for(step = 1; step < BLAKE2S_BLOCKBYTES; ++step) {
    for (i = 0; i < KAT_LENGTH; ++i) {
      uint8_t hash[BLAKE2S_OUTBYTES];
      blake2s_state S;
      uint8_t * p = buf;
      size_t mlen = i;
      int err = 0;

      if( (err = blake2s_init_key(&S, BLAKE2S_OUTBYTES, key, BLAKE2S_KEYBYTES)) < 0 ) {
        return -3;
      }

      while (mlen >= step) {
        if ( (err = blake2s_update(&S, p, step)) < 0 ) {
          return -4;
        }
        mlen -= step;
        p += step;
      }
      if ( (err = blake2s_update(&S, p, mlen)) < 0) {
        return -5;
      }
      if ( (err = blake2s_final(&S, hash, BLAKE2S_OUTBYTES)) < 0) {
        return -6;
      }

      if (0 != memcmp(hash, blake2s_keyed_kat[i], BLAKE2S_OUTBYTES)) {
        return -7;
      }
    }
  }

  /* Test error checking */
  {
    blake2s_state S;
    uint8_t hash[BLAKE2S_OUTBYTES];
    if( !(blake2s_init(&S, BLAKE2S_OUTBYTES + 1) < 0) ) { /* Output too large */
      return -8;
    }
    if( !(blake2s_init_key(&S, BLAKE2S_OUTBYTES, NULL, 1) < 0) ) { /* NULL key */
      return -9;
    }
    if( !(blake2s_init(&S, BLAKE2S_OUTBYTES) == 0) ) { /* OK */
      return -10;
    }
    if( !(blake2s_final(&S, hash, sizeof hash) == 0) ) { /* OK */
      return -11;
    }
    if( !(blake2s_final(&S, hash, sizeof hash) < 0) ) { /* invalid state */
      return -12;
    }
    if( !(blake2s_update(&S, hash, sizeof hash) < 0) ) { /* invalid state */
      return -13;
    }
  }
  return 0;
}

#define BLAKE2S_SELFTEST
#if defined(BLAKE2S_SELFTEST)

#include <stdlib.h>

int main(void) {
  printf("%s\n", blake2s_selftest() < 0 ? "error" : "ok");
  return 0;
}
#endif
