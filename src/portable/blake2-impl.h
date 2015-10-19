#ifndef LIBB2_PORTABLE_BLAKE2_IMPL_H
#define LIBB2_PORTABLE_BLAKE2_IMPL_H

#include <stdint.h>
#include <string.h>

#if defined(_MSC_VER)
  #define BLAKE2_INLINE __inline
#elif defined(__GNUC__)
  #define BLAKE2_INLINE __inline__
#else
  #define BLAKE2_INLINE
#endif



static BLAKE2_INLINE int is_little_endian(void) {
#if defined(__BYTE_ORDER__ ) && (__BYTE_ORDER__  == __ORDER_LITTLE_ENDIAN)
  return 1;
#else /* Not guaranteed to be resolved at compile time */
  /* 
  Compilers seem to be able to figure this out at compile time:
    - MSVC 2013, 2015
    - GCC 5.2
    - Clang 3.7
  */
  const uint32_t x = 0x01020304;
  unsigned char m[sizeof x];
  memcpy(m, &x, sizeof m);
  return m[0] == 0x04;
#endif
}

static BLAKE2_INLINE uint32_t load32(const void *src) {
  if (is_little_endian()) {
    uint32_t w;
    memcpy(&w, src, sizeof w);
    return w;
  } else {
    const uint8_t *p = (const uint8_t *)src;
    uint32_t w = *p++;
    w |= (uint32_t)(*p++) << 8;
    w |= (uint32_t)(*p++) << 16;
    w |= (uint32_t)(*p++) << 24;
    return w;
  }
}

static BLAKE2_INLINE uint64_t load64(const void *src) {
#if defined(NATIVE_LITTLE_ENDIAN)
  uint64_t w;
  memcpy(&w, src, sizeof w);
  return w;
#else
  const uint8_t *p = (const uint8_t *)src;
  uint64_t w = *p++;
  w |= (uint64_t)(*p++) << 8;
  w |= (uint64_t)(*p++) << 16;
  w |= (uint64_t)(*p++) << 24;
  w |= (uint64_t)(*p++) << 32;
  w |= (uint64_t)(*p++) << 40;
  w |= (uint64_t)(*p++) << 48;
  w |= (uint64_t)(*p++) << 56;
  return w;
#endif
}

static BLAKE2_INLINE void store32(void *dst, uint32_t w) {
#if defined(NATIVE_LITTLE_ENDIAN)
  memcpy(dst, &w, sizeof w);
#else
  uint8_t *p = (uint8_t *)dst;
  *p++ = (uint8_t)w;
  w >>= 8;
  *p++ = (uint8_t)w;
  w >>= 8;
  *p++ = (uint8_t)w;
  w >>= 8;
  *p++ = (uint8_t)w;
#endif
}

static BLAKE2_INLINE void store64(void *dst, uint64_t w) {
#if defined(NATIVE_LITTLE_ENDIAN)
  memcpy(dst, &w, sizeof w);
#else
  uint8_t *p = (uint8_t *)dst;
  *p++ = (uint8_t)w;
  w >>= 8;
  *p++ = (uint8_t)w;
  w >>= 8;
  *p++ = (uint8_t)w;
  w >>= 8;
  *p++ = (uint8_t)w;
  w >>= 8;
  *p++ = (uint8_t)w;
  w >>= 8;
  *p++ = (uint8_t)w;
  w >>= 8;
  *p++ = (uint8_t)w;
  w >>= 8;
  *p++ = (uint8_t)w;
#endif
}

static BLAKE2_INLINE uint64_t load48(const void *src) {
  const uint8_t *p = (const uint8_t *)src;
  uint64_t w = *p++;
  w |= (uint64_t)(*p++) << 8;
  w |= (uint64_t)(*p++) << 16;
  w |= (uint64_t)(*p++) << 24;
  w |= (uint64_t)(*p++) << 32;
  w |= (uint64_t)(*p++) << 40;
  return w;
}

static BLAKE2_INLINE void store48(void *dst, uint64_t w) {
  uint8_t *p = (uint8_t *)dst;
  *p++ = (uint8_t)w;
  w >>= 8;
  *p++ = (uint8_t)w;
  w >>= 8;
  *p++ = (uint8_t)w;
  w >>= 8;
  *p++ = (uint8_t)w;
  w >>= 8;
  *p++ = (uint8_t)w;
  w >>= 8;
  *p++ = (uint8_t)w;
}

static BLAKE2_INLINE uint32_t rotr32(const uint32_t w, const unsigned c) {
  return (w >> c) | (w << (32 - c));
}

static BLAKE2_INLINE uint64_t rotr64(const uint64_t w, const unsigned c) {
  return (w >> c) | (w << (64 - c));
}

/* prevents compiler optimizing out memset() */
static BLAKE2_INLINE void burn(void *v, size_t n) {
  static void *(* const volatile memset_v)(void *, int, size_t) = &memset;
  memset_v(v, 0, n);
}

#endif
