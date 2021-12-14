#ifndef ASMOPT_POLY1305_H
#define ASMOPT_POLY1305_H

#define ARCH_X86
#define HAVE_AVX512
#define HAVE_AVX2
#define HAVE_AVX
#define HAVE_XOP
#define HAVE_SSE4_2
#define HAVE_SSE4_1
#define HAVE_SSSE3
#define HAVE_SSE3
#define HAVE_SSE2
#define HAVE_SSE
#define HAVE_MMX
#define HAVE_SLASHMACRO
#define HAVE_AS_PRIVATE_EXTERN
#define CPU_64BITS
#define HAVE_INT64
#define HAVE_INT32
#define HAVE_INT16
#define HAVE_INT8
#define HAVE_STDINT
#define HAVE_INT128
#define DEFINE_INT128 typedef signed __int128 int128_t; typedef unsigned __int128 uint128_t;
#define HAVE_GETTIMEOFDAY

#if !defined(BUILDING_ASM)

#include <stddef.h>

/* use HAVE_INTxxx to determine if an integer with [8,16,32,64,128] bits is available */

#if defined(HAVE_STDINT)
	#include <stdint.h>
#else
	DEFINE_INT64
	DEFINE_INT32
	DEFINE_INT16
	DEFINE_INT8
#endif

/* stdint doesn't currently detect this, but may in the future */
DEFINE_INT128

#endif /* !defined(BUILDING_ASM) */

#endif /* ASMOPT_POLY1305_H */

