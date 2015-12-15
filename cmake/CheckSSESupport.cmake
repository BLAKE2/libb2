# Written in 2015 by Henrik Steffen Gaﬂmann henrik@gassmann.onl
#
# To the extent possible under law, the author(s) have dedicated all
# copyright and related and neighboring rights to this software to the
# public domain worldwide. This software is distributed without any warranty.
#
# You should have received a copy of the CC0 Public Domain Dedication
# along with this software. If not, see
#
#     http://creativecommons.org/publicdomain/zero/1.0/
#
########################################################################

include(CheckCSourceCompiles)

set(O_FLAGS ${CMAKE_REQUIRED_FLAGS})
set(O_DEFS ${CMAKE_REQUIRED_DEFINITIONS})

set(SSE2_CODE "
    #ifdef _MSC_VER
    #include <intrin.h>
    #endif
    #include <emmintrin.h>
    
    int main()
    {
        __m128i m128i;
        /* common intrinsics */
        _mm_loadu_si128(&m128i);
        _mm_storeu_si128(&m128i, m128i);
        _MM_SHUFFLE(0,3,2,1);
        
        /* blake2s intrinsics */
        _mm_set_epi32(0,0,0,0);
        _mm_xor_si128(m128i,m128i);
        _mm_srli_epi32(m128i,0);
        _mm_slli_epi32(m128i,0);
        _mm_add_epi32(m128i,m128i);
        _mm_shuffle_epi32(m128i,0);
        _mm_setr_epi32(0,0,0,0);
        
        /* blake2b intrinsics */
        
        
        return 0;
    }
")
set(SSSE3_CODE "
    #ifdef _MSC_VER
    #include <intrin.h>
    #endif
    #include <emmintrin.h>
    #include <tmmintrin.h>
    
    int main()
    {
        __m128 m128;
        __m128i m128i;
        /* common intrinsics */
        _mm_castsi128_ps(m128i);
        _mm_castps_si128(m128);
        
        /* blake2s intrinsics */
        _mm_shuffle_epi8(m128i,m128i);
        
        /* blake2b intrinsics */
        
        
        return 0;
    }
")
set(SSE41_CODE "
    #ifdef _MSC_VER
    #include <intrin.h>
    #endif
    #include <emmintrin.h>
    #include <tmmintrin.h>
    #include <smmintrin.h>
    
    int main()
    {
        __m128 m128;
        __m128i m128i;
        /* blake2s intrinsics */
        _mm_shuffle_ps(m128, m128, 0);
        _mm_blend_epi16(m128i, m128i, 0);
        _mm_slli_si128(m128i, 0); /*SSE2*/
        _mm_srli_si128(m128i, 0); /*SSE2*/
        _mm_shufflehi_epi16(m128i, 0); /*SSE2*/
        _mm_unpacklo_epi32(m128i, m128i); /*SSE2*/
        _mm_unpacklo_epi64(m128i, m128i); /*SSE2*/
        _mm_unpackhi_epi32(m128i, m128i); /*SSE2*/
        _mm_unpackhi_epi64(m128i, m128i); /*SSE2*/
        
        /* blake2b intrinsics */
        
        
        return 0;
    }
")
# correct this if i'm wrong, but I couldn't find any AVX intrinsics :(
#set(AVX_CODE "
#    #ifdef _MSC_VER
#    #include <intrin.h>
#    #endif
#    #include <emmintrin.h>
#    #include <tmmintrin.h>
#    #include <smmintrin.h>
#    #include <immintrin.h>
#    
#    int main()
#    {
#        __m128i m128;
#        //blake2s intrinsics
#        
#        //blake2b intrinsics
#        
#        
#        return 0;
#    }
#")
set(XOP_CODE "
    #ifdef _MSC_VER
    #include <intrin.h>
    #include <ammintrin.h>
    #else
    #include <x86intrin.h>
    #endif
    #include <emmintrin.h>
    #include <tmmintrin.h>
    #include <smmintrin.h>
    #include <immintrin.h>
    
    int main()
    {
        __m128i m128i;
        /* blake2s intrinsics */
        _mm_roti_epi32(m128i,0);
        _mm_perm_epi8(m128i,m128i,m128i);
        
        /* blake2b intrinsics */
        
        
        return 0;
    }
")

if(CMAKE_COMPILER_IS_GNUCC OR ("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang"))
    set(CMAKE_REQUIRED_FLAGS "${O_FLAGS} -msse2")
endif()
check_c_source_compiles("${SSE2_CODE}" SSE2_AVAILABLE)

if(CMAKE_COMPILER_IS_GNUCC OR "${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
    set(CMAKE_REQUIRED_FLAGS "${O_FLAGS} -msse2 -mssse3")
endif()
check_c_source_compiles("${SSSE3_CODE}" SSSE3_AVAILABLE)

if(CMAKE_COMPILER_IS_GNUCC OR "${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
    set(CMAKE_REQUIRED_FLAGS "${O_FLAGS} -msse2 -mssse3 -msse4.1")
endif()
check_c_source_compiles("${SSE41_CODE}" SSE41_AVAILABLE)

#if(CMAKE_COMPILER_IS_GNUCC)
#    set(CMAKE_REQUIRED_FLAGS "${O_FLAGS} -msse2 -mssse3 -msse4.1 -mavx")
#endif()
#check_c_source_compiles("${AVX_CODE}" AVX_AVAILABLE)
set(AVX_AVAILABLE 1)

if(CMAKE_COMPILER_IS_GNUCC OR "${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
    set(CMAKE_REQUIRED_FLAGS "${O_FLAGS} -msse2 -mssse3 -msse4.1 -mxop")
endif()
check_c_source_compiles("${XOP_CODE}" XOP_AVAILABLE)

unset(XOP_CODE)
#unset(AVX_CODE)
unset(SSE41_CODE)
unset(SSSE3_CODE)
unset(SSE2_CODE)
unset(O_DEFS)
unset(O_FLAGS)
