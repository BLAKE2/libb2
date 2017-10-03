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

if(MSVC)
    set(CMAKE_REQUIRED_FLAGS "${O_FLAGS} /openmp")
elseif(CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_REQUIRED_FLAGS "${O_FLAGS} -fopenmp")
elseif("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
    # don't know how to enable clang's openmp support
endif()
check_c_source_compiles("
    #include <omp.h>
    #ifndef _OPENMP
    #error \"_OPENMP not defined\"
    #endif
    int main()
    {
        char hash[1024];
        omp_set_num_threads(4);
        #pragma omp parallel shared(hash)
        omp_get_thread_num();
        return 0;
    }
" OpenMP_AVAILABLE)
