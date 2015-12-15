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

if(BLAKE2_SHARED_OBJECT)
    set(BLAKE2_SHARED_LIBRARY_VAL 1)
    set(BLAKE2_SHARED_LIBRARY_DEF SHARED)
else()
    set(BLAKE2_SHARED_LIBRARY_VAL 0)
    set(BLAKE2_SHARED_LIBRARY_DEF STATIC)
endif()

set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(LIBB2_SUFFIX_LIST _sse2 _ssse3 _sse41 _avx _xop)

set(COUNTER 0)
while(COUNTER LESS BLAKE2_EIS_IDX)
    list(GET LIBB2_SUFFIX_LIST ${COUNTER} _CURR_SUFFIX) 
    MATH(EXPR COUNTER "0${COUNTER}+1")
    
    list(GET BLAKE2_SSE_LEVELS ${COUNTER} _CURR_LEVEL)
    #list(APPEND BLAKE2_IMPL_LIST ${_CURR_LEVEL})
    
    set(_CURR_B2S_FILE "${CMAKE_CURRENT_BINARY_DIR}/blake2s_${_CURR_LEVEL}.c")
    set(_CURR_B2B_FILE "${CMAKE_CURRENT_BINARY_DIR}/blake2b_${_CURR_LEVEL}.c")
    configure_file("blake2s.c"
        ${_CURR_B2S_FILE}
        COPYONLY
    )
    configure_file("blake2b.c"
        ${_CURR_B2B_FILE}
        COPYONLY
    )
    set(_CURR_FILES ${_CURR_B2S_FILE} ${_CURR_B2B_FILE})
    list(APPEND BLAKE2_IMPL_SOURCES ${_CURR_FILES})
    
    if(COUNTER GREATER 0)
        list(APPEND FEATURE_DEFS HAVE_${_CURR_LEVEL})
        if (CMAKE_COMPILER_IS_GNUCC OR "${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
            if(COUNTER GREATER 4)
                set(FEATURE_FLAGS "${FEATURE_FLAGS} -mxop")
            elseif(COUNTER GREATER 3)
                set(FEATURE_FLAGS "${FEATURE_FLAGS} -mavx")
            elseif(COUNTER GREATER 2)
                set(FEATURE_FLAGS "${FEATURE_FLAGS} -msse4.1")
            elseif(COUNTER GREATER 1)
                set(FEATURE_FLAGS "${FEATURE_FLAGS} -mssse3")
            else()
                set(FEATURE_FLAGS -msse2)
            endif()
        endif()
    endif()
    
    set_source_files_properties(${_CURR_FILES} PROPERTIES
        COMPILE_FLAGS "${FEATURE_FLAGS}"
        COMPILE_DEFINITIONS "SUFFIX=${_CURR_SUFFIX};${FEATURE_DEFS}"
    )
    
    unset(_CURR_FILES)
    unset(_CURR_B2B_FILE)
    unset(_CURR_B2S_FILE)
    unset(_CURR_SUFFIX)
    unset(_CURR_LEVEL)
endwhile()
unset(FEATURE_FLAGS)
unset(FEATURE_DEFS)
unset(COUNTER)

if(NOT (BLAKE2_EIS_IDX EQUAL 0))
    set_source_files_properties(blake2b-ref.c blake2s-ref.c PROPERTIES
        COMPILE_DEFINITIONS "SUFFIX=_ref"
    )
else()
    set_source_files_properties(blake2b-ref.c blake2s-ref.c PROPERTIES
        COMPILE_DEFINITIONS "SUFFIX="
    )
endif()

add_library(libb2 ${BLAKE2_SHARED_LIBRARY_DEF}
    blake2.h
    blake2-config.h
    blake2-impl.h
    $<$<NOT:$<EQUAL:${BLAKE2_EIS_IDX},0>>:blake2-dispatch.c>
    
    
    blake2b-ref.c
    blake2b-round.h
    blake2b-load-sse2.h
    blake2b-load-sse41.h
    
    blake2bp.c
    
    
    blake2s-ref.c
    blake2s-round.h
    blake2s-load-sse2.h
    blake2s-load-sse41.h
    blake2s-load-xop.h
    
    blake2sp.c
    
    ${BLAKE2_IMPL_SOURCES}
)

source_group(common REGULAR_EXPRESSION .*blake2.*)
source_group(blake2s REGULAR_EXPRESSION .*blake2s.*)
source_group(blake2b REGULAR_EXPRESSION .*blake2b.*)

########################################################################
# config
target_compile_definitions(libb2
    PRIVATE
        _UNICODE
        NO_CONFIG
        $<$<NOT:$<BOOL:${BLAKE2_BIG_ENDIAN}>>:NATIVE_LITTLE_ENDIAN>
        $<${BLAKE2_SHARED_LIBRARY_VAL}:BLAKE2_DLL_EXPORTS>
        
    PUBLIC
        $<${BLAKE2_SHARED_LIBRARY_VAL}:BLAKE2_DLL>
)
set_target_properties(libb2 PROPERTIES PREFIX "")

if(BLAKE2_UTILIZE_OPENMP)
    if(MSVC)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /openmp")
    elseif(CMAKE_COMPILER_IS_GNUCC)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fopenmp")
    endif()
endif()

########################################################################
# install target
install(TARGETS libb2 EXPORT libb2-targets
    RUNTIME DESTINATION bin/$<CONFIG>
    LIBRARY DESTINATION lib/$<CONFIG>
    ARCHIVE DESTINATION lib/$<CONFIG>
    INCLUDES DESTINATION include
)
install(FILES blake2.h DESTINATION include)


########################################################################
# test drivers

if(BLAKE2_BUILD_TESTS)

    # BLAKE2 B
    add_executable(blake2b_test
        blake2b-test.c
        blake2-kat.h
    )
    target_link_libraries(blake2b_test PRIVATE libb2)

    # BLAKE2 S
    add_executable(blake2s_test
        blake2s-test.c
        blake2-kat.h
    )
    target_link_libraries(blake2s_test PRIVATE libb2)

    # BLAKE2 BP
    add_executable(blake2bp_test
        blake2bp-test.c
        blake2-kat.h
    )
    target_link_libraries(blake2bp_test PRIVATE libb2)

    # BLAKE2 SP
    add_executable(blake2sp_test
        blake2sp-test.c
        blake2-kat.h
    )
    target_link_libraries(blake2sp_test PRIVATE libb2)

endif()
