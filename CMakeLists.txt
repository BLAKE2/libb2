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
cmake_minimum_required(VERSION 3.0)
cmake_policy(VERSION 3.0)
cmake_policy(SET CMP0054 NEW)
project(libb2 VERSION 0.97)

if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
	message(FATAL_ERROR "in-source builds are not supported!")
endif()

# add cmake script path
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

# set pre install output directories
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
if(MSVC)
    set(CMAKE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
endif()

########################################################################
# platform detection/compiler support
include(TestBigEndian)
TEST_BIG_ENDIAN(BLAKE2_BIG_ENDIAN)

# SSE feature level
include(CheckSSESupport)
set(BLAKE2_SSE_LEVELS NO_SSE) #0
if(SSE2_AVAILABLE)
    list(APPEND BLAKE2_SSE_LEVELS SSE2) #1
    if(SSSE3_AVAILABLE)
        list(APPEND BLAKE2_SSE_LEVELS SSSE3) #2
        if(SSE41_AVAILABLE)
            list(APPEND BLAKE2_SSE_LEVELS SSE4_1) #3
            if (AVX_AVAILABLE)
                list(APPEND BLAKE2_SSE_LEVELS AVX) #4
                if (XOP_AVAILABLE)
                    list(APPEND BLAKE2_SSE_LEVELS XOP) #5
                endif()
            endif()
        endif()
    endif()
endif()

if (XOP_AVAILABLE)
    option(BLAKE2_FAT_BINARIES "build fat binaries with all available SSE code paths." ON)
endif()
if (BLAKE2_FAT_BINARIES)
    list(FIND BLAKE2_SSE_LEVELS XOP BLAKE2_EIS_IDX)
else()
    list(FIND BLAKE2_SSE_LEVELS NO_SSE BLAKE2_EIS_IDX)
endif()

# openmp support
include(CheckOpenMPSupport)
if(OpenMP_AVAILABLE)
    option(BLAKE2_UTILIZE_OPENMP "" ON)
else()
    set(BLAKE2_UTILIZE_OPENMP OFF)
endif()

option(BLAKE2_BUILD_TESTS "")
option(BLAKE2_SHARED_OBJECT "build a dynamic link library instead of a static one")

########################################################################
# add project
add_subdirectory(src)

########################################################################
# install target
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/libb2-config-version.cmake"
  VERSION ${libb2_VERSION}
  COMPATIBILITY ExactVersion
)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libb2-config-version.cmake" DESTINATION cmake)

configure_file(cmake/libb2-config.cmake
  "${CMAKE_CURRENT_BINARY_DIR}/libb2-config.cmake"
  COPYONLY
)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libb2-config.cmake" DESTINATION cmake)

install(EXPORT libb2-targets DESTINATION cmake)