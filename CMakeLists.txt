cmake_minimum_required(VERSION 3.16)
project(filehash)

set(CMAKE_CXX_STANDARD 17)

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "force set by root CMakeLists.txt" FORCE)
endif (NOT CMAKE_BUILD_TYPE)

find_library(PTHREAD_LIBRARY pthread REQUIRED)

# TODO: support clang (-ggdb)
set(CMAKE_C_FLAGS_DEBUG "-ggdb -O0 -fno-inline" CACHE STRING "force set by root CMakeLists.txt" FORCE)
set(CMAKE_CXX_FLAGS_DEBUG "-ggdb -O0 -fno-inline" CACHE STRING "force set by root CMakeLists.txt" FORCE)
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-ggdb -O3" CACHE STRING "force set by root CMakeLists.txt" FORCE)
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-ggdb -O3" CACHE STRING "force set by root CMakeLists.txt" FORCE)
set(CMAKE_C_FLAGS_RELEASE "-O3" CACHE STRING "force set by root CMakeLists.txt" FORCE)
set(CMAKE_CXX_FLAGS_RELEASE "-O3" CACHE STRING "force set by root CMakeLists.txt" FORCE)
string(TOUPPER ${CMAKE_BUILD_TYPE} EXTERNAL_BUILD_TYPE_UC)

set(EXTERNAL_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${EXTERNAL_BUILD_TYPE_UC}}")
set(EXTERNAL_PREFIX_DIR "${CMAKE_BINARY_DIR}/external_result")
set(EXTERNAL_INCLUDE_DIR "${EXTERNAL_PREFIX_DIR}/include")
set(EXTERNAL_LIB_DIR "${EXTERNAL_PREFIX_DIR}/lib")
file(MAKE_DIRECTORY ${EXTERNAL_PREFIX_DIR} ${EXTERNAL_INCLUDE_DIR} ${EXTERNAL_LIB_DIR})
add_subdirectory(external)

add_executable(filehash main.cpp)
target_link_libraries(filehash boost_program_options ${PTHREAD_LIBRARY})

add_executable(simple main2.cpp)
target_link_libraries(simple boost_program_options ${PTHREAD_LIBRARY})