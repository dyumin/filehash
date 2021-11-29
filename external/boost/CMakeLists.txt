include(ExternalProject)

set(BOOST_VERSION_STRING "1.77.0")
set(BOOST_HASH "5347464af5b14ac54bb945dc68f1dd7c56f0dad7262816b956138fc53bcc0131")

set(BOOST_COMPONENTS
    # chrono
    # date_time
    # filesystem
    # iostreams
    program_options
    # regex
    # system
    # thread
    )
string(REPLACE "." "_" BOOST_VERSION_UNDERSCORED ${BOOST_VERSION_STRING})
#set(BOOST_URL "${CMAKE_CURRENT_LIST_DIR}/boost_${BOOST_VERSION_UNDERSCORED}.tar.gz") # GitHub blocks pushes that exceed 100 MB.
set(BOOST_URL "https://boostorg.jfrog.io/artifactory/main/release/${BOOST_VERSION_STRING}/source/boost_${BOOST_VERSION_UNDERSCORED}.tar.gz")
set(BOOST_SOURCE_TARGET_DIR "${CMAKE_CURRENT_BINARY_DIR}/boost")
set(BOOST_BUILD_ROOT_DIR "${BOOST_SOURCE_TARGET_DIR}/src/boost")

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(BOOST_BUILD_TYPE variant=debug optimization=off inlining=off)
else ()
    set(BOOST_BUILD_TYPE variant=release optimization=speed inlining=full)
endif ()

set(BOOST_BUILD_CMD ${BOOST_BUILD_ROOT_DIR}/tools/build/src/engine/b2 install
    --build-dir=${BOOST_SOURCE_TARGET_DIR} --prefix=${EXTERNAL_PREFIX_DIR}
    --layout=system
    link=static ${BOOST_BUILD_TYPE} threading=multi debug-symbols=on runtime-debugging=on visibility=global
    "cxxflags=${EXTERNAL_CXX_FLAGS}"
    )

message(STATUS "CMAKE_CXX_COMPILER_ID = ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "CMAKE_CXX_COMPILER = ${CMAKE_CXX_COMPILER}")

if (${CMAKE_CXX_COMPILER_ID} STREQUAL "GNU")
    set(BOOST_GENERIC_COMPILER "gcc")
elseif (${CMAKE_CXX_COMPILER_ID} STREQUAL "Clang")
    set(BOOST_GENERIC_COMPILER "clang")
else ()
    message(FATAL_ERROR "Please help determine the toolset here")
endif ()

set(BOOST_BOOTSTRAP_SCRIPT sh -c "${BOOST_BUILD_ROOT_DIR}/tools/build/src/engine/build.sh --cxx=${CMAKE_CXX_COMPILER} && ${BOOST_BUILD_ROOT_DIR}/bootstrap.sh -with-toolset=${BOOST_GENERIC_COMPILER} --with-bjam=${BOOST_BUILD_ROOT_DIR}/tools/build/src/engine/b2")
list(APPEND BOOST_BUILD_CMD "toolset=${BOOST_GENERIC_COMPILER}")

set(BOOST_ALL_TARGETS_LIST boost_headers)
add_custom_target(boost_headers DEPENDS boost)
foreach (__component ${BOOST_COMPONENTS})
    list(APPEND BOOST_BUILD_CMD --with-${__component})
    add_library(boost_${__component} STATIC IMPORTED GLOBAL)
    add_dependencies(boost_${__component} boost_headers)
    set_target_properties(boost_${__component}
        PROPERTIES
        IMPORTED_LOCATION "${EXTERNAL_LIB_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}boost_${__component}${CMAKE_STATIC_LIBRARY_SUFFIX}"
        INTERFACE_INCLUDE_DIRECTORIES "${EXTERNAL_INCLUDE_DIR}")
    list(APPEND BOOST_ALL_TARGETS_LIST boost_${__component})
endforeach ()

ExternalProject_Add(boost
    PREFIX ${BOOST_SOURCE_TARGET_DIR}
    INSTALL_DIR ${EXTERNAL_PREFIX_DIR}
    BINARY_DIR ${BOOST_BUILD_ROOT_DIR}
    URL ${BOOST_URL}
    URL_HASH SHA256=${BOOST_HASH}
    CONFIGURE_COMMAND ${BOOST_BOOTSTRAP_SCRIPT}
    BUILD_COMMAND ${BOOST_BUILD_CMD}
    INSTALL_COMMAND ""  # installation is done as part of the build
    )
