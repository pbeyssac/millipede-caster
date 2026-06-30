cmake_minimum_required(VERSION 3.20)

project(caster C)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_XOPEN_SOURCE -D_GNU_SOURCE -Wall")

# Detect BSD systems and set CMAKE_C_FLAGS accordingly
if(${CMAKE_SYSTEM_NAME} MATCHES "BSD")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DDEBUG_JEMALLOC")
endif()

# Enable DEBUG=1 (memory allocation tracking, junk-filling) only in Debug builds.
# In Release builds DEBUG defaults to 0 (see caster/conf.h) for performance and
# to avoid leaking sensitive data (e.g. passwords) through DEBUG/EDEBUG logs.
if(CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DDEBUG=1")
endif()

file(GLOB SOURCES "caster/*.c")
get_filename_component(TESTS_C_ABS "caster/tests.c" ABSOLUTE)
list(REMOVE_ITEM SOURCES ${TESTS_C_ABS})

link_libraries(m pthread event_core event_pthreads event_extra event_openssl json-c cyaml ssl crypto)

add_executable(caster_cmake ${SOURCES})
#add_executable(tests caster/tests.c caster/util.c)

# Name the output binary "caster" so the Dockerfile and other tooling
# that expect /app/build/caster keep working.
set_target_properties(caster_cmake PROPERTIES OUTPUT_NAME "caster")

# Static linking is opt-in via -DSTATIC_BUILD=ON.
# A fully static binary requires all static dependencies (libyaml, libzstd,
# etc.) and is mainly useful for the Docker image. The default CI build
# produces a dynamically linked binary which is simpler and more portable.
option(STATIC_BUILD "Build a fully static binary" OFF)
if(STATIC_BUILD)
    target_link_libraries(caster_cmake -static yaml zstd z)
endif()

# Enable testing with CTest
enable_testing()
# Run a Python integration test via ctest
add_test(
    NAME near1
    COMMAND python3 ${CMAKE_SOURCE_DIR}/tests/test-near1.py
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tests
)
