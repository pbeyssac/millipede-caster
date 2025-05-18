cmake_minimum_required(VERSION 3.20)

project(caster C)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

# Detect BSD systems and set CMAKE_C_FLAGS accordingly
if(${CMAKE_SYSTEM_NAME} MATCHES "BSD")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DDEBUG_JEMALLOC")
endif()

file(GLOB SOURCES "caster/*.c")
get_filename_component(TESTS_C_ABS "caster/tests.c" ABSOLUTE)
list(REMOVE_ITEM SOURCES ${TESTS_C_ABS})

link_libraries(m pthread event_core event_pthreads event_extra json-c cyaml)

add_executable(caster ${SOURCES})
add_executable(tests caster/tests.c caster/util.c caster/conf.c)

if (CMAKE_BUILD_TYPE STREQUAL "Release")
    target_link_libraries(caster -static yaml)
endif()
