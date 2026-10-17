cmake_minimum_required(VERSION 3.21)
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/../VERSION" HOOKMAP_VERSION)
string(STRIP "${HOOKMAP_VERSION}" HOOKMAP_VERSION)
project(HookMap VERSION ${HOOKMAP_VERSION} LANGUAGES CXX)
# SKSE packs a version as major<<24 | minor<<16 | build<<4
math(EXPR HOOKMAP_VERSION_PACKED "(${PROJECT_VERSION_MAJOR} << 24) | (${PROJECT_VERSION_MINOR} << 16) | (${PROJECT_VERSION_PATCH} << 4)")
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")   # static runtime: nothing to install next to the DLL

add_library(HookMap SHARED src/main.cpp src/scanner.cpp)
target_compile_definitions(HookMap PRIVATE HOOKMAP_VERSION="${HOOKMAP_VERSION}" HOOKMAP_VERSION_PACKED=${HOOKMAP_VERSION_PACKED}u NOMINMAX WIN32_LEAN_AND_MEAN)
target_compile_options(HookMap PRIVATE /W4 /permissive- /utf-8)

# Self-test: patches its own code the way plugins do and checks that the scan names the right DLLs.
add_library(hm_test_a SHARED test/test_dll.cpp)
add_library(hm_test_b SHARED test/test_dll.cpp)
target_compile_definitions(hm_test_a PRIVATE HM_TEST_NAME="a")
target_compile_definitions(hm_test_b PRIVATE HM_TEST_NAME="b")
add_executable(hookmap_selftest test/selftest.cpp src/scanner.cpp)
target_compile_definitions(hookmap_selftest PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
target_compile_options(hookmap_selftest PRIVATE /W4 /permissive- /utf-8 /Od)
add_dependencies(hookmap_selftest hm_test_a hm_test_b)
