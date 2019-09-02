cmake_minimum_required(VERSION 3.5)

include (AutoConf.cmake)

option(BUILD_SHARED_LIBS "Link using shared libs" OFF)
option(make_tests "Make test programs" OFF)

if(NOT PLATFORM)
   set(PLATFORM "posix" CACHE STRING "Choose platform." FORCE)
   set_property(CACHE PLATFORM PROPERTY STRINGS "contiki" "espidf" "posix" "riot")
endif()

set(PACKAGE_NAME "tinydtls")
set(PACKAGE_VERSION "0.8.6" )

option(DTLS_ECC "disable support for TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8" ON )
option(DTLS_PSK "disable support for TLS_PSK_WITH_AES_128_CCM_8" ON)

configure_file(dtls_config.h.cmake.in dtls_config.h )

file(GLOB SOURCE "*.c" "ecc/ecc.c" "aes/*.c" "sha2/sha2.c" "platform/dtls_prng_${PLATFORM}.c")

add_library(tinydtls ${SOURCE})
target_compile_options(tinydtls PRIVATE -Wall -pedantic -std=c99 -DSHA2_USE_INTTYPES_H -fPIC -pedantic -Wall -Wextra -Wformat-security -Winline -Wmissing-declarations -Wmissing-prototypes -Wnested-externs -Wpointer-arith -Wshadow -Wstrict-prototypes -Wswitch-default -Wswitch-enum -Wunused  -DDTLSv12 -DWITH_SHA256 -DDTLS_CHECK_CONTENTTYPE)
target_compile_options(tinydtls PUBLIC -DDTLSv12 -DWITH_SHA256)
target_include_directories(tinydtls PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

if( ${make_tests} )
    add_subdirectory(tests)
endif()


if(${BUILD_SHARED_LIBS})
    install(TARGETS    tinydtls       DESTINATION /usr/local/lib )    
endif()