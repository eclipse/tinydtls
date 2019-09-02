cmake_minimum_required(VERSION 3.5)

add_executable(dtls-server dtls-server.c)
target_link_libraries(dtls-server LINK_PUBLIC tinydtls)
target_compile_options(dtls-server PUBLIC -DTEST_INCLUDE -DDTLSv12 -DWITH_SHA256)

add_executable(ccm-test ccm-test.c)
target_link_libraries(ccm-test LINK_PUBLIC tinydtls)
target_compile_options(ccm-test PUBLIC -DTEST_INCLUDE -DDTLSv12 -DWITH_SHA256)

add_executable(prf-test prf-test.c)
target_link_libraries(prf-test LINK_PUBLIC tinydtls)
target_compile_options(prf-test PUBLIC -DTEST_INCLUDE -DDTLSv12 -DWITH_SHA256)

add_executable(dtls-client dtls-client.c)
target_link_libraries(dtls-client LINK_PUBLIC tinydtls)
target_compile_options(dtls-client PUBLIC -DTEST_INCLUDE -DDTLSv12 -DWITH_SHA256)

