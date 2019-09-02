include(CheckIncludeFile)
include(CheckFunctionExists)
include(TestBigEndian)
include(CheckCSourceCompiles)
include(CheckStructHasMember)

check_include_file(assert.h     HAVE_ASSERT_H)
check_include_file(arpa/inet.h  HAVE_ARPA_INET_H)
check_include_file(fcntl.h      HAVE_FCNTL_H)
check_include_file(inttypes.h   HAVE_INTTYPES_H)
check_include_file(memory.h     HAVE_MEMORY_H)
check_include_file(netdb.h      HAVE_NETDB_H)
check_include_file(netinet/in.h HAVE_NETINET_IN_H)
check_include_file(stddef.h     HAVE_STDDEF_H)
check_include_file(stdint.h     HAVE_STDINT_H)
check_include_file(stdlib.h     HAVE_STDLIB_H)
check_include_file(string.h     HAVE_STRING_H)
check_include_file(strings.h    HAVE_STRINGS_H)
check_include_file(time.h       HAVE_TIME_H)
check_include_file(sys/param.h  HAVE_SYS_PARAM_H)
check_include_file(sys/socket.h HAVE_SYS_SOCKET_H)
check_include_file(sys/stat.h   HAVE_SYS_STAT_H)
check_include_file(sys/types.h  HAVE_SYS_TYPES_H)
check_include_file(sys/time.h   HAVE_SYS_TIME_H)
check_include_file(unistd.h     HAVE_UNISTD_H)
check_include_file(float.h      HAVE_FLOAT_H)
check_include_file(dlfcn.h      HAVE_DLFCN_H)

check_function_exists (memset         HAVE_MEMSET)
check_function_exists (select         HAVE_SELECT)
check_function_exists (socket         HAVE_SOCKET)
check_function_exists (strdup         HAVE_STRDUP)
check_function_exists (strerror       HAVE_STRERROR)
check_function_exists (strnlen        HAVE_STRNLEN)
check_function_exists (fls            HAVE_FLS)
check_function_exists (vprintf        HAVE_VPRINTF)

if( ${HAVE_STRING_H} AND ${HAVE_STRINGS_H} AND
    ${HAVE_FLOAT_H} AND ${HAVE_STDLIB_H} AND
    ${HAVE_STDDEF_H} AND ${HAVE_STDINT_H} AND
     ${HAVE_INTTYPES_H} AND ${HAVE_DLFCN_H} )
    set( STDC_HEADERS 1)
endif()

check_struct_has_member (struct sockaddr_in6.sin6_len netinet/in.h HAVE_SOCKADDR_IN6_SIN6_LEN)
TEST_BIG_ENDIAN(IS_BIG_ENDIAN)
if(IS_BIG_ENDIAN)
  set(WORDS_BIGENDIAN 1)
endif()
