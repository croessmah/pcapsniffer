cmake_minimum_required(VERSION 3.5)

project(pcapsniffer LANGUAGES C)

if(WINPCAP_ROOT)
    message(STATUS "WINPCAP_ROOT = ${WINPCAP_ROOT}" )
else()
    message(FATAL_ERROR "You must set WINPCAP_ROOT variable" )
endif()


#sniffer
set(SNIFFER_TARGET sniffer)
set(SNIFFER_SOURCES "sniffer.c")
set(SNIFFER_HEADERS "sniffer.h")
add_library(${SNIFFER_TARGET} SHARED ${SNIFFER_SOURCES} ${SNIFFER_HEADERS})
target_compile_definitions(${SNIFFER_TARGET} PRIVATE WPCAP HAVE_REMOTE BUILDING_SNIFFER_LIBRARY)
target_include_directories(${SNIFFER_TARGET} PRIVATE "${WINPCAP_ROOT}/Include")
target_link_directories(${SNIFFER_TARGET} PRIVATE "${WINPCAP_ROOT}/Lib")
target_link_libraries(${SNIFFER_TARGET} PRIVATE wpcap ws2_32)
