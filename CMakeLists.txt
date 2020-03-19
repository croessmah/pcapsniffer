cmake_minimum_required(VERSION 3.5)

project(pcapsniffer LANGUAGES C)

set(WINPCAP_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/winpcap")


#sniffer
set(SNIFFER_TARGET sniffer)
set(SNIFFER_SOURCES "sniffer.c")
set(SNIFFER_HEADERS "sniffer.h")
add_library(${SNIFFER_TARGET} SHARED ${SNIFFER_SOURCES} ${SNIFFER_HEADERS})
target_compile_definitions(${SNIFFER_TARGET} PRIVATE WPCAP HAVE_REMOTE BUILDING_SNIFFER_LIBRARY)
target_include_directories(${SNIFFER_TARGET} PUBLIC "${WINPCAP_ROOT}/Include")
target_link_directories(${SNIFFER_TARGET} PUBLIC "${WINPCAP_ROOT}/Lib")
target_link_libraries(${SNIFFER_TARGET} wpcap ws2_32 shlwapi)
set_property(TARGET ${SNIFFER_TARGET} PROPERTY CXX_STANDARD 17)
set_property(TARGET ${SNIFFER_TARGET} PROPERTY CXX_STANDARD_REQUIRED ON)
set_property(TARGET ${SNIFFER_TARGET} PROPERTY CXX_EXTENSIONS OFF)
