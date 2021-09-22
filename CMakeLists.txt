cmake_minimum_required(VERSION 3.1)

if (WIN32)
#set(CMAKE_GENERATOR_PLATFORM x86)
# visual studio version check
endif (WIN32)
set(CMAKE_BUILD_TYPE Release)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
project(pcap-example C CXX)

set(PCAP_ROOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/deps/WpdPack")
find_package(PCAP REQUIRED)

message(STATUS "pcap include " ${PCAP_INCLUDE_DIR})
message(STATUS "pcap lib " ${PCAP_LIBRARY})

include_directories(SYSTEM ${PCAP_INCLUDE_DIR})
if (WIN32)
add_definitions(-D_WINSOCK_DEPRECATED_NO_WARNINGS)
endif (WIN32)

add_executable(step1-1 src/step1/example1.cpp)
target_link_libraries(step1-1 ${PCAP_LIBRARY} ws2_32.lib)
if (WIN32)
target_link_libraries(step1-1 ws2_32.lib)
endif()