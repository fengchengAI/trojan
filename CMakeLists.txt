cmake_minimum_required(VERSION 3.6)
project(trojan CXX)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0")

#设置这里只是为了检查nlohmann_json，因为本人是用vcpkg安装的，事实上可以直接源码安装。


set(SOURCE_FILES     src/main.cpp)

AUX_SOURCE_DIRECTORY(src/core SOURCE_FILES)
AUX_SOURCE_DIRECTORY(src/proto SOURCE_FILES)
AUX_SOURCE_DIRECTORY(src/session SOURCE_FILES)
AUX_SOURCE_DIRECTORY(src/ssl SOURCE_FILES)
AUX_SOURCE_DIRECTORY(src/icmp SOURCE_FILES)

ADD_EXECUTABLE(trojan ${SOURCE_FILES})
include_directories(src)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(trojan ${CMAKE_THREAD_LIBS_INIT})

find_package(Boost 1.66.0 REQUIRED COMPONENTS system program_options)
include_directories(${Boost_INCLUDE_DIR})
target_link_libraries(trojan ${Boost_LIBRARIES})


set(ENABLE_LOG ON)
if (ENABLE_LOG)
    add_definitions(-DENABLE_LOG)
    set(DEFAULT_LOG_PATH ${PROJECT_SOURCE_DIR}/log/trojan.log CACHE STRING "Default log path")
    message(${DEFAULT_LOG_PATH})
    add_definitions(-DDEFAULT_LOG_PATH="${DEFAULT_LOG_PATH}")
endif ()


find_package(OpenSSL 1.1.0 REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
target_link_libraries(trojan ${OPENSSL_LIBRARIES})
if(OPENSSL_VERSION VERSION_GREATER_EQUAL 1.1.1)
    option(ENABLE_SSL_KEYLOG "Build with SSL KeyLog support" ON)
    if(ENABLE_SSL_KEYLOG)
        add_definitions(-DENABLE_SSL_KEYLOG)
    endif()

    option(ENABLE_TLS13_CIPHERSUITES "Build with TLS1.3 ciphersuites support" ON)
    if(ENABLE_TLS13_CIPHERSUITES)
        add_definitions(-DENABLE_TLS13_CIPHERSUITES)
    endif()
endif()



option(FORCE_TCP_FASTOPEN "Force build with TCP Fast Open support" OFF)
if(FORCE_TCP_FASTOPEN)
    add_definitions(-DTCP_FASTOPEN=23 -DTCP_FASTOPEN_CONNECT=30)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL Linux)
    option(ENABLE_NAT "Build with NAT support" ON)
    if(ENABLE_NAT)
        add_definitions(-DENABLE_NAT)
    endif()

    option(ENABLE_REUSE_PORT "Build with SO_REUSEPORT support" ON)
    if(ENABLE_REUSE_PORT)
        add_definitions(-DENABLE_REUSE_PORT)
    endif()
endif()


set(SYSTEMD_SERVICE AUTO CACHE STRING "Install systemd service")
set_property(CACHE SYSTEMD_SERVICE PROPERTY STRINGS AUTO ON OFF)
set(SYSTEMD_SERVICE_PATH /lib/systemd/system CACHE PATH "Systemd service path")
if(SYSTEMD_SERVICE STREQUAL AUTO)
    if(EXISTS /usr/lib/systemd/system)
        set(SYSTEMD_SERVICE ON)
        set(SYSTEMD_SERVICE_PATH /usr/lib/systemd/system CACHE PATH "Systemd service path" FORCE)
    elseif(EXISTS /lib/systemd/system)
        set(SYSTEMD_SERVICE ON)
        set(SYSTEMD_SERVICE_PATH /lib/systemd/system CACHE PATH "Systemd service path" FORCE)
    endif()
endif()


set(DEFAULT_CONFIG /usr/local/etc/trojan/buy.json CACHE STRING "Default config path")
add_definitions(-DDEFAULT_CONFIG="${DEFAULT_CONFIG}")
