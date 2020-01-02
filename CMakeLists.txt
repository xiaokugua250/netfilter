cmake_minimum_required(VERSION 3.13)
project(netfilter C)

set(CMAKE_C_STANDARD 99)

add_executable(netfilter main.c src/netfilter.c src/netfiler_hello.c src/netfilter_print/netfiler_printer.c src/netcap/netcap_device.c src/capnetfiler/capnetfiler.c src/netcap/cap_device.c src/netcap/cap_device_info.c src/netcap/cap_packet_capture.c src/netcap/cap_packet_handler.c)