#!/bin/bash

Code="../../src/main.cpp ../../src/Utils.cpp ../../NetworkUtils.cpp ../../src/Packet.cpp ../../src/DNSParser.cpp ../../PacketFilterQueue.cpp"

# build object file
cd ../build/rel
g++ -std=c++17 -Wall -D DEBUG_BUILD -fPIC -c -o utils.o ../../src/Utils.cpp
g++ -std=c++17 -Wall -D DEBUG_BUILD -fPIC -c -o network_utils.o ../../src/NetworkUtils.cpp
g++ -std=c++17 -Wall -D DEBUG_BUILD -fPIC -c -o packet.o ../../src/Packet.cpp
g++ -std=c++17 -Wall -D DEBUG_BUILD -fPIC -c -o dnsparser.o ../../src/DNSParser.cpp
g++ -std=c++17 -Wall -D DEBUG_BUILD -fPIC -c -o packetfilterqueue.o ../../src/PacketFilterQueue.cpp

# build shared library
g++ -shared -o ../lib/libpacketcraft.so utils.o network_utils.o packet.o dnsparser.o packetfilterqueue.o -lnetfilter_queue -lmnl

cd ../../src