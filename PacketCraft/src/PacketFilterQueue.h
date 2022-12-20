#ifndef PC_PACKETFILTERQUEUE_H
#define PC_PACKETFILTERQUEUE_H

#include "PCHeaders.h"
#include "Packet.h"

extern "C"
{
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/pktbuff.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv6.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/libnetfilter_queue_udp.h>
#include <libmnl/libmnl.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
}

/*
    a user defined callback function that returns either true or false. user can filter for packets
    and if a packet matches the filter conditions (returns true) the packet will go to the EditPacketFunc
    where it can be edited.
*/
typedef bool32 (*FilterPacketFunc)(const PacketCraft::Packet& packet, void* data);

/*
    a user defined callback function where packets that have succesfully gone through the FilterPacketFunc can
    be edited.
*/
typedef uint32_t (*EditPacketFunc)(PacketCraft::Packet& packet, void* data);

namespace PacketCraft
{
    enum FilterPacketPolicy
    {
        PC_DROP,
        PC_ACCEPT
    };

    struct NetfilterCallbackData
    {
        Packet* packet;
        FilterPacketFunc filterPacketFunc;
        EditPacketFunc editPacketFunc;
        FilterPacketPolicy onFilterSuccess;
        FilterPacketPolicy onFilterFail;
        mnl_socket* nl;
        void* filterPacketFuncData;
        void* editPacketFuncData;

    };

    class PacketFilterQueue
    {

        public:

        PacketFilterQueue(PacketCraft::Packet* packet, const uint32_t queueNum, const uint32_t af, FilterPacketFunc filterPacketFunc = nullptr, 
            EditPacketFunc editPacketFunc = nullptr, FilterPacketPolicy onFilterSuccess = PC_ACCEPT, FilterPacketPolicy onFilterFail = PC_ACCEPT,
            void* filterPacketFuncData = nullptr, void* editPacketFuncData = nullptr);
        ~PacketFilterQueue();
        int Run();

        private:
        int Queue(mnl_socket* nl, char* packetBuffer, size_t packetBufferSize);

        uint32_t af; // address family (AF_INET/AF_INET6)
        uint32_t queueNum;
        uint32_t portId;
        nfq_handle* handler;
        nfq_q_handle* queue;
        NetfilterCallbackData callbackData;
    };
}

#endif