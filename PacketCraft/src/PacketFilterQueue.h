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

typedef bool32 (*FilterPacketFunc)(const PacketCraft::Packet& packet);
typedef uint32_t (*EditPacketFunc)(PacketCraft::Packet& packet);

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
    };

    class PacketFilterQueue
    {
        public:
        PacketFilterQueue(PacketCraft::Packet& packet, const uint32_t queueNum, const uint32_t af, FilterPacketFunc filterPacketFunc = nullptr, 
            EditPacketFunc editPacketFunc = nullptr, FilterPacketPolicy onFilterSuccess = PC_ACCEPT, FilterPacketPolicy onFilterFail = PC_ACCEPT);
        ~PacketFilterQueue();

        int Init();

        int Queue(mnl_socket* nl, char* packetBuffer, size_t packetBufferSize);

        private:
        uint32_t af; // address family (AF_INET/AF_INET6)
        uint32_t queueNum;
        uint32_t portId;

        nfq_handle* handler;
        nfq_q_handle* queue;

        NetfilterCallbackData callbackData;
    };
}

#endif