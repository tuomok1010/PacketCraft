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

namespace PacketCraft
{
    enum FilterPacketPolicy
    {
        PC_DROP,
        PC_ACCEPT
    };

    struct NetfilterCallbackData
    {
        bool (*filterPacketFunc)(const PacketCraft::Packet& packet);
        int (*editPacketFunc)(PacketCraft::Packet& packet);
        FilterPacketPolicy onFilterSuccess;
        FilterPacketPolicy onFilterFail;
        mnl_socket* nl;
    };

    class PacketFilterQueue
    {
        public:
        PacketFilterQueue();
        ~PacketFilterQueue();

        int Init(const uint32_t queueNum, const uint32_t af, 
            bool (*filterPacketFunc)(const PacketCraft::Packet& packet) = nullptr, int (*editPacketFunc)(PacketCraft::Packet& packet) = nullptr, 
            FilterPacketPolicy onFilterSuccess = PC_ACCEPT, FilterPacketPolicy onFilterFail = PC_ACCEPT);

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