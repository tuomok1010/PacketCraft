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
    class PacketFilterQueue
    {
        public:
        PacketFilterQueue(const uint32_t queueNum, const uint32_t ipVersion);
        ~PacketFilterQueue();

        int Init();
        int Queue();

        private:
        uint32_t ipVersion;
        uint32_t queueNum;
        uint32_t portId;

        nfq_handle* handler;
        nfq_q_handle* queue;
        mnl_socket *nl;
    };
}

#endif