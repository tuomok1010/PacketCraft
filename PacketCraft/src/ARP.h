#ifndef PC_ARP_H
#define PC_ARP_H

#include "PCHeaders.h"
#include "Packet.h"

enum class ARPType
{
    ARP_REQUEST,
    ARP_REPLY
};

namespace PacketCraft
{
    class ARPPacket : public Packet
    {
        public:
        ARPPacket();
        ~ARPPacket();

        int Create(const ether_addr& srcMAC, const ether_addr& dstMAC, const sockaddr_in& srcIP, const sockaddr_in& dstIP, ARPType type);
        int Create(const char* srcMACStr, const char* dstMACStr, const char* srcIPStr, const char* dstIPStr, ARPType type);
        int Send(const int socket, const char* interfaceName) const;
        void ResetPacketBuffer();
        int PrintPacketData() const;

        int ProcessReceivedPacket(uint8_t* packet, int layerSize = 0, unsigned short protocol = PC_PROTO_ETH) override;
        void FreePacket() override;

        EthHeader* ethHeader;
        ARPHeader* arpHeader;
    };
}

#endif