#include "ARP.h"
#include "Utils.h"

#include <iostream>

#include <cstring>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netinet/ether.h>

PacketCraft::ARPPacket::ARPPacket():
    ethHeader(nullptr),
    arpHeader(nullptr)
{

}

PacketCraft::ARPPacket::~ARPPacket()
{

}

int PacketCraft::ARPPacket::Create(const ether_addr& srcMAC, const ether_addr& dstMAC, const sockaddr_in& srcIP, const sockaddr_in& dstIP, ARPType type)
{
    ResetPacketBuffer();

    AddLayer(PC_ETHER_II, ETH_HLEN);
    ethHeader = (EthHeader*)GetLayerStart(0);
    memcpy(ethHeader->ether_shost, srcMAC.ether_addr_octet, ETH_ALEN);
    memcpy(ethHeader->ether_dhost, dstMAC.ether_addr_octet, ETH_ALEN);
    ethHeader->ether_type = htons(ETH_P_ARP);

    AddLayer(PC_ARP, sizeof(ARPHeader));
    arpHeader = (ARPHeader*)GetLayerStart(1);
    arpHeader->ar_hrd = htons(ARPHRD_ETHER);
    arpHeader->ar_pro = htons(ETH_P_IP);
    arpHeader->ar_hln = ETH_ALEN;
    arpHeader->ar_pln = IPV4_ALEN;
    arpHeader->ar_op = htons(type == ARPType::ARP_REQUEST ? ARPOP_REQUEST : ARPOP_REPLY);
    memcpy(arpHeader->ar_sha, srcMAC.ether_addr_octet, ETH_ALEN);
    memcpy(arpHeader->ar_sip, &srcIP.sin_addr.s_addr, IPV4_ALEN);
    memcpy(arpHeader->ar_tha, dstMAC.ether_addr_octet, ETH_ALEN);
    memcpy(arpHeader->ar_tip, &dstIP.sin_addr.s_addr, IPV4_ALEN);

    return NO_ERROR;
}

int PacketCraft::ARPPacket::Create(const char* srcMACStr, const char* dstMACStr, const char* srcIPStr, const char* dstIPStr, ARPType type)
{
    ether_addr srcMAC{};
    ether_addr dstMAC{};
    sockaddr_in srcIP{};
    sockaddr_in dstIP{};

    if(ether_aton_r(srcMACStr, &srcMAC) == nullptr)
    {
        // LOG_ERROR(APPLICATION_ERROR, "ether_aton_r() error!");
        return APPLICATION_ERROR;
    }

    if(ether_aton_r(dstMACStr, &dstMAC) == nullptr)
    {
        // LOG_ERROR(APPLICATION_ERROR, "ether_aton_r() error!");
        return APPLICATION_ERROR;
    }

    if(inet_pton(AF_INET, srcIPStr, &srcIP.sin_addr) <= 0)
    {
        // LOG_ERROR(APPLICATION_ERROR, "inet_pton() error!");
        return APPLICATION_ERROR;
    }

    if(inet_pton(AF_INET, dstIPStr, &dstIP.sin_addr) <= 0)
    {
        // LOG_ERROR(APPLICATION_ERROR, "inet_pton() error!");
        return APPLICATION_ERROR;
    }

    return Create(srcMAC, dstMAC, srcIP, dstIP, type);
}

int PacketCraft::ARPPacket::Send(const int socket, const char* interfaceName) const
{
    int ifIndex = if_nametoindex(interfaceName);
    if(ifIndex == 0)
    {
        // LOG_ERROR(APPLICATION_ERROR, "if_nametoindex() error!");
        return APPLICATION_ERROR;
    }

    return Packet::Send(socket, interfaceName, 0);
}

void PacketCraft::ARPPacket::ResetPacketBuffer()
{
    PacketCraft::Packet::ResetPacketBuffer();
    ethHeader = nullptr;
    arpHeader = nullptr;
}

void PacketCraft::ARPPacket::FreePacket()
{
    PacketCraft::Packet::FreePacket();
    ethHeader = nullptr;
    arpHeader = nullptr;
}

int PacketCraft::ARPPacket::PrintPacketData() const
{
    if(ethHeader == nullptr)
    {
        // LOG_ERROR(APPLICATION_ERROR, "ethHeader is null!");
        return APPLICATION_ERROR;
    }
    if(arpHeader == nullptr)
    {
        // LOG_ERROR(APPLICATION_ERROR, "arpHeader is null!");
        return APPLICATION_ERROR;
    }

    char ethDstAddr[ETH_ADDR_STR_LEN]{};    /* destination eth addr	*/
    char ethSrcAddr[ETH_ADDR_STR_LEN]{};    /* source ether addr	*/

    if(ether_ntoa_r((ether_addr*)ethHeader->ether_dhost, ethDstAddr) == nullptr)
    {
        // LOG_ERROR(APPLICATION_ERROR, "ether_ntoa_r() error!");
        return APPLICATION_ERROR;
    }

    if(ether_ntoa_r((ether_addr*)ethHeader->ether_shost, ethSrcAddr) == nullptr)
    {
        // LOG_ERROR(APPLICATION_ERROR, "ether_ntoa_r() error!");
        return APPLICATION_ERROR;
    }

    char ar_sha[ETH_ADDR_STR_LEN]{};    /* Sender hardware address.  */
    char ar_sip[INET_ADDRSTRLEN]{};     /* Sender IP address.  */
    char ar_tha[ETH_ADDR_STR_LEN]{};    /* Target hardware address.  */
    char ar_tip[INET_ADDRSTRLEN]{};     /* Target IP address.  */

    if(inet_ntop(AF_INET, arpHeader->ar_sip, ar_sip, INET_ADDRSTRLEN) == nullptr)
    {
        // LOG_ERROR(APPLICATION_ERROR, "inet_ntop() error!");
        return APPLICATION_ERROR;
    }

    if(inet_ntop(AF_INET, arpHeader->ar_tip, ar_tip, INET_ADDRSTRLEN) == nullptr)
    {
        // LOG_ERROR(APPLICATION_ERROR, "inet_ntop() error!");
        return APPLICATION_ERROR;
    }

    if(ether_ntoa_r((ether_addr*)arpHeader->ar_sha, ar_sha) == nullptr)
    {
        // LOG_ERROR(APPLICATION_ERROR, "ether_ntoa_r() error!");
        return APPLICATION_ERROR;
    }

    if(ether_ntoa_r((ether_addr*)arpHeader->ar_tha, ar_tha) == nullptr)
    {
        // LOG_ERROR(APPLICATION_ERROR, "ether_ntoa_r() error!");
        return APPLICATION_ERROR;
    }

    // TODO: format nicely with iomanip perhaps?
    std::cout
        << " = = = = = = = = = = = = = = = = = = = = \n"
        << "[ETHERNET]:\n"
        << "destination: "          << ethDstAddr << "\n"
        << "source: "               << ethSrcAddr << "\n"
        << "type: "                 << ntohs(ethHeader->ether_type) << "\n"
        << " - - - - - - - - - - - - - - - - - - - - \n"
        << "[ARP]:\n"
        << "hardware type: "        << ntohs(arpHeader->ar_hrd) << "\n"
        << "protocol type: "        << ntohs(arpHeader->ar_pro) << "\n"
        << "hardware size: "        << (uint16_t)arpHeader->ar_hln << "\n"
        << "protocol size: "        << (uint16_t)arpHeader->ar_pln << "\n"
        << "op code: "              << ntohs(arpHeader->ar_op) << " (" << (ntohs(arpHeader->ar_op) == 1 ? "request" : "reply") << ")\n"
        << "sender MAC address: "   << ar_sha << "\n"
        << "sender IP address: "    << ar_sip << "\n"
        << "target MAC address: "   << ar_tha << "\n"
        << "target IP address: "    << ar_tip << "\n"
        << " = = = = = = = = = = = = = = = = = = = = " << std::endl;

    return NO_ERROR;
}

// TODO: extensive testing! This needs to be bulletproof!!!
int PacketCraft::ARPPacket::ProcessReceivedPacket(uint8_t* packet, int layerSize, unsigned short protocol)
{
    switch(protocol)
    {
        case PC_PROTO_ETH:
        {
            AddLayer(PC_ETHER_II, ETH_HLEN);
            memcpy(GetData(), packet, ETH_HLEN);
            protocol = ntohs(((EthHeader*)packet)->ether_type);
            ethHeader = (EthHeader*)GetLayerStart(GetNLayers() - 1);
            packet += ETH_HLEN;
            break;
        }
        case ETH_P_ARP:
        {
            AddLayer(PC_ARP, sizeof(ARPHeader));
            memcpy(GetLayerStart(GetNLayers() - 1), packet, sizeof(ARPHeader));
            arpHeader = (ARPHeader*)GetLayerStart(GetNLayers() - 1);
            return NO_ERROR;
        }
        default:
        {
            ResetPacketBuffer();
            // LOG_ERROR(APPLICATION_ERROR, "unsupported packet layer type received! Packet data cleared.");
            return APPLICATION_ERROR;
        }
    }

    return ProcessReceivedPacket(packet, 0, protocol);

}