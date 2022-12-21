#include "Packet.h"
#include "Utils.h"
#include "NetworkUtils.h"
#include "PCHeaders.h"

#include <iostream>
#include <fstream>

#include <cstdlib>
#include <cstring>
#include <poll.h>

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <arpa/inet.h>

PacketCraft::Packet::Packet():
    data(nullptr),
    start(nullptr),
    end(nullptr),
    sizeInBytes(0),
    nLayers(0)
{
    for(int i = 0; i < PC_MAX_LAYERS; ++i)
    {
        layerInfos[i].type = PC_NONE;
        layerInfos[i].sizeInBytes = 0;
        layerInfos[i].start = nullptr;
        layerInfos[i].end = nullptr;
    }

    data = malloc(PC_MAX_PACKET_SIZE);
    start = (uint8_t*)data;
    end = (uint8_t*)data;
    memset(data, 0, PC_MAX_PACKET_SIZE);

    printBuffer = (char*)malloc(PRINT_BUFFER_SIZE);
    memset(printBuffer, '\0', PRINT_BUFFER_SIZE);
}

PacketCraft::Packet::Packet(const Packet& packet)
{
    *this = packet; // works because we have an overloaded '=' operator
}

PacketCraft::Packet::~Packet()
{
    FreePacket();
    free(printBuffer);
}

void PacketCraft::Packet::operator = (const Packet& packet)
{
    this->data = malloc(PC_MAX_PACKET_SIZE);
    this->sizeInBytes = packet.sizeInBytes;
    this->nLayers = packet.nLayers;
    this->start = (uint8_t*)data;
    this->end = (uint8_t*)data + sizeInBytes;

    memcpy(this->data, packet.data, packet.sizeInBytes);
    this->printBuffer = (char*)malloc(PRINT_BUFFER_SIZE);
    memset(this->printBuffer, '\0', PRINT_BUFFER_SIZE);

    uint8_t* dataPtr = (uint8_t*)this->data;
    for(unsigned int i = 0; i < packet.nLayers; ++i)
    {
        this->layerInfos[i].start = dataPtr;
        dataPtr += packet.layerInfos[i].sizeInBytes;
        this->layerInfos[i].end = dataPtr;
        this->layerInfos[i].sizeInBytes = packet.layerInfos[i].sizeInBytes;
        this->layerInfos[i].type = packet.layerInfos[i].type;
    }
}

int PacketCraft::Packet::AddLayer(const uint32_t layerType, const size_t layerSize)
{
    size_t newDataSize = layerSize + sizeInBytes;
    
    start = (uint8_t*)data;
    end = (uint8_t*)data + newDataSize;

    layerInfos[nLayers].start = (uint8_t*)end - layerSize;
    layerInfos[nLayers].end = (uint8_t*) end;
    layerInfos[nLayers].sizeInBytes = layerSize;
    layerInfos[nLayers].type = layerType;

    sizeInBytes += layerSize;
    ++nLayers;

    return NO_ERROR;
}

// TODO: TEST
void PacketCraft::Packet::DeleteLayer(const uint32_t layerIndex)
{
    uint8_t* newData = (uint8_t*)malloc(PC_MAX_PACKET_SIZE);
    LayerInfo newLayerInfos[PC_MAX_LAYERS];
    uint32_t newSizeInBytes{0};
    uint32_t newNLayers{0};

    start = newData;
    end = newData;

    for(unsigned int i = 0, j = 0; i < nLayers; ++i)
    {
        if(i == layerIndex)
        {
            layerInfos[i].start = nullptr;
            layerInfos[i].end = nullptr;
            layerInfos[i].type = PC_NONE;
            layerInfos[i].sizeInBytes = 0;
            continue;
        }

        memcpy(end, layerInfos[i].start, layerInfos[i].sizeInBytes);
        newLayerInfos[j].start = end;
        newLayerInfos[j].type = layerInfos[i].type;
        newLayerInfos[j].sizeInBytes = layerInfos[i].sizeInBytes;


        end += layerInfos[i].sizeInBytes;
        newLayerInfos[j].end = end;
        newSizeInBytes += layerInfos[i].sizeInBytes;
        ++newNLayers;
        ++j;

        layerInfos[i].start = nullptr;
        layerInfos[i].end = nullptr;
        layerInfos[i].type = PC_NONE;
        layerInfos[i].sizeInBytes = 0;
    }

    for(unsigned int i = 0; i < newNLayers; ++i)
    {
        layerInfos[i].start = newLayerInfos[i].start;
        layerInfos[i].end = newLayerInfos[i].end;
        layerInfos[i].type = newLayerInfos[i].type;
        layerInfos[i].sizeInBytes = newLayerInfos[i].sizeInBytes;
    }

    free(data);
    data = newData;
    nLayers = newNLayers;
    sizeInBytes = newSizeInBytes;
}

int PacketCraft::Packet::Send(const int socket, const char* interfaceName, const int flags) const
{
    int ifIndex = if_nametoindex(interfaceName);
    if(ifIndex == 0)
    {
        // LOG_ERROR(APPLICATION_ERROR, "if_nametoindex() error!");
        return APPLICATION_ERROR;
    }

    EthHeader* ethHeader = (EthHeader*)FindLayerByType(PC_ETHER_II);
    if(ethHeader == nullptr)
    {
        // LOG_ERROR(APPLICATION_ERROR, "EthHeader not found");
        return APPLICATION_ERROR;
    }

    sockaddr_ll sockAddr{};
    sockAddr.sll_family = PF_PACKET;
    sockAddr.sll_protocol = ethHeader->ether_type;
    sockAddr.sll_ifindex = ifIndex;
    sockAddr.sll_halen = ETH_ALEN;
    sockAddr.sll_hatype = htons(ARPHRD_ETHER);
    memcpy(sockAddr.sll_addr, ethHeader->ether_shost, ETH_ALEN);

    int bytesSent{};
    bytesSent = sendto(socket, data, sizeInBytes, flags, (sockaddr*)&sockAddr, sizeof(sockAddr));
    // std::cout << "bytes sent: " << bytesSent << std::endl;
    if(bytesSent != sizeInBytes)
    {
        // LOG_ERROR(APPLICATION_ERROR, "sendto() error!");
        return APPLICATION_ERROR;
    }

    return NO_ERROR;
}

int PacketCraft::Packet::Receive(const int socketFd, const int flags, int waitTimeoutMS)
{
    // uint8_t* packet = (uint8_t*)malloc(IP_MAXPACKET);
    sockaddr fromInfo{};
    socklen_t fromInfoLen{sizeof(fromInfo)};

    pollfd pollFds[1]{};
    pollFds[0].fd = socketFd;
    pollFds[0].events = POLLIN;

    int bytesReceived{};

    int nEvents = poll(pollFds, sizeof(pollFds) / sizeof(pollFds[0]), waitTimeoutMS);
    if(nEvents == -1)
    {
        //free(packet);
        // LOG_ERROR(APPLICATION_ERROR, "poll() error!");
        return APPLICATION_ERROR;
    }
    else if(nEvents == 0)
    {
        //free(packet);
        // LOG_ERROR(APPLICATION_ERROR, "poll() timed out.");
        return APPLICATION_ERROR;
    }
    else if(pollFds[0].revents & POLLIN)
    {
        ResetPacketBuffer();
        bytesReceived = recvfrom(socketFd, data, IP_MAXPACKET, flags, &fromInfo, &fromInfoLen);
        if(bytesReceived == -1)
        {
            //free(packet);
            // LOG_ERROR(APPLICATION_ERROR, "recvfrom() error!");
            return APPLICATION_ERROR;
        }
        else if(bytesReceived == 0)
        {
            //free(packet);
            // LOG_ERROR(APPLICATION_ERROR, "0 bytes received error!");
            return APPLICATION_ERROR;
        }
        else
        {
            if(ProcessReceivedPacket((uint8_t*)data, 0) == APPLICATION_ERROR)
            {
                //free(packet);
                // LOG_ERROR(APPLICATION_ERROR, "ProcessReceivedPacket() error!");
                return APPLICATION_ERROR;
            }
            else
            {
                //free(packet);
                return NO_ERROR;
            }
        }
    }

    //free(packet);
    // LOG_ERROR(APPLICATION_ERROR, "unknown error!");
    return APPLICATION_ERROR;
}

void* PacketCraft::Packet::FindLayerByType(const uint32_t layerType) const
{
    for(unsigned int i = 0; i < nLayers; ++i)
    {
        if(layerInfos[i].type == layerType)
            return layerInfos[i].start;
    }

    return nullptr;
}

int32_t PacketCraft::Packet::FindIndexByType(const uint32_t layerType) const
{
    for(unsigned int i = 0; i < nLayers; ++i)
    {
        if(layerInfos[i].type == layerType)
            return i;
    }

    return -1;
}

void PacketCraft::Packet::CalculateChecksums()
{
    for(unsigned int i = 0; i < nLayers; ++i)
    {
        switch(layerInfos[i].type)
        {
            case PC_IPV4:
            {
                std::cout << "calculating ipv4 checksum" << std::endl;
                IPv4Header* ipv4Header = (IPv4Header*)GetLayerStart(i);
                ipv4Header->ip_sum = 0;
                ipv4Header->ip_sum = CalculateChecksum(ipv4Header, ipv4Header->ip_hl * 4);
                break;
            }
            case PC_ICMPV4:
            {
                std::cout << "calculating icmpv4 checksum" << std::endl;
                ICMPv4Header* icmpv4Header = (ICMPv4Header*)GetLayerStart(i);
                icmpv4Header->checksum = 0;
                icmpv4Header->checksum = CalculateChecksum(icmpv4Header, GetLayerSize(i));
                break;
            }
            case PC_ICMPV6:
            {
                std::cout << "calculating icmpv6 checksum" << std::endl;
                IPv6Header* ipv6Header = (IPv6Header*)FindLayerByType(PC_IPV6);
                ICMPv6Header* icmpv6Header = (ICMPv6Header*)GetLayerStart(i);
                icmpv6Header->icmp6_cksum = 0;

                ICMPv6PseudoHeader pseudoHeader;
                memcpy(pseudoHeader.ip6_src.__in6_u.__u6_addr8, ipv6Header->ip6_src.__in6_u.__u6_addr8, IPV6_ALEN);
                memcpy(pseudoHeader.ip6_dst.__in6_u.__u6_addr8, ipv6Header->ip6_dst.__in6_u.__u6_addr8, IPV6_ALEN);
                pseudoHeader.payloadLength = htonl(GetLayerSize(i));
                memset(pseudoHeader.zeroes, 0, 3);
                pseudoHeader.nextHeader = 58;

                size_t dataSize = sizeof(pseudoHeader) + GetLayerSize(i);
                uint8_t* data = (uint8_t*)malloc(dataSize);
                memcpy(data, &pseudoHeader, sizeof(pseudoHeader));
                memcpy(data + sizeof(pseudoHeader), icmpv6Header, GetLayerSize(i));

                icmpv6Header->icmp6_cksum = CalculateChecksum(data, dataSize);
                free(data);

                break;
            }
            case PC_UDP:
            {
                IPv4Header* ipv4Header = (IPv4Header*)FindLayerByType(PC_IPV4);
                IPv6Header* ipv6Header = (IPv6Header*)FindLayerByType(PC_IPV6);
                UDPHeader* udpHeader = (UDPHeader*)GetLayerStart(i);
                udpHeader->check = 0;

                if(ipv4Header != nullptr)
                {
                    std::cout << "calculating udpv4 checksum" << std::endl;
                    UDPv4PseudoHeader pseudoHeader;
                    memcpy(&pseudoHeader.ip_src.s_addr, &ipv4Header->ip_src.s_addr, IPV4_ALEN);
                    memcpy(&pseudoHeader.ip_dst.s_addr, &ipv4Header->ip_dst.s_addr, IPV4_ALEN);
                    pseudoHeader.zeroes = 0;
                    pseudoHeader.proto = ipv4Header->ip_p;
                    pseudoHeader.udpLen = udpHeader->len;

                    size_t dataSize = sizeof(pseudoHeader) + ntohs(udpHeader->len);
                    
                    if((ntohs(udpHeader->len) - sizeof(UDPHeader)) % 2 != 0)
                        dataSize += 1;
                        

                    uint8_t* data = (uint8_t*)malloc(dataSize);
                    memset(data, 0, dataSize);
                    memcpy(data, &pseudoHeader, sizeof(pseudoHeader));
                    memcpy(data + sizeof(pseudoHeader), udpHeader, ntohs(udpHeader->len));
        
                    udpHeader->check = CalculateChecksum(data, dataSize);
                    if(ntohs(udpHeader->check) == 0)
                        udpHeader->check = ~0;

                    free(data);
                }
                else if(ipv6Header != nullptr)
                {
                    std::cout << "calculating udpv6 checksum" << std::endl;
                    UDPv6PseudoHeader pseudoHeader;
                    memcpy(pseudoHeader.ip6_src.__in6_u.__u6_addr8, ipv6Header->ip6_src.__in6_u.__u6_addr8, IPV6_ALEN);
                    memcpy(pseudoHeader.ip6_dst.__in6_u.__u6_addr8, ipv6Header->ip6_dst.__in6_u.__u6_addr8, IPV6_ALEN);
                    pseudoHeader.udpLen = udpHeader->len;
                    memset(pseudoHeader.zeroes, 0, 3);
                    pseudoHeader.nextHeader = ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_nxt;

                    size_t dataSize = sizeof(pseudoHeader) + ntohs(udpHeader->len);
                    
                    if((ntohs(udpHeader->len) - sizeof(UDPHeader)) % 2 != 0)
                        dataSize += 1;

                    uint8_t* data = (uint8_t*)malloc(dataSize);
                    memset(data, 0, dataSize);
                    memcpy(data, &pseudoHeader, sizeof(pseudoHeader));
                    memcpy(data + sizeof(pseudoHeader), udpHeader, ntohs(udpHeader->len));

                    udpHeader->check = CalculateChecksum(data, dataSize);
                    if(ntohs(udpHeader->check) == 0)
                        udpHeader->check = ~0;

                    free(data);
                }

                break;
            }
            case PC_TCP: // TODO: TEST
            {
                IPv4Header* ipv4Header = (IPv4Header*)FindLayerByType(PC_IPV4);
                IPv6Header* ipv6Header = (IPv6Header*)FindLayerByType(PC_IPV6);
                TCPHeader* tcpHeader = (TCPHeader*)GetLayerStart(i);
                tcpHeader->check = 0;

                if(ipv4Header != nullptr)
                {
                    std::cout << "calculating tcpv4 checksum" << std::endl;
                    TCPv4PseudoHeader pseudoHeader;
                    memcpy(&pseudoHeader.ip_src.s_addr, &ipv4Header->ip_src.s_addr, IPV4_ALEN);
                    memcpy(&pseudoHeader.ip_dst.s_addr, &ipv4Header->ip_dst.s_addr, IPV4_ALEN);
                    pseudoHeader.zeroes = 0;
                    pseudoHeader.proto = ipv4Header->ip_p;
                    pseudoHeader.tcpLen = htons(ntohs(ipv4Header->ip_len) - (ipv4Header->ip_hl * 32 / 8));

                    size_t dataSize = sizeof(pseudoHeader) + ntohs(pseudoHeader.tcpLen);
                    if(dataSize % 2 != 0)
                        dataSize += 1;

                    uint8_t* data = (uint8_t*)malloc(dataSize);
                    memset(data, 0, dataSize);
                    memcpy(data, &pseudoHeader, sizeof(pseudoHeader));
                    memcpy(data + sizeof(pseudoHeader), tcpHeader, ntohs(pseudoHeader.tcpLen));

                    tcpHeader->check = CalculateChecksum(data, dataSize);
                    free(data);

                }
                else if(ipv6Header != nullptr)
                {
                    std::cout << "calculating tcpv6 checksum" << std::endl;
                    TCPv6PseudoHeader pseudoHeader;
                    memcpy(pseudoHeader.ip6_src.__in6_u.__u6_addr8, ipv6Header->ip6_src.__in6_u.__u6_addr8, IPV6_ALEN);
                    memcpy(pseudoHeader.ip6_dst.__in6_u.__u6_addr8, ipv6Header->ip6_dst.__in6_u.__u6_addr8, IPV6_ALEN);
                    pseudoHeader.tcpLen = htonl(GetLayerSize(i));
                    memset(pseudoHeader.zeroes, 0, 3);
                    pseudoHeader.nextHeader = ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_nxt;

                    size_t dataSize = sizeof(pseudoHeader) + ntohl(pseudoHeader.tcpLen);
                    if(dataSize % 2 != 0)
                        dataSize += 1;

                    uint8_t* data = (uint8_t*)malloc(dataSize);
                    memset(data, 0, dataSize);
                    memcpy(data, &pseudoHeader, sizeof(pseudoHeader));
                    memcpy(data + sizeof(pseudoHeader), tcpHeader, ntohs(pseudoHeader.tcpLen));

                    tcpHeader->check = CalculateChecksum(data, dataSize);
                    free(data);
                }

                break;
            }
        }
    }

    std::cout << "checksums calculated" << std::endl;
}

int PacketCraft::Packet::Print(bool32 printToFile, const char* fullFilePath) const
{
    std::ofstream file;

    if(printToFile == TRUE)
    {
        if(!file.is_open())
            file.open(fullFilePath, std::ofstream::out | std::ofstream::app);
    }

    int layerSize = 0; // next layer size, used to calculate data/options size of payloads
    for(unsigned int i = 0; i < nLayers; ++i)
    {
        uint32_t layerProtocol = GetLayerType(i);
        switch(layerProtocol)
        {
            case PC_ETHER_II:
            {
                EthHeader* ethHeader = (EthHeader*)GetLayerStart(i);
                if(ethHeader == nullptr)
                {
                    if(file.is_open())
                        file.close();

                    memset(printBuffer, '\0', PRINT_BUFFER_SIZE);

                    LOG_ERROR(APPLICATION_ERROR, "ethHeader was null!");
                    return APPLICATION_ERROR;
                }

                if(PacketCraft::ConvertEthLayerToString(printBuffer, PRINT_BUFFER_SIZE, ethHeader) == APPLICATION_ERROR)
                {
                    if(file.is_open())
                        file.close();

                    memset(printBuffer, '\0', PRINT_BUFFER_SIZE);

                    LOG_ERROR(APPLICATION_ERROR, "ConvertEthLayerToString() error!");
                    return APPLICATION_ERROR;
                }

                break;
            }
            case PC_ARP:
            {
                ARPHeader* arpHeader = (ARPHeader*)GetLayerStart(i);
                if(arpHeader == nullptr)
                {
                    if(file.is_open())
                        file.close();

                    memset(printBuffer, '\0', PRINT_BUFFER_SIZE);

                    LOG_ERROR(APPLICATION_ERROR, "arpHeader was null!");
                    return APPLICATION_ERROR;
                }

                if(PacketCraft::ConvertARPLayerToString(printBuffer, PRINT_BUFFER_SIZE, arpHeader) == APPLICATION_ERROR)
                {
                    if(file.is_open())
                        file.close();

                    memset(printBuffer, '\0', PRINT_BUFFER_SIZE);

                    LOG_ERROR(APPLICATION_ERROR, "ConvertARPLayerToString() error!");
                    return APPLICATION_ERROR;
                }

                break;
            }
            case PC_IPV4:
            {
                IPv4Header* ipv4Header = (IPv4Header*)GetLayerStart(i);
                if(ipv4Header == nullptr)
                {
                    if(file.is_open())
                        file.close();

                    memset(printBuffer, '\0', PRINT_BUFFER_SIZE);

                    LOG_ERROR(APPLICATION_ERROR, "ipv4Header was null!");
                    return APPLICATION_ERROR;
                }

                if(PacketCraft::ConvertIPv4LayerToString(printBuffer, PRINT_BUFFER_SIZE, ipv4Header) == APPLICATION_ERROR)
                {
                    if(file.is_open())
                        file.close();

                    memset(printBuffer, '\0', PRINT_BUFFER_SIZE);

                    LOG_ERROR(APPLICATION_ERROR, "ConvertIPv4LayerToString() error!");
                    return APPLICATION_ERROR;
                }

                layerSize = ntohs(ipv4Header->ip_len) - (ipv4Header->ip_hl * 32 / 8);
                if(layerSize < 0)
                    layerSize = 0;

                break;
            }
            case PC_IPV6:
            {
                IPv6Header* ipv6Header = (IPv6Header*)GetLayerStart(i);
                if(ipv6Header == nullptr)
                {
                    if(file.is_open())
                        file.close();

                    memset(printBuffer, '\0', PRINT_BUFFER_SIZE);

                    LOG_ERROR(APPLICATION_ERROR, "ipv6Header was null!");
                    return APPLICATION_ERROR;
                }

                if(PacketCraft::ConvertIPv6LayerToString(printBuffer, PRINT_BUFFER_SIZE, ipv6Header) == APPLICATION_ERROR)
                {
                    if(file.is_open())
                        file.close();

                    memset(printBuffer, '\0', PRINT_BUFFER_SIZE);

                    LOG_ERROR(APPLICATION_ERROR, "ConvertIPv6LayerToString() error!");
                    return APPLICATION_ERROR;
                }

                layerSize = ntohs(ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_plen);
                if(layerSize < 0)
                    layerSize = 0;

                break;
            }
            case PC_ICMPV4:
            {
                ICMPv4Header* icmpv4Header = (ICMPv4Header*)GetLayerStart(i);
                if(icmpv4Header == nullptr)
                {
                    if(file.is_open())
                        file.close();

                    memset(printBuffer, '\0', PRINT_BUFFER_SIZE);

                    LOG_ERROR(APPLICATION_ERROR, "icmpv4Header was null!");
                    return APPLICATION_ERROR;
                }

                int payloadDataSize = layerSize - sizeof(ICMPv4Header);
                if(payloadDataSize < 0)
                    payloadDataSize = 0;

                if(PacketCraft::ConvertICMPv4LayerToString(printBuffer, PRINT_BUFFER_SIZE, icmpv4Header, payloadDataSize) == APPLICATION_ERROR)
                {
                    if(file.is_open())
                        file.close();

                    memset(printBuffer, '\0', PRINT_BUFFER_SIZE);

                    LOG_ERROR(APPLICATION_ERROR, "ConvertICMPv4LayerToString() error!");
                    return APPLICATION_ERROR;
                }

                break;
            }
            case PC_ICMPV6:
            {
                ICMPv6Header* icmpv6Header = (ICMPv6Header*)GetLayerStart(i);
                if(icmpv6Header == nullptr)
                {
                    if(file.is_open())
                        file.close();

                    memset(printBuffer, '\0', PRINT_BUFFER_SIZE);

                    LOG_ERROR(APPLICATION_ERROR, "icmpv6Header was null!");
                    return APPLICATION_ERROR;
                }

                int payloadDataSize = layerSize - sizeof(ICMPv6Header);
                if(payloadDataSize < 0)
                    payloadDataSize = 0;

                if(PacketCraft::ConvertICMPv6LayerToString(printBuffer, PRINT_BUFFER_SIZE, icmpv6Header, payloadDataSize) == APPLICATION_ERROR)
                {
                    if(file.is_open())
                        file.close();

                    memset(printBuffer, '\0', PRINT_BUFFER_SIZE);

                    LOG_ERROR(APPLICATION_ERROR, "ConvertICMPv6LayerToString() error!");
                    return APPLICATION_ERROR;
                }

                break;
            }
            case PC_TCP:
            {
                TCPHeader* tcpHeader = (TCPHeader*)GetLayerStart(i);
                if(tcpHeader == nullptr)
                {
                    if(file.is_open())
                        file.close();

                    memset(printBuffer, '\0', PRINT_BUFFER_SIZE);

                    LOG_ERROR(APPLICATION_ERROR, "tcpHeader was null!");
                    return APPLICATION_ERROR;
                }

                if(PacketCraft::ConvertTCPLayerToString(printBuffer, PRINT_BUFFER_SIZE, tcpHeader) == APPLICATION_ERROR)
                {
                    if(file.is_open())
                        file.close();

                    memset(printBuffer, '\0', PRINT_BUFFER_SIZE);

                    LOG_ERROR(APPLICATION_ERROR, "ConvertTCPLayerToString() error!");
                    return APPLICATION_ERROR;
                }

                break;
            }
            case PC_UDP:
            {
                UDPHeader* udpHeader = (UDPHeader*)GetLayerStart(i);
                if(udpHeader == nullptr)
                {
                    if(file.is_open())
                        file.close();

                    memset(printBuffer, '\0', PRINT_BUFFER_SIZE);

                    LOG_ERROR(APPLICATION_ERROR, "udpHeader was null!");
                    return APPLICATION_ERROR;
                }

                if(PacketCraft::ConvertUDPLayerToString(printBuffer, PRINT_BUFFER_SIZE, udpHeader) == APPLICATION_ERROR)
                {
                    if(file.is_open())
                        file.close();

                    memset(printBuffer, '\0', PRINT_BUFFER_SIZE);

                    LOG_ERROR(APPLICATION_ERROR, "ConvertTCPLayerToString() error!");
                    return APPLICATION_ERROR;
                }

                break;
            }
            case PC_HTTP_RESPONSE:
            case PC_HTTP_REQUEST:
            {
                uint32_t dataSize = GetLayerSize(i);
                uint8_t* data = (uint8_t*)GetLayerStart(i);
                if(data == nullptr)
                {
                    if(file.is_open())
                        file.close();

                    memset(printBuffer, '\0', PRINT_BUFFER_SIZE);

                    LOG_ERROR(APPLICATION_ERROR, "HTTP data was null!");
                    return APPLICATION_ERROR;
                }

                if(PacketCraft::ConvertHTTPLayerToString(printBuffer, PRINT_BUFFER_SIZE, data, dataSize) == APPLICATION_ERROR)
                {
                    if(file.is_open())
                        file.close();

                    memset(printBuffer, '\0', PRINT_BUFFER_SIZE);

                    LOG_ERROR(APPLICATION_ERROR, "ConvertTCPLayerToString() error!");
                    return APPLICATION_ERROR;
                }

                break;
            }
            case PC_DNS_RESPONSE:
            case PC_DNS_REQUEST:
            {
                uint32_t dataSize = GetLayerSize(i);
                uint8_t* data = (uint8_t*)GetLayerStart(i);
                if(data == nullptr)
                {
                    if(file.is_open())
                        file.close();

                    memset(printBuffer, '\0', PRINT_BUFFER_SIZE);

                    LOG_ERROR(APPLICATION_ERROR, "HTTP data was null!");
                    return APPLICATION_ERROR;
                }

                if(ConvertDNSLayerToString(printBuffer, PRINT_BUFFER_SIZE, data, dataSize) == APPLICATION_ERROR)
                {
                    if(file.is_open())
                        file.close();

                    memset(printBuffer, '\0', PRINT_BUFFER_SIZE);

                    LOG_ERROR(APPLICATION_ERROR, "ConvertTCPLayerToString() error!");
                    return APPLICATION_ERROR;
                }

                break;
            }
            default:
            {
                if(file.is_open())
                    file.close();

                memset(printBuffer, '\0', PRINT_BUFFER_SIZE);

                LOG_ERROR(APPLICATION_ERROR, "unknown protocol detected!");
                return APPLICATION_ERROR;
            }
        }

        if(printToFile == TRUE)
            file.write(printBuffer, PacketCraft::GetStrLen(printBuffer));
        else
            std::cout << printBuffer << std::endl;

        memset(printBuffer, '\0', PRINT_BUFFER_SIZE);
    }

    if(file.is_open())
        file.close();

    return NO_ERROR;
}

// TODO: extensive testing! This needs to be bulletproof!!!
int PacketCraft::Packet::ProcessReceivedPacket(uint8_t* packet, int layerSize, unsigned short protocol)
{
    // std::cout << "in ProcessReceivedPacket, protocol is " << protocol << std::endl;
    switch(protocol)
    {
        case PC_PROTO_ETH:
        {
            AddLayer(PC_ETHER_II, ETH_HLEN);
            memcpy(data, packet, ETH_HLEN);
            protocol = NetworkProtoToPacketCraftProto(ntohs(((EthHeader*)packet)->ether_type));
            packet += ETH_HLEN;
            break;
        }
        case PC_ARP:
        {
            AddLayer(PC_ARP, sizeof(ARPHeader));
            memcpy(GetLayerStart(nLayers - 1), packet, sizeof(ARPHeader));
            return NO_ERROR;
        }
        case PC_IPV4:
        {
            IPv4Header* ipHeader = (IPv4Header*)packet;
            AddLayer(PC_IPV4, ipHeader->ip_hl * 4);
            memcpy(GetLayerStart(nLayers - 1), packet, ipHeader->ip_hl * 4);
            protocol = NetworkProtoToPacketCraftProto(ipHeader->ip_p);

            // this is the next layer size (header + data)
            layerSize = ntohs(ipHeader->ip_len) - (ipHeader->ip_hl * 4);
            if(layerSize <= 0)
                return NO_ERROR;

            packet += (uint32_t)ipHeader->ip_hl * 4;
            break;
        }
        case PC_IPV6: // TODO: need to support extension headers!
        {
            IPv6Header* ipv6Header = (IPv6Header*)packet;
            AddLayer(PC_IPV6, sizeof(IPv6Header));
            memcpy(GetLayerStart(nLayers - 1), packet, sizeof(IPv6Header));
            protocol = NetworkProtoToPacketCraftProto(ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_nxt);

            if(protocol == PC_ICMPV6 || protocol == PC_TCP || protocol == PC_UDP)
            {
                layerSize = ntohs(ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_plen);
                if(layerSize < 0)
                    layerSize = 0;
            }

            packet += sizeof(IPv6Header);
            break;
        }
        case PC_ICMPV4:
        {
            AddLayer(PC_ICMPV4, layerSize);
            memcpy(GetLayerStart(nLayers - 1), packet, layerSize);

            return NO_ERROR;
        }
        case PC_ICMPV6: // TODO: TEST!!!
        {
            AddLayer(PC_ICMPV6, layerSize);
            memcpy(GetLayerStart(nLayers - 1), packet, layerSize);

            return NO_ERROR;
        }
        case PC_TCP: // NOTE: this only adds the TCP header and options, data has its own case
        {
            TCPHeader* tcpHeader = (TCPHeader*)packet;
            AddLayer(PC_TCP, tcpHeader->doff * 32 / 8);
            memcpy(GetLayerStart(nLayers - 1), packet, tcpHeader->doff * 32 / 8);

            layerSize = layerSize - (tcpHeader->doff * 32 / 8);
            protocol = GetTCPDataProtocol(tcpHeader);

            if(layerSize <= 0) // if no data is present
                return NO_ERROR;

            packet += tcpHeader->doff * 32 / 8;
            break;
        }
        case PC_UDP: // NOTE: this only adds the UDP header, data has its own case
        {
            UDPHeader* udpHeader = (UDPHeader*)packet;
            AddLayer(PC_UDP, sizeof(UDPHeader));
            memcpy(GetLayerStart(nLayers - 1), packet, sizeof(UDPHeader));

            layerSize = layerSize - sizeof(UDPHeader);
            protocol = GetUDPDataProtocol(udpHeader);

            if(layerSize <= 0)
                return NO_ERROR;

            packet += sizeof(UDPHeader);
            break;
        }
        // PAYLOAD DATA PROTOCOLS:
        case PC_HTTP_REQUEST:
        {
            AddLayer(PC_HTTP_REQUEST, layerSize);
            memcpy(GetLayerStart(nLayers - 1), packet, layerSize);
            return NO_ERROR;
        }
        case PC_HTTP_RESPONSE:
        {
            AddLayer(PC_HTTP_RESPONSE, layerSize);
            memcpy(GetLayerStart(nLayers - 1), packet, layerSize);
            return NO_ERROR;
        }
        case PC_DNS_REQUEST:
        {
            AddLayer(PC_DNS_REQUEST, layerSize);
            memcpy(GetLayerStart(nLayers - 1), packet, layerSize);
            return NO_ERROR;
        }
        case PC_DNS_RESPONSE:
        {
            AddLayer(PC_DNS_RESPONSE, layerSize);
            memcpy(GetLayerStart(nLayers - 1), packet, layerSize);
            return NO_ERROR;
        }
        default:
        {
            ResetPacketBuffer();
            
            // NOTE: for debugging, comment out to reduce spam
            // LOG_ERROR(APPLICATION_ERROR, "unsupported packet layer type received! Packet data cleared.");

            return APPLICATION_ERROR;
        }
    }

    return ProcessReceivedPacket(packet, layerSize, protocol);

}

void PacketCraft::Packet::FreePacket()
{
    if(data && sizeInBytes > 0)
    {
        free(data);
    }

    data = nullptr;
    start = nullptr;
    end = nullptr;
    sizeInBytes = 0;
    nLayers = 0;

    for(int i = 0; i < PC_MAX_LAYERS; ++i)
    {
        layerInfos[i].type = PC_NONE;
        layerInfos[i].sizeInBytes = 0;
        layerInfos[i].start = nullptr;
        layerInfos[i].end = nullptr;
    }
}

void PacketCraft::Packet::ResetPacketBuffer()
{
    if(data)
    {
        memset(data, 0, sizeInBytes);
    }

    start = (uint8_t*)data;
    end = (uint8_t*)data;
    sizeInBytes = 0;
    nLayers = 0;

    for(int i = 0; i < PC_MAX_LAYERS; ++i)
    {
        layerInfos[i].type = PC_NONE;
        layerInfos[i].sizeInBytes = 0;
        layerInfos[i].start = nullptr;
        layerInfos[i].end = nullptr;
    }

    memset(printBuffer, '\0', PRINT_BUFFER_SIZE);
}

void* PacketCraft::Packet::GetLayerStart(const uint32_t layerIndex) const
{
    return layerInfos[layerIndex].start;
}

void* PacketCraft::Packet::GetLayerEnd(const uint32_t layerIndex) const 
{
    return layerInfos[layerIndex].end;
}

uint32_t PacketCraft::Packet::GetLayerType(const uint32_t layerIndex) const
{
    return layerInfos[layerIndex].type;
}

uint32_t PacketCraft::Packet::GetLayerSize(const uint32_t layerIndex) const
{
    return layerInfos[layerIndex].sizeInBytes;
}