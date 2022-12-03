#ifndef NETWORK_UTILS_H
#define NETWORK_UTILS_H

#include <unordered_map>

#include "PCTypes.h"

namespace PacketCraft
{
    // used in const char* PacketCraft::ProtoUint32ToStr(uint32_t protocol)
    const static std::unordered_map<uint32_t, const char*> networkProtocols
    {
        {PC_NONE, "NONE"},
        {PC_ETHER_II, "ETHERNET"},
        {PC_ARP, "ARP"},
        {PC_IPV4, "IPV4"},
        {PC_IPV6, "IPV6"},
        {PC_ICMPV4, "ICMPV4"},
        {PC_ICMPV6, "ICMPV6"},
        {PC_TCP, "TCP"},
        {PC_UDP, "UDP"},
        {PC_HTTP_REQUEST, "HTTP_REQUEST"},
        {PC_HTTP_RESPONSE, "HTTP_RESPONSE"},
        {PC_DNS_REQUEST, "DNS_REQUEST"},
        {PC_DNS_RESPONSE, "DNS_RESPONSE"},
        {PC_HTTP_GET, "HTTP_GET"},
        {PC_HTTP_HEAD, "HTTP_HEAD"},
        {PC_HTTP_POST, "HTTP_POST"},
        {PC_HTTP_PUT, "HTTP_PUT"},
        {PC_HTTP_DELETE, "HTTP_DELETE"},
        {PC_HTTP_CONNECT, "HTTP_CONNECT"},
        {PC_HTTP_OPTIONS, "HTTP_OPTIONS"},
        {PC_HTTP_TRACE, "HTTP_TRACE"},
        {PC_HTTP_PATCH, "HTTP_PATCH"},
        {PC_HTTP_INFO, "HTTP_INFO"},
        {PC_HTTP_SUCCESS, "HTTP_SUCCESS"},
        {PC_HTTP_REDIR, "HTTP_REDIR"},
        {PC_HTTP_CLIENT_ERR, "HTTP_CLIENT_ERROR"},
        {PC_HTTP_SERVER_ERR, "HTTP_SERVER_ERROR"}
    };

    const char* ProtoUint32ToStr(uint32_t protocol);
    uint32_t ProtoStrToUint32(const char* protocol);
    uint32_t NetworkProtoToPacketCraftProto(unsigned short networkProtocolInHostByteOrder);

    uint32_t GetTCPDataProtocol(TCPHeader* tcpHeader);
    uint32_t GetUDPDataProtocol(UDPHeader* udpHeader);

    uint32_t GetHTTPMethod(uint8_t* payloadData);

    int GetMACAddr(ether_addr& ethAddr, const char* interfaceName, const int socketFd);
    int GetMACAddr(ether_addr& ethAddr, const int interfaceIndex, const int socketFd);
    int GetMACAddr(char* ethAddrStr, const char* interfaceName, const int socketFd);
    int GetMACAddr(char* ethAddrStr, const int interfaceIndex, const int socketFd);

    int GetIPAddr(sockaddr_in& addr, const char* interfaceName);
    int GetIPAddr(sockaddr_in6& addr, const char* interfaceName);
    int GetIPAddr(sockaddr_storage& addr, const char* interfaceName);
    int GetIPAddr(char* ipAddrStr, const char* interfaceName, const int af);

    int GetNetworkMask(sockaddr_in& mask, const char* interfaceName, const int socketFd);
    int GetNetworkMask(sockaddr_in& mask, const int interfaceIndex, const int socketFd);

    int GetBroadcastAddr(sockaddr_in& broadcastAddr, const char* interfaceName, const int socketFd);
    int GetBroadcastAddr(sockaddr_in& broadcastAddr, const int interfaceIndex, const int socketFd);

    int GetNetworkAddr(sockaddr_in& networkAddr, const sockaddr_in& broadcastAddr, const int nHostBits);
    int GetNetworkAddr(sockaddr_in& networkAddr, const char* interfaceName, const int socketFd);
    int GetNetworkAddr(sockaddr_in& networkAddr, const int interfaceIndex, const int socketFd);

    int GetARPTableMACAddr(const int socketFd, const char* interfaceName, const sockaddr_in& ipAddr, ether_addr& macAddr);
    int GetARPTableMACAddr(const int socketFd, const char* interfaceName, const char* ipAddrStr, char* macAddrStr);

    int GetNumHostBits(const sockaddr_in& networkMask);
    int GetNumHostBits(int& nBits, const char* interfaceName, const int socketFd);

    int AddAddrToARPTable(const int socketFd, const char* interfaceName, const sockaddr_in& ipAddr, const ether_addr& macAddr);
    int AddAddrToARPTable(const int socketFd, const char* interfaceName, const char* ipAddrStr, const char* macAddrStr);

    int RemoveAddrFromARPTable(const int socketFd, const char* interfaceName, const sockaddr_in& ipToRemove);
    int RemoveAddrFromARPTable(const int socketFd, const char* interfaceName, const char* ipToRemoveStr);

    int SetMACAddr(const int socketFd, const char* interfaceName, const ether_addr& newMACAddr);
    int SetMACAddr(const int socketFd, const char* interfaceName, const char* newMACAddrStr);

    // attempts to get the MAC of another device in the network and store it in targetMAC. 
    // If succesfull it adds it to the ARP table. timeOut is in milliseconds, negative means we wait forever
    int GetTargetMACAddr(const int socketFd, const char* interfaceName, const sockaddr_in& targetIP, ether_addr& targetMAC, int timeOut = -1);

    int EnablePortForwarding();
    int DisablePortForwarding();

    uint32_t CalculateICMPv4DataSize(IPv4Header* ipv4Header, ICMPv4Header* icmpv4Header);
    uint32_t CalculateICMPv6DataSize(IPv6Header* ipv6Header, ICMPv6Header* icmpv6Header);

    // TODO: check all the checksum calculation/verifications and make sure they work!
    uint16_t CalculateChecksum(void* data, size_t sizeInBytes);
    bool32 VerifyChecksum(void* data, size_t sizeInBytes);
    //////////////////////////////////////////////////////////////////////////////////////

    // converts a dns name with labels to a domain format
    int DNSNameToDomain(const char* dnsName, char* domainName);

    // converts a domain to a dns name with labels
    int DomainToDNSName(const char* domainName, char* dnsName);

    // Print/Convert to string functions
    int PrintIPAddr(const sockaddr_storage& addr, const char* prefix = "", const char* suffix = "");
    int PrintIPAddr(const sockaddr_in& addr, const char* prefix = "", const char* suffix = "");
    int PrintIPAddr(const sockaddr_in6& addr, const char* prefix = "", const char* suffix = "");
    int PrintMACAddr(const ether_addr& addr, const char* prefix = "", const char* suffix = "");

    int PrintEthernetLayer(EthHeader* ethHeader);
    int PrintARPLayer(ARPHeader* arpHeader);
    int PrintIPv4Layer(IPv4Header* ipv4Header);
    int PrintIPv6Layer(IPv6Header* ipv6Header);
    int PrintICMPv4Layer(ICMPv4Header* icmpv4Header, size_t dataSize = 0);
    int PrintICMPv6Layer(ICMPv6Header* icmpv6Header, size_t dataSize = 0);
    int PrintTCPLayer(TCPHeader* tcpHeader, size_t dataSize = 0);
    int PrintUDPLayer(UDPHeader* udpLayer);

    void PrintLayerTypeStr(const uint32_t layerType, const char* prefix = "", const char* suffix = "");

    int ConvertEthLayerToString(char* buffer, size_t bufferSize, EthHeader* ethHeader);
    int ConvertARPLayerToString(char* buffer, size_t bufferSize, ARPHeader* arpHeader);
    int ConvertIPv4LayerToString(char* buffer, size_t bufferSize, IPv4Header* ipv4Header);
    int ConvertIPv6LayerToString(char* buffer, size_t bufferSize, IPv6Header* ipv6Header);
    int ConvertICMPv4LayerToString(char* buffer, size_t bufferSize, ICMPv4Header* icmpv4Header, size_t icmpv4DataSize = 0);
    int ConvertICMPv6LayerToString(char* buffer, size_t bufferSize, ICMPv6Header* icmpv6Header, size_t icmpv6DataSize = 0);
    int ConvertTCPLayerToString(char* buffer, size_t bufferSize, TCPHeader* tcpHeader);
    int ConvertUDPLayerToString(char* buffer, size_t bufferSize, UDPHeader* udpHeader);
    int ConvertHTTPLayerToString(char* buffer, size_t bufferSize, uint8_t* data, size_t dataSize);
    int ConvertDNSLayerToString(char* buffer, size_t bufferSize, uint8_t* data, size_t dataSize);

    uint8_t* ParseDomainName(char* domainNameStr, uint8_t* domainName, uint8_t* startOfHeader);
    //////////////////////////////////////////////////////////////////////////////////////

}

#endif