#ifndef PC_DEFINES_H
#define PC_DEFINES_H

#include <sys/types.h>
#include <stdint.h>

#define IPV4_ALEN 4
#define IPV6_ALEN 16

#define FQDN_MAX_STR_LEN                255

// used when allocating buffers for printing different kinds of packet layers. Check PrintUDPLayer() in NetworkUtils for example
#define PC_ETH_MAX_STR_SIZE             4'096
#define PC_ARP_MAX_STR_SIZE             4'096
#define PC_IPV4_MAX_STR_SIZE            4'096
#define PC_IPV6_MAX_STR_SIZE            4'096
#define PC_ICMPV4_MAX_STR_SIZE          4'096
#define PC_ICMPV6_MAX_STR_SIZE          4'096
#define PC_TCP_MAX_STR_SIZE             32'768
#define PC_UDP_MAX_STR_SIZE             32'768
////////////////////////////////////////////////////

// used when converting packet layers into strings. Check ConvertUDPLayerToString in NetworkUtils for example
#define PC_ICMPV4_MAX_DATA_STR_SIZE     4'096
#define PC_IPV4_MAX_OPTIONS_STR_SIZE    4'096
#define PC_ICMPV6_MAX_DATA_STR_SIZE     4'096
#define PC_TCP_MAX_OPTIONS_STR_SIZE     4'096
#define PC_TCP_MAX_DATA_STR_SIZE        32'768
#define PC_UDP_MAX_DATA_STR_SIZE        32'768
#define PC_DNS_MAX_DATA_STR_SIZE        32'768
#define PC_DNS_MAX_Q_SECTION_STR_SIZE   4'096
////////////////////////////////////////////////////



/*
    NOTE: PacketCraft::Packet layer types. These are the link/internet/transport layers that PacketCraft supports.
    If you add new ones, remember to update the networkProtocols variable in NetworkUtils.h
*/

// NOTE: used as the default protocol in PacketCraft::Packet::ProcessReceivedPacket
#define PC_PROTO_ETH        UINT16_MAX

// Supported link/internet layer protocols, used mostly in PacketCraft::Packet class
#define PC_NONE             0x0000
#define PC_ETHER_II         0x0001
#define PC_ARP              0x0002
#define PC_IPV4             0x0003
#define PC_IPV6             0x0004

// Supported payload protocols, used mostly in PacketCraft::Packet class
#define PC_ICMPV4           0x0005
#define PC_ICMPV6           0x0006
#define PC_TCP              0x0007
#define PC_TCP_OPTIONS      0x0008
#define PC_UDP              0x0009

// Supported application layer protocols, used mostly in PacketCraft::Packet class
#define PC_HTTP_REQUEST     0x000a
#define PC_HTTP_RESPONSE    0x000b
#define PC_DNS_REQUEST      0x000c
#define PC_DNS_RESPONSE     0x000d
/////////////////////////////////////////////////////

// Supported HTTP methods, used in NetworkUtils GetHTTPMethod()
#define PC_HTTP_GET         0x000e
#define PC_HTTP_HEAD        0x000f
#define PC_HTTP_POST        0x0010
#define PC_HTTP_PUT         0x0011
#define PC_HTTP_DELETE      0x0012
#define PC_HTTP_CONNECT     0x0013
#define PC_HTTP_OPTIONS     0x0014
#define PC_HTTP_TRACE       0x0015
#define PC_HTTP_PATCH       0x0016

#define PC_HTTP_INFO        0x0017
#define PC_HTTP_SUCCESS     0x0018
#define PC_HTTP_REDIR       0x0019
#define PC_HTTP_CLIENT_ERR  0x001a
#define PC_HTTP_SERVER_ERR  0x001b
/////////////////////////////////////////////////////

#define PC_MAX_LAYERS       10

#define TRUE                1
#define FALSE               0

#define NO_ERROR            0
#define APPLICATION_ERROR   1
#define APPLICATION_WARNING 2

#define ETH_ADDR_STR_LEN    18

typedef int32_t bool32;

enum class PingType
{
    ECHO_REQUEST,
    ECHO_REPLY
};

enum class IPVersion
{
    NONE,
    IPV4,
    IPV6
};

struct ether_addr;
struct sockaddr_in;
struct sockaddr_in6;
struct sockaddr_storage;
struct sockaddr;

struct EthHeader;
struct ARPHeader;
struct IPv4Header;
struct IPv4OptionsHeader;
struct IPv6Header;
struct ICMPv4Header;
struct ICMPv6Header;
struct TCPHeader;
struct UDPHeader;
struct DNSHeader;
struct TCPv4PseudoHeader;
struct TCPv6PseudoHeader;
struct UDPv4PseudoHeader;
struct UDPv6PseudoHeader;

#endif