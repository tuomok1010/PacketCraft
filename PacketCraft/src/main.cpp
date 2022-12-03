// network stuff
#include <arpa/inet.h>

// packet craft
#include "include/PCInclude.h"


int main(int argc, char** argv)
{
    /*
    // DEST INFO
    const char* dstMACStr = "ff:ff:ff:ff:ff:ff";
    const char* dstIPStr = "10.0.2.4";

    ether_addr dstMAC;
    ether_aton_r(dstMACStr, &dstMAC);

    sockaddr_in dstIP;
    inet_pton(AF_INET, dstIPStr, &dstIP.sin_addr);
    ////////////////////

    int mySocket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if(mySocket < 0)
    {
        LOG_ERROR(APPLICATION_ERROR, "socket() error!");
        return APPLICATION_ERROR;
    }

    ether_addr srcMAC;
    PacketCraft::GetMACAddr(srcMAC, "eth0", mySocket);
    PacketCraft::PrintMACAddr(srcMAC, "source MAC: ", "\n");

    sockaddr_in srcIP;
    PacketCraft::GetIPAddr(srcIP, "eth0");
    PacketCraft::PrintIPAddr(srcIP, "source IP: ", "\n");

    PacketCraft::ARPPacket arpPacket;
    arpPacket.Create(srcMAC, dstMAC, srcIP, dstIP, ARPType::ARP_REQUEST);
    arpPacket.Send(mySocket, "eth0");

    */
    return NO_ERROR;
}

