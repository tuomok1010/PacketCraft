#include "PacketFilterQueue.h"
#include "Utils.h"
#include "NetworkUtils.h"

#include <stdlib.h>
#include <poll.h>
#include <netinet/ip.h>
#include <linux/netfilter.h>
#include <iostream>

 static int nfq_send_verdict(int queue_num, uint32_t id, mnl_socket* nl, pkt_buff* pkBuff, int verdict = NF_ACCEPT)
 {
    char buf[MNL_SOCKET_BUFFER_SIZE];
    nlmsghdr* nlh;
    nlattr* nest;

    nlh = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, queue_num);

    if(pktb_mangled(pkBuff))
    {
        /*
        std::cout << "packet after mangling:" << std::endl;
        uint8_t* networkHeader = pktb_network_header(pkBuff);
        uint8_t* transportHeader = pktb_transport_header(pkBuff);
        if(networkHeader)
        {
            PacketCraft::PrintIPv4Layer((IPv4Header*)networkHeader);
            if(transportHeader)
            {
                if(((IPv4Header*)networkHeader)->ip_p == IPPROTO_TCP)
                    PacketCraft::PrintTCPLayer((TCPHeader*)transportHeader);
                else if(((IPv4Header*)networkHeader)->ip_p == IPPROTO_UDP)
                    PacketCraft::PrintUDPLayer((UDPHeader*)transportHeader);
            }
        }
        */
        nfq_nlmsg_verdict_put_pkt(nlh, pktb_data(pkBuff), pktb_len(pkBuff));
    }

    nfq_nlmsg_verdict_put(nlh, id, verdict);

    /* example to set the connmark. First, start NFQA_CT section: */
    nest = mnl_attr_nest_start(nlh, NFQA_CT);
    /* then, add the connmark attribute: */
    mnl_attr_put_u32(nlh, CTA_MARK, htonl(42));
    /* more conntrack attributes, e.g. CTA_LABELS could be set here */
    /* end conntrack section */

    mnl_attr_nest_end(nlh, nest);

    if(mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) 
    {
        LOG_ERROR(APPLICATION_ERROR, "mnl_socket_sendto() error");
        return APPLICATION_ERROR;
    }

    return NO_ERROR;
 }

static int queueCallback(const nlmsghdr *nlh, void *data)
{
    PacketCraft::NetfilterCallbackData callbackData = *(PacketCraft::NetfilterCallbackData*)data;
    nfqnl_msg_packet_hdr* ph{nullptr};
    nlattr* attr[NFQA_MAX + 1]{};
    nfgenmsg*nfg{nullptr};

    if(nfq_nlmsg_parse(nlh, attr) < 0) 
    {
        LOG_ERROR(APPLICATION_ERROR, "nfq_nlmsg_parse() error");
        return MNL_CB_ERROR;
    }

    nfg = (nfgenmsg*)mnl_nlmsg_get_payload(nlh);
    if(nfg == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "mnl_nlmsg_get_payload() error");
        return MNL_CB_ERROR;
    }

    if(attr[NFQA_PACKET_HDR] == NULL) 
    {
        LOG_ERROR(APPLICATION_ERROR, "metaheader not set");
        return MNL_CB_ERROR;
    }

    ph = (nfqnl_msg_packet_hdr*)mnl_attr_get_payload(attr[NFQA_PACKET_HDR]);
    if(ph == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "mnl_attr_get_payload() NFQA_PACKET_HDR error");
        return MNL_CB_ERROR;
    }

    uint16_t plen = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);
    uint8_t* payload = (uint8_t*)mnl_attr_get_payload(attr[NFQA_PAYLOAD]);

    if(payload == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "mnl_attr_get_payload() NFQA_PAYLOAD error");
        return MNL_CB_ERROR;
    }

    uint32_t af{};
    if(ntohs(ph->hw_protocol) == ETH_P_IP)
        af = AF_INET;
    else if(ntohs(ph->hw_protocol) == ETH_P_IPV6)
        af = AF_INET6;
    else
    {
        // do something?
    }

    pkt_buff* pkBuff = pktb_alloc(af, payload, plen, 4'096);
    if(pkBuff == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "pktb_alloc() error");
        return MNL_CB_ERROR;
    }

    // printf("packet received (id=%u hw=0x%04x hook=%u, payload len %u\n",
    //         ntohl(ph->packet_id), ntohs(ph->hw_protocol), ph->hook, plen);

    uint8_t* pkData = pktb_data(pkBuff);

    uint32_t proto{};
    switch(ntohs(ph->hw_protocol))
    {
        case ETH_P_IP:      proto = PC_IPV4; break;
        case ETH_P_IPV6:    proto = PC_IPV6; break;
        case ETH_P_ARP:     proto = PC_ARP;  break;
    }

    uint32_t verdict = NF_ACCEPT;
    // if PacketCraft::Packet doesn't support the received packet, we will just accept it and return no error
    if(callbackData.packet->ProcessReceivedPacket(pkData, 0, proto) == APPLICATION_ERROR)
    {
        if(nfq_send_verdict(ntohs(nfg->res_id), ntohl(ph->packet_id), callbackData.nl, pkBuff, NF_ACCEPT) == APPLICATION_ERROR)
        {
            callbackData.packet->ResetPacketBuffer();
            LOG_ERROR(APPLICATION_ERROR, "nfq_send_verdict() error");
            return MNL_CB_ERROR;
        }

        callbackData.packet->ResetPacketBuffer();
        // LOG_ERROR(APPLICATION_ERROR, "PacketCraft::ProcessReceivedPacket() error!");
        return MNL_CB_OK;
    }

    if(callbackData.filterPacketFunc != nullptr)
    {
        if(callbackData.filterPacketFunc(*callbackData.packet, callbackData.filterPacketFuncData) == TRUE)
        {
            verdict = callbackData.onFilterSuccess == PacketCraft::FilterPacketPolicy::PC_ACCEPT ? NF_ACCEPT : NF_DROP;      
            if(callbackData.editPacketFunc != nullptr)
            {
                if(callbackData.editPacketFunc(*callbackData.packet, callbackData.editPacketFuncData) == APPLICATION_ERROR)
                {
                    if(nfq_send_verdict(ntohs(nfg->res_id), ntohl(ph->packet_id), callbackData.nl, pkBuff, verdict) == APPLICATION_ERROR)
                    {
                        callbackData.packet->ResetPacketBuffer();
                        LOG_ERROR(APPLICATION_ERROR, "nfq_send_verdict() error");
                        return MNL_CB_ERROR;
                    }

                    callbackData.packet->ResetPacketBuffer();
                    LOG_ERROR(APPLICATION_ERROR, "editPacketFunc() error!");
                    return MNL_CB_ERROR;
                }
                callbackData.packet->CalculateChecksums();
                /*
                std::cout << "packet before mangling:" << std::endl;
                uint8_t* networkHeader = pktb_network_header(pkBuff);
                uint8_t* transportHeader = pktb_transport_header(pkBuff);

                if(networkHeader)
                {
                    PacketCraft::PrintIPv4Layer((IPv4Header*)networkHeader);
                    if(transportHeader)
                    {
                        if(((IPv4Header*)networkHeader)->ip_p == IPPROTO_TCP)
                            PacketCraft::PrintTCPLayer((TCPHeader*)transportHeader);
                        else if(((IPv4Header*)networkHeader)->ip_p == IPPROTO_UDP)
                            PacketCraft::PrintUDPLayer((UDPHeader*)transportHeader);
                    }
                }
                */
                int dataOffset = 0;
                uint8_t* macHeader = pktb_mac_header(pkBuff); // check if ethernet header is present (pktb was created in family AF_BRIDGE)
                if(macHeader)
                    dataOffset = -ETH_HLEN;

                // TODO IMPORTANT: if mac header exists, do we need to add ETH_HLEN to plen??
                if(pktb_mangle(pkBuff, dataOffset, 0, plen, (char*)callbackData.packet->GetData(), callbackData.packet->GetSizeInBytes()) == 0)
                {
                    if(nfq_send_verdict(ntohs(nfg->res_id), ntohl(ph->packet_id), callbackData.nl, pkBuff, verdict) == APPLICATION_ERROR)
                    {
                        callbackData.packet->ResetPacketBuffer();
                        LOG_ERROR(APPLICATION_ERROR, "nfq_send_verdict() error");
                        return MNL_CB_ERROR;
                    }

                    callbackData.packet->ResetPacketBuffer();
                    LOG_ERROR(APPLICATION_ERROR, "pktb_mangle() error!");
                    return MNL_CB_ERROR;
                }
            }      
        }
        else
        {
            verdict = callbackData.onFilterFail == PacketCraft::FilterPacketPolicy::PC_ACCEPT ? NF_ACCEPT : NF_DROP;
        }
    }

    if(nfq_send_verdict(ntohs(nfg->res_id), ntohl(ph->packet_id), callbackData.nl, pkBuff, verdict) == APPLICATION_ERROR)
    {
        callbackData.packet->ResetPacketBuffer();
        LOG_ERROR(APPLICATION_ERROR, "nfq_send_verdict() error");
        return MNL_CB_ERROR;
    }

    callbackData.packet->ResetPacketBuffer();
    return MNL_CB_OK;
}

PacketCraft::PacketFilterQueue::PacketFilterQueue(PacketCraft::Packet* packet, const uint32_t queueNum, const uint32_t af, FilterPacketFunc filterPacketFunc,
    EditPacketFunc editPacketFunc, FilterPacketPolicy onFilterSuccess, FilterPacketPolicy onFilterFail, void* filterPacketFuncData, void* editPacketFuncData)
{
    this->queueNum = queueNum;
    this->af = af;
    this->callbackData.packet = packet;
    this->callbackData.editPacketFunc = editPacketFunc;
    this->callbackData.filterPacketFunc = filterPacketFunc;
    this->callbackData.onFilterSuccess = onFilterSuccess;
    this->callbackData.onFilterFail = onFilterFail;
    this->callbackData.editPacketFuncData = editPacketFuncData;
    this->callbackData.filterPacketFuncData = filterPacketFuncData;
}

PacketCraft::PacketFilterQueue::~PacketFilterQueue()
{

}

int PacketCraft::PacketFilterQueue::Run()
{
    /*
        TODO: could we use the PacketCraft::Packet buffer instead of allocating a new one here?
    */
    char* buffer{nullptr};
    nlmsghdr* nlh{nullptr};

    /* largest possible packet payload, plus netlink data overhead: */
    size_t bufferSize = 0xffff + (MNL_SOCKET_BUFFER_SIZE/2);
    int res;
    callbackData.nl = mnl_socket_open(NETLINK_NETFILTER);

    if(callbackData.nl == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "mnl_socket_open() error");
        return APPLICATION_ERROR;
    }

    if(mnl_socket_bind(callbackData.nl, 0, MNL_SOCKET_AUTOPID) < 0)
    {
        mnl_socket_close(callbackData.nl);
        LOG_ERROR(APPLICATION_ERROR, "mnl_socket_bind() error");
        return APPLICATION_ERROR;
    }

    portId = mnl_socket_get_portid(callbackData.nl);
    buffer = (char*)malloc(bufferSize);

    if(!buffer) 
    {
        mnl_socket_close(callbackData.nl);
        LOG_ERROR(APPLICATION_ERROR, "malloc() error");
        return APPLICATION_ERROR;
    }

    nlh = nfq_nlmsg_put(buffer, NFQNL_MSG_CONFIG, queueNum);

    if(nlh == nullptr)
    {
        mnl_socket_close(callbackData.nl);
        free(buffer);
        LOG_ERROR(APPLICATION_ERROR, "nfq_nlmsg_put() error");
        return APPLICATION_ERROR;
    }

    nfq_nlmsg_cfg_put_cmd(nlh, this->af, NFQNL_CFG_CMD_BIND);

    if(mnl_socket_sendto(callbackData.nl, nlh, nlh->nlmsg_len) < 0) 
    {
        mnl_socket_close(callbackData.nl);
        free(buffer);
        LOG_ERROR(APPLICATION_ERROR, "mnl_socket_sendto() error");
        return APPLICATION_ERROR;
    }

    nlh = nfq_nlmsg_put(buffer, NFQNL_MSG_CONFIG, queueNum);
    if(nlh == nullptr)
    {
        mnl_socket_close(callbackData.nl);
        free(buffer);
        LOG_ERROR(APPLICATION_ERROR, "nfq_nlmsg_put() error");
        return APPLICATION_ERROR;
    }

    nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, IP_MAXPACKET);
    mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
    mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO));

    if(mnl_socket_sendto(callbackData.nl, nlh, nlh->nlmsg_len) < 0) 
    {
        mnl_socket_close(callbackData.nl);
        free(buffer);
        LOG_ERROR(APPLICATION_ERROR, "mnl_socket_sendto() error");
        return APPLICATION_ERROR;
    }

    /* ENOBUFS is signalled to userspace when packets were lost
    * on kernel side.  In most cases, userspace isn't interested
    * in this information, so turn it off.
    */
    res = 1;
    mnl_socket_setsockopt(callbackData.nl, NETLINK_NO_ENOBUFS, &res, sizeof(int));

    if(Queue(callbackData.nl, buffer, bufferSize) == APPLICATION_ERROR)
    {
        mnl_socket_close(callbackData.nl);
        free(buffer);
        LOG_ERROR(APPLICATION_ERROR, "PacketCraft::PacketFilterQueue::Queue() error!");
        return APPLICATION_ERROR;
    }

    mnl_socket_close(callbackData.nl);
    free(buffer);
    return NO_ERROR;
}

int PacketCraft::PacketFilterQueue::Queue(mnl_socket* nl, char* packetBuffer, size_t packetBufferSize)
{
    pollfd pollFds[2]{-1, -1};
    pollFds[0].fd = 0;
    pollFds[0].events = POLLIN;
    pollFds[1].fd = mnl_socket_get_fd(nl);
    pollFds[1].events = POLLIN;

    for(;;)
    {
        int nEvents = poll(pollFds, sizeof(pollFds) / sizeof(pollFds[0]), -1);
        if(nEvents == -1)
        {
            LOG_ERROR(APPLICATION_ERROR, "poll() error");
            return APPLICATION_ERROR;
        }

        else if(pollFds[1].revents & POLLIN) // we have a packet in the queue
        {
            int res = mnl_socket_recvfrom(nl, packetBuffer, packetBufferSize);
            if (res == -1) 
            {
                LOG_ERROR(APPLICATION_ERROR, "mnl_socket_recvfrom() error");
                return APPLICATION_ERROR;
            }

            res = mnl_cb_run(packetBuffer, res, 0, portId, queueCallback, &callbackData);
            if (res < 0)
            {
                LOG_ERROR(APPLICATION_ERROR, "mnl_cb_run() error");
                return APPLICATION_ERROR;
            }
        }
        else if(pollFds[0].revents & POLLIN) // user hit a key and wants to quit program
        {
            break;
        }
        else
        {
            LOG_ERROR(APPLICATION_ERROR, "unknown poll() error!");
            return APPLICATION_ERROR;
        }
    }

    return NO_ERROR;
}