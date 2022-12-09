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
    std::cout << "in queueCallback" << std::endl;

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

    uint32_t af{0};
    if(ntohs(ph->hw_protocol) == ETH_P_IP)
        af = AF_INET;
    else if(ntohs(ph->hw_protocol) == ETH_P_IPV6)
        af = AF_INET6;
    else if(ntohs(ph->hw_protocol) == ETH_P_ARP)
        af = AF_INET;

    pkt_buff* pkBuff = pktb_alloc(af, payload, plen, 4'096);
    if(pkBuff == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "pktb_alloc() error");
        return MNL_CB_ERROR;
    }
    
    printf("packet received (id=%u hw=0x%04x hook=%u, payload len %u\n",
            ntohl(ph->packet_id), ntohs(ph->hw_protocol), ph->hook, plen);

    uint8_t* pkData = pktb_data(pkBuff);

    uint32_t proto{};
    switch(ntohs(ph->hw_protocol))
    {
        case ETH_P_IP:      proto = PC_IPV4; break;
        case ETH_P_IPV6:    proto = PC_IPV6; break;
        case ETH_P_ARP:     proto = PC_ARP;  break;
    }

    PacketCraft::Packet packet;
    if(packet.ProcessReceivedPacket(pkData, 0, proto) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "ProcessReceivedPacket() error!");
    }
    if(packet.Print() == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "Print() error!");
    }
    
    if(nfq_send_verdict(ntohs(nfg->res_id), ntohl(ph->packet_id), (mnl_socket*)data, pkBuff) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "nfq_send_verdict() error");
        return MNL_CB_ERROR;
    }

    return MNL_CB_OK;
}

PacketCraft::PacketFilterQueue::PacketFilterQueue(const uint32_t queueNum, const uint32_t ipVersion) :
    ipVersion(ipVersion),
    queueNum(queueNum)
{

}

PacketCraft::PacketFilterQueue::~PacketFilterQueue()
{

}

int PacketCraft::PacketFilterQueue::Init()
{
    char* buffer{nullptr};
    nlmsghdr* nlh{nullptr};

    /* largest possible packet payload, plus netlink data overhead: */
    size_t bufferSize = 0xffff + (MNL_SOCKET_BUFFER_SIZE/2);
    int res;

    nl = mnl_socket_open(NETLINK_NETFILTER);
    // nl = mnl_socket_open(NETLINK_ROUTE);

    if(nl == nullptr)
    {
        LOG_ERROR(APPLICATION_ERROR, "mnl_socket_open() error");
        return APPLICATION_ERROR;
    }


    if(mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) 
    {
        mnl_socket_close(nl);
        LOG_ERROR(APPLICATION_ERROR, "mnl_socket_bind() error");
        return APPLICATION_ERROR;
    }

    portId = mnl_socket_get_portid(nl);

    buffer = (char*)malloc(bufferSize);
    if(!buffer) 
    {
        mnl_socket_close(nl);
        LOG_ERROR(APPLICATION_ERROR, "malloc() error");
        return APPLICATION_ERROR;
    }

    nlh = nfq_nlmsg_put(buffer, NFQNL_MSG_CONFIG, queueNum);
    if(nlh == nullptr)
    {
        mnl_socket_close(nl);
        free(buffer);
        LOG_ERROR(APPLICATION_ERROR, "nfq_nlmsg_put() error");
        return APPLICATION_ERROR;
    }

    nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_BIND);

    if(mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) 
    {
        mnl_socket_close(nl);
        free(buffer);
        LOG_ERROR(APPLICATION_ERROR, "mnl_socket_sendto() error");
        return APPLICATION_ERROR;
    }
 
    nlh = nfq_nlmsg_put(buffer, NFQNL_MSG_CONFIG, queueNum);
    if(nlh == nullptr)
    {
        mnl_socket_close(nl);
        free(buffer);
        LOG_ERROR(APPLICATION_ERROR, "nfq_nlmsg_put() error");
        return APPLICATION_ERROR;
    }

    nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, IP_MAXPACKET);
    mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
    mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO));

    if(mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) 
    {
        mnl_socket_close(nl);
        free(buffer);
        LOG_ERROR(APPLICATION_ERROR, "mnl_socket_sendto() error");
        return APPLICATION_ERROR;
    }

    /* ENOBUFS is signalled to userspace when packets were lost
    * on kernel side.  In most cases, userspace isn't interested
    * in this information, so turn it off.
    */
    res = 1;
    mnl_socket_setsockopt(nl, NETLINK_NO_ENOBUFS, &res, sizeof(int));

    pollfd pollFds[2]{-1, -1};
    pollFds[0].fd = 0;
    pollFds[0].events = POLLIN;
    pollFds[1].fd = mnl_socket_get_fd(nl);
    pollFds[1].events = POLLIN;

    std::cout << "mnl socket created. polling..." << std::endl;

    for(;;)
    {
        int nEvents = poll(pollFds, sizeof(pollFds) / sizeof(pollFds[0]), -1);

        if(nEvents == -1)
        {
            mnl_socket_close(nl);
            free(buffer);
            LOG_ERROR(APPLICATION_ERROR, "poll() error");
            return APPLICATION_ERROR;
        }
        else if(pollFds[1].revents & POLLIN) // we have a packet in the queue
        {
            std::cout << "packet in queue" << std::endl;
            res = mnl_socket_recvfrom(nl, buffer, bufferSize);
            if (res == -1) 
            {
                mnl_socket_close(nl);
                free(buffer);
                LOG_ERROR(APPLICATION_ERROR, "mnl_socket_recvfrom() error");
                return APPLICATION_ERROR;
            }
            
            res = mnl_cb_run(buffer, res, 0, portId, queueCallback, nl);
            if (res < 0)
            {
                mnl_socket_close(nl);
                free(buffer);
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
            mnl_socket_close(nl);
            free(buffer);
            LOG_ERROR(APPLICATION_ERROR, "unknown poll() error!");
            return APPLICATION_ERROR;
        }
    }


    mnl_socket_close(nl);
    free(buffer);
    return NO_ERROR;
}