#include "DNSParser.h"
#include "NetworkUtils.h"
#include "Utils.h"

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <arpa/inet.h> 

PacketCraft::DNSParser::DNSParser() :
    header({}),
    questionsArray(nullptr),
    answersArray(nullptr)
{

}

PacketCraft::DNSParser::~DNSParser()
{
    FreeData();
}

void PacketCraft::DNSParser::FreeData()
{
    if(questionsArray != nullptr)
        free(questionsArray);

    if(answersArray != nullptr)
        free(answersArray);

    header.id = 0;
    header.rd = 0;
    header.tc = 0;
    header.aa = 0;
    header.opcode = 0;
    header.qr = 0;
    header.rcode = 0;
    header.zero = 0;
    header.ra = 0;
    header.qcount = 0;
    header.ancount = 0;
    header.nscount = 0;
    header.adcount = 0;
}

int PacketCraft::DNSParser::Parse(DNSHeader& dnsHeader)
{
    FreeData();

    header.id = ntohs(dnsHeader.id);
    header.rd = dnsHeader.rd;
    header.tc = dnsHeader.tc;
    header.aa = dnsHeader.aa;
    header.opcode = dnsHeader.opcode;
    header.qr = dnsHeader.qr;
    header.rcode = dnsHeader.rcode;
    header.zero = dnsHeader.zero;
    header.ra = dnsHeader.ra;
    header.qcount = ntohs(dnsHeader.qcount);
    header.ancount = ntohs(dnsHeader.ancount);
    header.nscount = ntohs(dnsHeader.nscount);
    header.adcount = ntohs(dnsHeader.adcount);

    questionsArray = (DNSQuestion*)malloc(header.qcount * sizeof(DNSQuestion));
    answersArray = (DNSAnswer*)malloc(header.ancount * sizeof(DNSAnswer));

    uint8_t* querySection = dnsHeader.querySection;

    // parse questions
    for(unsigned int i = 0; i < header.qcount; ++i)
    {
        querySection = ParseDomainName(questionsArray[i].qName, querySection, (uint8_t*)&dnsHeader);
        if(querySection == nullptr)
        {
            LOG_ERROR(APPLICATION_ERROR, "ParseDomainName() error!");
            return APPLICATION_ERROR;
        }
    
        questionsArray[i].qType = ntohs(*(uint16_t*)querySection);
        querySection += 2;
        questionsArray[i].qClass = ntohs(*(uint16_t*)querySection);
        querySection += 2; // ptr now points to the answers section
    }

    // parse answers
    for(unsigned int i = 0; i < header.ancount; ++i)
    {
        querySection = ParseDomainName(answersArray[i].aName, querySection, (uint8_t*)&dnsHeader);
        if(querySection == nullptr)
        {
            LOG_ERROR(APPLICATION_ERROR, "ParseDomainName() error!");
            return APPLICATION_ERROR;
        }

        answersArray[i].aType = ntohs(*(uint16_t*)querySection);
        querySection += 2;
        answersArray[i].aClass = ntohs(*(uint16_t*)querySection);
        querySection += 2;
        answersArray[i].timeToLive = ntohl(*(uint32_t*)querySection);
        querySection += 4;
        answersArray[i].rLength = ntohs(*(uint16_t*)querySection);
        querySection += 2;

        if(answersArray[i].aType == 1)
        {
            if(answersArray[i].rLength == IPV4_ALEN)
            {
                if(inet_ntop(AF_INET, querySection, answersArray[i].rData, INET_ADDRSTRLEN) == nullptr)
                {
                    LOG_ERROR(APPLICATION_ERROR, "inet_ntop() error!");
                    return APPLICATION_ERROR;
                }
            }
            else if(answersArray[i].rLength == IPV6_ALEN)
            {
                if(inet_ntop(AF_INET6, querySection, answersArray[i].rData, INET6_ADDRSTRLEN) == nullptr)
                {
                    LOG_ERROR(APPLICATION_ERROR, "inet_ntop() error!");
                    return APPLICATION_ERROR;
                }
            }

            querySection += answersArray[i].rLength;
        }
        else if(answersArray[i].aType == 5)
        {
            querySection = ParseDomainName(answersArray[i].rData, querySection, (uint8_t*)&dnsHeader);
        }
        else
        {
            memcpy(answersArray[i].rData , querySection, answersArray[i].rLength);
            memset(answersArray[i].rData + answersArray[i].rLength, '\0', 1);
            querySection += answersArray[i].rLength;
        }
    }

    return NO_ERROR;
}