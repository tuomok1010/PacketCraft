#ifndef PC_DNS_PARSER_H
#define PC_DNS_PARSER_H

#include "PCTypes.h"
#include "PCHeaders.h"

namespace PacketCraft
{
    struct __attribute__((__packed__)) ParsedDNSHeader // NOTE: almost the same as the DNS header in PCHeaders.h
    {
        uint16_t id;
    # if __BYTE_ORDER == __BIG_ENDIAN
        uint16_t qr:1;
        uint16_t opcode:4;
        uint16_t aa:1;
        uint16_t tc:1;
        uint16_t rd:1;
        uint16_t ra:1;
        uint16_t zero:3;
        uint16_t rcode:4;
    # elif __BYTE_ORDER == __LITTLE_ENDIAN
        uint16_t rd:1;
        uint16_t tc:1;
        uint16_t aa:1;
        uint16_t opcode:4;
        uint16_t qr:1;
        uint16_t rcode:4;
        uint16_t zero:3;
        uint16_t ra:1;
    # else
    #  error "Adjust your <bits/endian.h> defines"
    # endif

        uint16_t qcount;	/* question count */
        uint16_t ancount;	/* Answer record count */
        uint16_t nscount;	/* Name Server (Autority Record) Count */ 
        uint16_t adcount;	/* Additional Record Count */
    };

    struct DNSQuestion
    {
        char qName[FQDN_MAX_STR_LEN];
        uint16_t qType;
        uint16_t qClass;
    };

    struct DNSAnswer
    {
        char aName[FQDN_MAX_STR_LEN];
        uint16_t aType;
        uint16_t aClass;
        uint32_t timeToLive;
        uint16_t rLength;
        char rData[FQDN_MAX_STR_LEN];
    };

    class DNSParser
    {
        public:
        DNSParser();

        ~DNSParser();

        // parses data in host byte order, and the domain names in a clear string format, for example: www.google.com
        int Parse(DNSHeader& dnsHeader);

        ParsedDNSHeader header;
        DNSQuestion* questionsArray;
        DNSAnswer* answersArray;

        private:
        void FreeData();
    };
}

#endif