#ifndef PC_PACKET_H
#define PC_PACKET_H

#include <stdint.h>
#include <sys/types.h>

#include "PCTypes.h"

#define PRINT_BUFFER_SIZE (IP_MAXPACKET * 4)

namespace PacketCraft
{
    struct LayerInfo
    {
        uint32_t type;
        size_t sizeInBytes;

        uint8_t* start;
        uint8_t* end;
    };

    class Packet
    {
        public:
        Packet();
        Packet(const Packet& packet);
        ~Packet();

        void operator = (const Packet& packet);

        // Check PCTypes.h for valid layerTypes
        int AddLayer(const uint32_t layerType, const size_t layerSize);
        void DeleteLayer(const uint32_t layerIndex);
        int Send(const int socket, const char* interfaceName, const int flags) const;
        int Receive(const int socketFd, const int flags, int waitTimeoutMS = -1); // negative timeout means we wait forever until a packet is received
        void ResetPacketBuffer();
        void* FindLayerByType(const uint32_t layerType) const;
        void CalculateChecksums();

        // if printToFile is true, prints the packet into a txt file in fullFilePath, otherwise prints it in console
        int Print(bool32 printToFile = FALSE, const char* fullFilePath = "") const;

        void* GetLayerStart(const uint32_t layerIndex) const;
        void* GetLayerEnd(const uint32_t layerIndex) const;
        uint32_t GetLayerType(const uint32_t layerIndex) const;
        uint32_t GetLayerSize(const uint32_t layerIndex) const;

        inline void* GetData() const { return data; }
        inline void* Start() const { return start; }
        inline void* End() const { return end; }
        inline int GetSizeInBytes() const { return sizeInBytes; }
        inline uint32_t GetNLayers() const { return nLayers; }
        
        virtual int ProcessReceivedPacket(uint8_t* packet, int layerSize = 0, unsigned short nextHeader = PC_PROTO_ETH);

        protected:
        virtual void FreePacket();

        /////////////////

        private:
        void* data;
        uint8_t* start;
        uint8_t* end;

        LayerInfo layerInfos[PC_MAX_LAYERS];

        int sizeInBytes;
        uint32_t nLayers;

        char* printBuffer;
    };
}

#endif