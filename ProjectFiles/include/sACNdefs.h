#ifndef _SACN_H_
#define _SACN_H_
#include <stdint.h>

struct ACNRootLayer {
    uint8_t preamble_size[2];                 // 0x0010
    uint8_t postamble_size[2];                // 0x0000
    uint8_t  ACNPacketIdentifier[12];         // 0x41 0x53 0x43 0x2d 0x45 0x31 0x2e 0x31 0x37 0x00 0x00 0x00
    uint8_t flags_length[2];                  // 0x7 << 12 || length of PDU
    uint8_t  vector[4];                       // 0x00000004 || 0x00000008 for sync or discovery
    uint8_t  senderCID[16];                   // 16 byte UUID
};

struct ACNDataFramingLayer {
    uint8_t flags_length[2];                  // 0x7 << 12 || length of PDU
    uint8_t vector[4];                        // 0x00000002
    uint8_t  sourceName[64];                  // 64 byte string
    uint8_t  priority;                        // 0x64
    uint8_t syncUniverse[2];                  // 0x0000
    uint8_t  sequenceNumber;                  // 0x00
    uint8_t  options;                         // 0x00
    uint8_t universe[2];                      // 0x0001
};

struct ACNSyncFramingLayer {
    uint8_t flags_length[2];                  // 0x7 << 12 || length of PDU
    uint8_t vector[4];                        // 0x00000001
    uint8_t  sequenceNumber;                  // 0x00
    uint8_t syncUniverse[2];                  // 0x0000
    uint8_t reserved[2];
};

struct ACNDiscoveryFramingLayer {
    uint8_t flags_length[2];                  // 0x7 << 12 || length of PDU
    uint8_t vector[4];                        // 0x00000002
    uint8_t  sourceName[64];                  // 64 byte string
    uint8_t reserved[4];                      // 0x00000000
};

struct ACNDMPLayer {
    uint8_t flags_length[2];                  // 0x7 << 12 || length of PDU
    uint8_t  vector;                          // 0x02
    uint8_t  addressType;                     // 0xa1
    uint8_t firstPropertyAddress[2];          // 0x0000
    uint8_t addressIncrement[2];              // 0x0001
    uint8_t propertyValueCount[2];            // 0x0001 - 0x0201 | 1+ number of slots
    uint8_t  propertyValues[513];             // start code + 512 bytes of data
};

struct ACNDiscoveryLayer {
    uint8_t flags_length[2];                  // 0x7 << 12 || length of PDU
    uint8_t vector[4];                        // 0x00000001
    uint8_t  page;                            // 0x00
    uint8_t  lastPage;                        // 0x00
    uint8_t universes[1024];                  // 0x0000 - 0x03ff
};

struct ACNDataPacket{
    ACNRootLayer rootLayer;
    ACNDataFramingLayer framingLayer;
    ACNDMPLayer dmpLayer;
};

struct ACNSyncPacket{
    ACNRootLayer rootLayer;
    ACNSyncFramingLayer syncFramingLayer;
};

struct ACNDiscoveryPacket{
    ACNRootLayer rootLayer;
    ACNDiscoveryFramingLayer discoveryFramingLayer;
    ACNDiscoveryLayer discoveryLayer;
};



bool validRoot(ACNRootLayer *rootLayer) {
    if (rootLayer->preamble_size[0] != 0x00 || rootLayer->preamble_size[1] != 0x10) {
        return false;
    }
    if (rootLayer->postamble_size[0] != 0x00 || rootLayer->postamble_size[1] != 0x00) {
        return false;
    }
    if (rootLayer->ACNPacketIdentifier[0] != 0x41 || rootLayer->ACNPacketIdentifier[1] != 0x53 || rootLayer->ACNPacketIdentifier[2] != 0x43 || rootLayer->ACNPacketIdentifier[3] != 0x2d || rootLayer->ACNPacketIdentifier[4] != 0x45 || rootLayer->ACNPacketIdentifier[5] != 0x31 || rootLayer->ACNPacketIdentifier[6] != 0x2e || rootLayer->ACNPacketIdentifier[7] != 0x31 || rootLayer->ACNPacketIdentifier[8] != 0x37 || rootLayer->ACNPacketIdentifier[9] != 0x00 || rootLayer->ACNPacketIdentifier[10] != 0x00 || rootLayer->ACNPacketIdentifier[11] != 0x00) {
        return false;
    }
    if (rootLayer->vector[0] != 0x00 || rootLayer->vector[1] != 0x00 || rootLayer->vector[2] != 0x00 || (rootLayer->vector[3] != 0x04 /*&& rootLayer->vector[3] != 0x08*/)) {
        return false;
    }
    return true;
}

#endif

