//
//  SSL/TLS Project
//  ServerClientRecordProtocol.h
//
//  Created by Darka on 16/12/15.
//  Copyright © 2015 Darka. All rights reserved.

#ifndef ServerClientRecordProtocol_h
#define ServerClientRecordProtocol_h

#include <stdio.h>
#include "../BasicComunication/ServerClientBasic.h"

#define REV32(value)({(value & 0x000000FFU) << 24 | (value & 0x0000FF00U) << 8 |(value & 0x00FF0000U) >> 8 | (value & 0xFF000000U) >> 24;})
#define REV16(value)({(value & 0x00FFU) << 8 | (value & 0xFF00U) >> 8;})

#endif

/*
 * Record protocol
 */
typedef struct record{
    uint8_t type;
    uint16_t version;
    uint16_t lenght;
    unsigned char *message;
}record;

/*
 * Send record through the channel
 * !!!! for send record is important to set 'to' and 'from' in the channel creation!!!!
 *
 * ch : channel to use
 * r  : record to be sent
 * return 1 if the message was successfully sent, 0 otherwise
 */
int sendRecord(channel *ch, record *r);

/*
 * Build a record from the received messsage
 *
 * message : message received
 * messageLen : message length
 * return the built record
 */
record *deserializeRecord(unsigned char *message, uint32_t messageLen);

/*
 * Serialize record in a byte stream
 * message and message length are used for return
 *
 * message : pointer to null (the function allocate space for you)
 * messageLen : pointer to integer (will contains the message length)
 */
void serializeRecord(record *r, unsigned char **message, uint16_t *messageLen);