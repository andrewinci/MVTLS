//
//  SSL/TLS Project
//  ServerClientRecordProtocol.h
//
//  Created on 23/12/15.
//  Copyright © 2015 Mello, Darka. All rights reserved.
//

#ifndef ServerClientRecordProtocol_h
#define ServerClientRecordProtocol_h

#include <stdio.h>
#include "ServerClientBasic.h"

#define REV32(value)({(value & 0x000000FFU) << 24 | (value & 0x0000FF00U) << 8 |(value & 0x00FF0000U) >> 8 | (value & 0xFF000000U) >> 24;})
#define REV16(value)({(value & 0x00FFU) << 8 | (value & 0xFF00U) >> 8;})

#endif


/*
 * Record types
 */
#ifndef enum_recordtype
#define enum_recordtype
typedef enum{
    HANDSHAKE           = 0x16,
    CHANGE_CIPHER_SPEC  = 0x14,
    ALERT               = 0x15,
    APPLICATION_DATA    = 0x17
}recordType;
#endif

/*
 * Record Version
 */
#ifndef enum_record_version
#define enum_record_version
typedef enum{
    SSL3_0 = 0x0300,
    TLS1_0 = 0x0301,
    TLS1_1 = 0x0302,
    TLS1_2 = 0x0303
}recordVersion;
#endif

/*
 * Record protocol
 */
#ifndef struct_record
#define struct_record
typedef struct record{
    uint8_t type;
    uint16_t version;
    uint16_t lenght;
    unsigned char *message;
}record;
#endif

/*
 * Send record through the channel
 * !!!! for send record is important to set 'to' and 'from' in the channel creation!!!!
 *
 * ch : channel to use
 * r  : record to be sent
 * return 1 if the message was successfully sent, 0 otherwise
 */
int send_record(channel *ch, record *r);

/*
 * Build a record from the received messsage
 *
 * message : message received
 * messageLen : message length
 * return the built record
 */
record *deserialize_record(unsigned char *message, uint32_t messageLen);

/*
 * Serialize record in a byte stream
 * message and message length are used for return
 *
 * message : pointer to null (the function allocate space for you)
 * messageLen : pointer to integer (will contains the message length)
 */
void serialize_record(record *r, unsigned char **message, uint16_t *messageLen);

/*
 * Print a description of the record
 */
void print_record(record r);