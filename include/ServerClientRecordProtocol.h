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

#define REV16(value)({(value & 0x00FFU) << 8 | (value & 0xFF00U) >> 8;})

#endif


/*
 * Record types
 */
#ifndef enum_recordtype
#define enum_recordtype

/** \enum record_type 
 *  Define the different type of record
 */
typedef enum{
	HANDSHAKE				= 0x16,
	CHANGE_CIPHER_SPEC	= 0x14,
	ALERT						= 0x15,
	APPLICATION_DATA		= 0x17
}record_type;
#endif

/*
 * Record protocol
 */
#ifndef struct_record
#define struct_record

/**
* \struct record_t
* \brief Record protocol struct
*/
typedef struct{
	/** Record message type  */
	record_type type;

	/** TLS version */
	uint16_t version;

	/** Message to send length */
	uint16_t length;

	/** Message to send*/
	unsigned char *message;
}record_t;
#endif

/**
 * Send record to_send over the channel ch.
 * Note :for send record is important to set 'to' and 'from' in the channel creation.
 *
 * \param ch : channel to use
 * \param to_send  : record to send
 * \return 1 if the message was successfully sent, 0 otherwise
 */
int send_record(channel_t *ch, record_t *to_send);

/**
 * Deserialize a byte stream message of length message_len into 
 * a record struct.
 *
 * \param message : message received
 * \param messageLen : message length
 * \return record : the deserialized record
 */
record_t *deserialize_record(unsigned char *message, uint32_t message_len);

/**
 * Serialize record in a byte stream of length message_len stored in 
 * message.
 *
 * \param message : pointer to null (the function allocate space for you)
 * \param messageLen : pointer to integer (will contains the message length)
 */
void serialize_record(record_t *r, unsigned char **message, uint16_t *message_len);

/**
 * Print a description of the record
 */
void print_record(record_t *r);

/**
 * Free memory for a record r
 * \param r : pointer to record to free
 */
void free_record(record_t *r);
