/**
 *  SSL/TLS Project
 *  \file ServerClientRecordProtocol.h
 *	This file is an interface to the record protocol.
 *	Provide function and struct for modelling and manage record messages.
 *
 *  \date Created on 23/12/15.
 *  \copyright Copyright © 2015 Alessandro Melloni, Andrea Francesco Vinci. All rights reserved.
 *
 */

#ifndef ServerClientRecordProtocol_h
#define ServerClientRecordProtocol_h

#include <stdio.h>
#include "ServerClientTransportProtocol.h"

/**	\def REV16 
*	Rotational byte for uint16
*/
#define REV16(value)({(value & 0x00FFU) << 8 | (value & 0xFF00U) >> 8;})

/** \enum record_type 
 *  Define the different type of record
 */
typedef enum{
	HANDSHAKE				= 0x16,
	CHANGE_CIPHER_SPEC      = 0x14,
	ALERT					= 0x15,
	APPLICATION_DATA		= 0x17
}record_type;

/**
* \struct record_t
* Record protocol struct.
* Model fields of the record messages.	
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
 * De-serialize a byte stream message of length message_len into 
 * a record struct.
 *
 * \param message : message received
 * \param messageLen : message length
 * \return record : the de-serialized record
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
 *	\param r : record to print.
 */
void print_record(record_t *r);

/**
 * Deallocate memory pointed by r
 * \param r : pointer to record to free
 */
void free_record(record_t *r);
