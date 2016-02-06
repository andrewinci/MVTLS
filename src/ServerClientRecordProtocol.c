/**
 *	SSL/TLS Project
 *	\file ServerClientRecordProtocol.c
 *	This file is an interface to the record protocol.
 *	Provide function and struct for modelling and manage record messages.
 *
 *	\date Created on 23/12/15.
 *	\copyright Copyright © 2015 Alessandro Melloni, Andrea Francesco Vinci. All rights reserved.
 *
 */

#include "ServerClientRecordProtocol.h"

/**
 * Make a record starting from message, type and tls version.
 *
 *	\param message: the message to incapsulate into the resulting record
 *	\param message_len: the message length
 *	\param r_type: the record type
 *	\param tls_version: the tls version
 *	\return the record that encapsulate h
 */
record_t *make_record(unsigned char *message, uint16_t message_len, record_type r_type, uint16_t tls_version){
    // Make record
    record_t *to_send = malloc(sizeof(record_t));
    to_send->type = r_type;
    to_send->version = tls_version;
    to_send->length = message_len;
    to_send->message = malloc(sizeof(unsigned char)*message_len);
    memcpy(to_send->message, message, message_len);
    
    return to_send;
}

/**
 * Serialize record in a byte stream of length message_len stored in 
 * message.
 *
 *	\param r: record to serialize
 *	\param message: pointer to NULL (the function itself allocates space)
 *	\param messageLen: pointer to integer (will contains the message length)
 */
void serialize_record(record_t *r, unsigned char **message, uint16_t *messageLen){

	*messageLen = r->length;
	uint16_t lenghtRev = REV16(*messageLen);
	*message = calloc((*messageLen)+5, sizeof(unsigned char));
	memcpy(*message, &(r->type), 1);
	memcpy(*message+1, &(r->version), 2);
	memcpy(*message+3, &lenghtRev, 2);
	memcpy(*message+5, r->message, r->length);
	*messageLen+=5;
}

/**
 * De-serialize a byte stream message of length message_len into 
 * a record struct.
 *
 *	\param message: message received
 *	\param messageLen: message length
 *	\return record: the de-serialized record
 */
record_t *deserialize_record(unsigned char *message, uint32_t messageLen){
	record_t *result = malloc(sizeof(record_t));

	result->type = *message;
	memcpy(&(result->version), message+1, 2);
	memcpy(&(result->length), message+3, 2);
	result->length = REV16(result->length);

	result->message = malloc(sizeof(unsigned char)*(result->length));
	memcpy(result->message, message+5, result->length);

	return result;
}

/**
 * Send record to_send over the channel ch.
 * Note: to send record is important to set 'to' and 'from' in the channel creation.
 *
 *	\param ch: channel to use
 *	\param r: record to send
 *	\return 1 if the message was successfully sent, 0 otherwise
 */
int send_record(channel_t *ch, record_t *r){
	unsigned char *message = NULL;
	uint16_t messageLen;
	serialize_record(r, &message, &messageLen);
	packet_transport_t *tosend = create_packet(NULL, NULL, message, messageLen); 
	int result = send_packet(ch, tosend);

	// Clean up
	free(message);
	free_packet(tosend);

	return result;
}

/**
 * Print a description of the record
 *
 *	\param r: record to print.
 */
void print_record(record_t *r){
	unsigned char *message;
	uint16_t len;
	serialize_record(r, &message, &len);
	for (int i = 0; i<len; i++) {
		if(i%9 == 0)
			printf("\n");
		printf("%02x ", message[i]);
	}
	printf("\n");
	free(message);
}

/**
 * Deallocate memory pointed by r
 *
 *  \param r: pointer to record to free
 */
void free_record(record_t *r){
	if(r == NULL)
		return;
	free(r->message);
	free(r);
}
