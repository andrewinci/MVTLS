//
//  SSL/TLS Project
//  ServerClientRecordProtocol.c
//
//  Created on 23/12/15.
//  Copyright © 2015 Alessandro Melloni, Andrea Francesco Vinci. All rights reserved.
//

#include "ServerClientRecordProtocol.h"

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

void free_record(record_t *r){
	if(r == NULL)
		return;
	free(r->message);
	free(r);
}
