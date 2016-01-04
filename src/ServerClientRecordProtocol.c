//
//  SSL/TLS Project
//  ServerClientRecordProtocol.c
//
//  Created on 23/12/15.
//  Copyright © 2015 Mello, Darka. All rights reserved.
//

#include "ServerClientRecordProtocol.h"

void serialize_record(record *r, unsigned char **message, uint16_t *messageLen){
    *messageLen = r->lenght;
    uint16_t lenghtRev = REV16(*messageLen);
    *message = calloc((*messageLen)+5,1);
    memcpy(*message, &(r->type), 1);
    memcpy(*message+1, &(r->version), 2);
    memcpy(*message+3, &lenghtRev, 2);
    memcpy(*message+5, r->message, r->lenght);
}

record *deserialize_record(unsigned char *message, uint32_t messageLen){
    record *result = malloc(sizeof(record));

    result->type = *message;
    memcpy(&(result->version), message+1, 2);
    memcpy(&(result->lenght), message+3, 2);
    result->lenght = REV16(result->lenght);
    
    result->message = malloc(result->lenght);
    memcpy(result->message, message+5, result->lenght);
    
    return result;
}

int send_record(channel *ch, record *r){
    unsigned char *message = NULL;
    uint16_t messageLen;
    serialize_record(r, &message, &messageLen);
    packet_basic *tosend = create_packet(NULL, NULL, message, messageLen+5); //the basic layer puts automatically 'from' and 'to'
                                                                    //if they are NULL
    int result = send_packet(ch, tosend);
	free(message);
    free_packet(tosend);
    return result;
}

void print_record(record r){
    printf("\n***RECORD***\n");
    printf("Type : %d\n",r.type);
    printf("Version : %d\n",r.version);
    printf("Length : %d\n", r.lenght);
    printf("Message : \n");
    for(int i = 0;i<r.lenght;i++)
        printf("%02x ", *(r.message+i));
    
}

void free_record(record *r){
	if(r==NULL)
		return;
	free(r->message);
	free(r);
}