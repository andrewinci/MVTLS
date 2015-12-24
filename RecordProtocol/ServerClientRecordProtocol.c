//
//  SSL/TLS Project
//  ServerClientRecordProtocol.c
//
//  Created by Darka on 16/12/15.
//  Copyright © 2015 Darka. All rights reserved.

#include "ServerClientRecordProtocol.h"

void serializeRecord(record *r, unsigned char **message, uint16_t *messageLen){
    *messageLen = r->lenght;
    uint16_t lenghtRev = REV16(*messageLen);
    *message = calloc(*messageLen+5,1);
    memcpy(*message, &(r->type), 1);
    memcpy(*message+1, &(r->version), 2);
    memcpy(*message+3, &lenghtRev, 2);
    memcpy(*message+5, r->message, r->lenght);
}

record *deserializeRecord(unsigned char *message, uint32_t messageLen){
    record *result = malloc(sizeof(record));

    result->type = *message;
    memcpy(&(result->version), message+1, 2);
    memcpy(&(result->lenght), message+3, 2);
    result->lenght = REV16(result->lenght);
    
    result->message = malloc(result->lenght);
    memcpy(result->message, message+5, result->lenght);
    
    return result;
}

int sendRecord(channel *ch, record *r){
    unsigned char *message = NULL;
    uint16_t messageLen;
    serializeRecord(r, &message, &messageLen);
    packet *tosend = createPacket(NULL, NULL, message, messageLen+5); //the basic layer puts automatically 'from' and 'to'
                                                                    //if they are NULL
    int result = sendPacket(ch, tosend);
    freePacket(tosend);
    return result;
}

