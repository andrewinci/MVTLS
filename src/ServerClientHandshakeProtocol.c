//
//  SSL/TLS Project
//  ServerClientHandshakeProtocol.h
//
//  Created on 24/12/15.
//  Copyright © 2015 Mello, Darka. All rights reserved.
//

#include "ServerClientHandshakeProtocol.h"

record_t *make_record(handshake_t *h) {
    unsigned char *message = NULL;
    uint32_t messageLen = 0;
    serialize_handshake(h, &message, &messageLen);
    
    //make record
    record_t *to_send = malloc(sizeof(record_t));
    to_send->type = HANDSHAKE;
    to_send->version = TLS1_2;
    to_send->length = messageLen;
    to_send->message = message;
    return to_send;
}

int send_handshake(channel_t *ch, handshake_t *h){
    record_t *to_send;
    to_send = make_record(h);
    
    int result = send_record(ch, to_send);
    //free(message);
    free_record(to_send);
    return result;
}

void serialize_handshake(handshake_t *h, unsigned char **stream, uint32_t *streamLen){
    unsigned char *buff = malloc(sizeof(unsigned char)*(h->length+4));
    *stream = buff;
    *buff = h->type;
    buff++;
    
    uint32_t len = REV32(h->length)>>8;
    memcpy(buff, &len, 3);
    buff+=3;
    
    memcpy(buff, h->message, h->length);
    
    *streamLen = h->length+4;
}

handshake_t *deserialize_handshake(unsigned char *message, uint32_t messageLen){
    handshake_t *h = malloc(sizeof(handshake_t));
    h->type = *message;
    message++;
    
    uint32_t len;
    memcpy(&len, message, 3);
    len = REV32(len)>>8;
    h->length = len;
    message+=3;
    
	h->message = malloc(sizeof(unsigned char)*(h->length));
	memcpy(h->message,message,h->length);
    return h;
}

void free_handshake(handshake_t *h){
	if(h==NULL)
		return;
	free(h->message);
	free(h);
}

void print_handshake(handshake_t *h){
    unsigned char *message = NULL;
    uint32_t messageLen = 0;
    serialize_handshake(h, &message, &messageLen);
    for(int i=0; i<messageLen; i++){
        if(i%9 == 0)
            printf("\n");
        printf("%02x ", message[i]);
    }
    printf("\n");
    free(message);
}