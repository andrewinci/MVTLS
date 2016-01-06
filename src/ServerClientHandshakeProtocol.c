//
//  SSL/TLS Project
//  ServerClientHandshakeProtocol.h
//
//  Created on 24/12/15.
//  Copyright © 2015 Mello, Darka. All rights reserved.
//

#include "ServerClientHandshakeProtocol.h"

const int RSA_IDS_NUM = 28;
const uint16_t RSA_IDS[] = {0x0001, 0x0002, 0x0004, 0x0005, 0x0007, 0x0009, 0x000A, 0x002E, 0x002F, 0x0035, 0x003B, 0x003C, 0x003D, 0x0041, 0x0084, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x009C, 0x009D, 0x00AC, 0x00AD, 0x00B6, 0x00B7, 0x00B8, 0x00B9
};

const int DH_DSS_IDS_NUM = 12;
const uint16_t DH_DSS_IDS[] = {0x000B, 0x000C, 0x000D, 0x0030, 0x0036, 0x003E, 0x0042, 0x0068, 0x0085, 0x0097, 0x00A4, 0x00A5
};

const int DH_RSA_IDS_NUM = 12;
const uint16_t DH_RSA_IDS[] = {0x000E, 0x000F, 0x0010, 0x0031, 0x0037, 0x003F, 0x0043, 0x0069, 0x0086, 0x0098, 0x00A0, 0x00A1
};

int send_handshake(channel *ch, handshake *h){
    unsigned char *message = NULL;
    uint32_t messageLen = 0;
    serialize_handshake(h, &message, &messageLen);
    
    //make record
    record *to_send = malloc(sizeof(record));
    to_send->type = HANDSHAKE;
    to_send->version = SSL3_0;
    to_send->lenght = messageLen;
    to_send->message = message;
    
    int result = send_record(ch, to_send);
    //free(message);
    free_record(to_send);
    return result;
}

void serialize_handshake(handshake *h, unsigned char **stream, uint32_t *streamLen){
    unsigned char *buff = malloc(h->length+6);
    *stream = buff;
    *buff = h->type;
    buff++;
    
    uint32_t len = REV32(h->length)>>8;
    memcpy(buff, &len, 3);
    buff+=3;
    
    memcpy(buff, h->message, h->length);
    
    *streamLen = h->length+6;
}

handshake *deserialize_handshake(unsigned char *message, uint32_t messageLen){
    handshake *h = malloc(sizeof(handshake));
    h->type = *message;
    message++;
    
    uint32_t len;
    memcpy(&len, message, 3);
    len = REV32(len)>>8;
    h->length = len;
    message+=3;
    
	h->message = malloc(h->length);
	memcpy(h->message,message,h->length);
    return h;
}

void free_handshake(handshake *h){
	if(h==NULL)
		return;
	free(h->message);
	free(h);
}

void print_handshake(handshake *h){
    printf("\n***Handshake***\n");
    printf("Type : %d\n", h->type);
    printf("Length : %d\n", h->length);
    printf("Message : \n");
    for(int i =0 ; i<h->length;i++){
        printf("%02x ",*(h->message+i));
    }
}


    
key_exchange_algorithm get_kx_algorithm(uint16_t cipher_suite_Id){
    for(int i=0;i<DH_RSA_IDS_NUM;i++)
        if(DH_RSA_IDS[i]==cipher_suite_Id)
            return DH_RSA_KX;
    
    for(int i=0;i<RSA_IDS_NUM;i++)
        if(RSA_IDS[i]==cipher_suite_Id)
            return RSA_KX;

    for(int i=0;i<DH_DSS_IDS_NUM;i++)
        if(DH_DSS_IDS[i]==cipher_suite_Id)
            return DH_DSS_KX;

    return 0;
}

