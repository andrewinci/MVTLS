//
//  SSL/TLS Project
//  clientRecord.c
//
//  Created by Darka on 16/12/15.
//  Copyright © 2015 Darka. All rights reserved.
//

#include <stdio.h>
#include "ServerClientRecordProtocol.h"

void onPacketReceive(channel *ch, packet *p);

int main(int argc, const char * argv[]) {
    //setting up the channel
    char *fileName = "channelRecord.txt";
    char *channelFrom = "Client";
    char *channelTo = "Server";
    channel *client = createChannel(fileName, channelFrom, channelTo, CLIENT);
    
    setOnReceive(client, &onPacketReceive);
    //star channel and listener to new message
    startChannel(client);
    printf("*** Record client is start ***\n\n");
    record *r = malloc(sizeof(record));
    r->type = 0x01;
    r->version = 0x0303;
    r->lenght = 0x01;
    r->message = malloc(1);
    *(r->message)='\x31';
    sendRecord(client, r);
    free(r->message);
    free(r);
    waitChannel(client);
    free(client);
}


void onPacketReceive(channel *ch, packet *p){
    
    //get record
    record *r = deserializeRecord(p->message, p->messageLen);
    
    //print received message
    printf("**Basic**\n");
    printf("message from: %s\n", p->from);
    printf("message len: %d\n", p->messageLen);
    printf("****Record****\n");
    printf("type : %02x\n",r->type);
    printf("version : %04x\n",r->version);
    printf("record message:\n%.*s\n",r->lenght, r->message);
    printf("hex : \n");
    for(int i=0;i<p->messageLen;i++)
        printf("%02x ",*(p->message+i));
    printf("\n");
    
    //prepare new packet to be send
    //if the from field is NULL it will be autofill
    if(*(r->message)<'8'){
        (*(r->message))++;
        
        printf("Sending record:\n");
        unsigned char *message = NULL;
        uint16_t len;
        serializeRecord(r, &message, &len);
        for(int i=0;i<len+5;i++)
            printf("%02x ",*(message+i));
        printf("\n");
        
        if(sendRecord(ch, r))
            printf("\nPacket sent correctly\n\n");
        else printf("\nError in sendPacket\n");
        free(r->message);
        free(r);
    }
    else stopChannel(ch);
    freePacket(p);
}