//
//  SSL/TLS Project
//  clientRecord.c
//
//  Created on 23/12/15.
//  Copyright © 2015 Mello, Darka. All rights reserved.
//

#include <stdio.h>

#include "ServerClientRecordProtocol.h"

void onPacketReceive(channel *ch, packet_basic *p);

int main(int argc, const char * argv[]) {
    //setting up the channel
    char *fileName = "channelRecord.txt";
    char *channelFrom = "Client";
    char *channelTo = "Server";
    channel *client = create_channel(fileName, channelFrom, channelTo, CLIENT);
    
    set_on_receive(client, &onPacketReceive);
    //star channel and listener to new message
    start_channel(client);
    printf("*** Record client is start ***\n\n");
    
    record *r = malloc(sizeof(record));
    r->type = HANDSHAKE;
    r->version = SSL3_0;
    r->lenght = 0x01;
    r->message = malloc(1);
    *(r->message)='\x31';
    
    send_record(client, r);
    free(r->message);
    free(r);
    wait_channel(client);
    free(client);
}

void onPacketReceive(channel *ch, packet_basic *p){
    
    //get record
    record *r = deserialize_record(p->message, p->messageLen);
    
    //print received message
    printf("**Basic**\n");
    printf("message from: %s\n", p->source);
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
        serialize_record(r, &message, &len);
        for(int i=0;i<len+5;i++)
            printf("%02x ",*(message+i));
        printf("\n");
        if(send_record(ch, r))
            printf("\nPacket sent correctly\n\n");
        else printf("\nError in sendPacket\n");

		free(message);
		if(*(r->message)=='7'){
			free(r->message);
			free(r);
			free_packet(p);
        	stop_channel(ch);
        }        
		free(r->message);
        free(r);
		free_packet(p);
    }
    else {
		free(r->message);
        free(r);
		free_packet(p);
		stop_channel(ch);
	}

}