//
//  SSL/TLS Project
//  serverRecord.C
//
//  Created on 23/12/15.
//  Copyright © 2015 Alessandro Melloni, Andrea Francesco Vinci. All rights reserved.
//

#include <stdio.h>

#include "ServerClientRecordProtocol.h"

void onPacketReceive(channel *ch, packet_basic *p);

int main(int argc, const char * argv[]) {
    //setting up the channel
    char *fileName = "channelRecord.txt";
    char *channelFrom = "Server";
    char *channelTo = "Client";

    //starting the channel between client and server
    channel *server = create_channel(fileName, channelFrom, channelTo, SERVER);
    
    set_on_receive(server, &onPacketReceive);
    //star channel and listener to new message
    start_listener(server);
    
    printf("*** Record server is start ***\n\n");
    wait_channel(server);
    free(server);
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
		if(*(r->message)=='6'){
			free(r->message);
			free(r);
			free_packet(p);
			stop_channel(ch);
		}
		free(r->message);
        free(r);
		free_packet(p);
    }
    else 
		{
			free(r->message);
			free(r);
			free_packet(p);
			stop_channel(ch);
		}

}