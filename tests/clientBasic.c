/**
 *  SSL/TLS Project
 *
 *  \file clientBasic.c
 *  Client for testing the basic protocol layer.
 *
 *  \addtogroup BasicProtocolLayer
 *  @{
 *  \date Created on 22/12/15.
 *  \copyright Copyright © 2015 Mello, Darka. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>

#include "ServerClientBasic.h"

void onPacketReceive(channel *ch, packet_basic *p);

int main(int argc, char **argv){
    char *fileName = "channel.txt";
    char *clientName = "Client";
    channel *client = create_channel(fileName, clientName, NULL, CLIENT);
    set_on_receive(client, &onPacketReceive);
    start_listener(client);
    printf("*** Client is start ***\n");
    
    //sending packet
    unsigned char *message = malloc(2);
    *message = '1';
    char to[] = "Server\0";
    printf("Client send: %c \n",*message);
    
    packet_basic *p = create_packet(NULL, to, message, 1);
    free(message);
    send_packet(client, p);
    free_packet(p);
    wait_channel(client);
    free(client);
}

void onPacketReceive(channel *ch, packet_basic *p){
    
    //print received message
    printf("message from: %s\n", p->source);
    printf("message len: %d\n", p->messageLen);
    printf("message:\n%.*s\n\n",p->messageLen, p->message);
    
    //prepare new packet to be send
    //if the 'from' field is NULL it will be autofill
    
    if(*(p->message)<'8'){
        (*(p->message))++;
        packet_basic *packet = create_packet(NULL, p->source, p->message, 1);
        
        if(send_packet(ch, packet))
            printf("\nPacket sent correctly\n\n");
        else printf("\nError in sendPacket\n\n");
		free_packet(packet);
        if(*(p->message)=='7'){
			free_packet(p);
        	stop_channel(ch);
        }
    }
	free_packet(p);
}
 /** @} */