//
//  SSL/TLS Project
//  clientBasic.c
//
//  Created on 22/12/15.
//  Copyright © 2015 Mello, Darka. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>

#include "ServerClientBasic.h"


#include<stdio.h>
void onPacketReceive(channel *ch, packet *p);

int main(int argc, char **argv){
    char *fileName = "channel.txt";
    char *clientName = "Client";
    channel *client = create_channel(fileName, clientName, NULL, CLIENT);
    set_on_receive(client, &onPacketReceive);
    start_channel(client);
    printf("*** Client is start ***\n");
    
    //sending packet
    unsigned char *message = malloc(1);
    *message = '\x01';
    char *to = "Server\0";
    printf("Client send: %s\n",message);
    
    packet *p = create_packet(NULL, to, message, 1);
    send_packet(client, p);
    free_packet(p);
    wait_channel(client);

}

void onPacketReceive(channel *ch, packet *p){
    
    //print received message
    printf("message from: %s\n", p->from);
    printf("message len: %d\n", p->messageLen);
    printf("message:\n%.*s\n\n",p->messageLen, p->message);
    
    //prepare new packet to be send
    //if the 'from' field is NULL it will be autofill
    
    if(*(p->message)<'8'){
        (*(p->message))++;
        packet *packet = create_packet(NULL, p->from, p->message, 1);
        
        if(send_packet(ch, packet))
            printf("\nPacket sent correctly\n\n");
        else printf("\nError in sendPacket\n\n");
        free_packet(packet);
    }
    else stop_channel(ch);
    free_packet(p);
}
