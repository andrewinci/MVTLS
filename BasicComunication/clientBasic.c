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
    channel *client = createChannel(fileName, clientName, NULL, CLIENT);
    setOnReceive(client, &onPacketReceive);
    startChannel(client);
    printf("*** Client is start ***\n");
    
    //sending packet
    unsigned char *message = malloc(1);
    *message = '\x01';
    char *to = "Server\0";
    printf("Client send: %s\n",message);
    
    packet *p = createPacket(NULL, to, message, 1);
    sendPacket(client, p);
    freePacket(p);
    waitChannel(client);

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
        packet *packet = createPacket(NULL, p->from, p->message, 1);
        
        if(sendPacket(ch, packet))
            printf("\nPacket sent correctly\n\n");
        else printf("\nError in sendPacket\n\n");
        freePacket(packet);
    }
    else stopChannel(ch);
    freePacket(p);
}
