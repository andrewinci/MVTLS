//
//  SSL/TLS Project
//  serverBasic.c
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
    char *fileName= "channel.txt";
    char *serverName = "Server";

    //create channel
    channel *server = createChannel(fileName, serverName, NULL, SERVER);
    //set function to be called when a message is received
    setOnReceive(server, &onPacketReceive);
    //star channel and listener to new message
    startChannel(server);
    
    printf("*** Server is start ***\n");
    waitChannel(server);
    free(server);
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
        packet *packet = createPacket(NULL, p->from, p->message, 2);

        if(sendPacket(ch, packet))
            printf("\nPacket sent correctly\n");
        else printf("\nError in sendPacket\n");
        freePacket(packet);
    }
    else stopChannel(ch);
    freePacket(p); 
}