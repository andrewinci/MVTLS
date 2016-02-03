//
//  SSL/TLS Project
//
//  serverBasic.c
//  Server for testing the basic protocol layer.
//
//
//  Created on 22/12/15.
//  Copyright © 2015 Alessandro Melloni, Andrea Francesco Vinci. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>

#include "ServerClientTransportProtocol.h"

void onPacketReceive(channel_t *ch, packet_transport_t *p);

int main(int argc, char **argv){
    char *fileName= "channel.txt";
    char *serverName = "Server";

    //create channel
    channel_t *server = create_channel(fileName, serverName, "Client");
    //set function to be called when a message is received
    set_on_receive(server, &onPacketReceive);
    //star channel and listener to new message
    start_listener(server);
    
    printf("*** Server is start ***\n");
    wait_channel(server);
    free(server);
}

void onPacketReceive(channel_t *ch, packet_transport_t *p){
    
    //print received message
    printf("message from: %.8s\n",p->source);
    printf("message len: %d\n", p->length);
    printf("message:\n%.*s\n\n",p->length, p->message);
    
    //prepare new packet to be send
    //if the 'from' field is NULL it will be autofill
    if(*(p->message)<'8'){
        (*(p->message))++;
        packet_transport_t *packet = create_packet(NULL, p->source, p->message, 1);

        if(send_packet(ch, packet))
            printf("\nPacket sent correctly\n");
        else printf("\nError in sendPacket\n");
		
		free_packet(packet);
        
		if(*(p->message)=='8'){
			free_packet(p);
            stop_channel(ch);
        }
		
    }
    free_packet(p); 
}
 /** @} */