//
//  SSL/TLS Project
//  serverHandshake.h
//
//  Created on 24/12/15.
//  Copyright © 2015 Alessandro Melloni, Andrea Francesco Vinci. All rights reserved.
//

#include <stdio.h>
#include <time.h>

#include "ServerClientHandshakeProtocol.h"
#include "ServerClientRecordProtocol.h"


void onPacketReceive(channel_t *ch, packet_transport_t *p);

int main() {
    //setting up the channel
    char *fileName = "channelHandshake.txt";
    char *channelFrom = "Server";
    char *channelTo = "Client";
    channel_t *server = create_channel(fileName, channelFrom, channelTo);
    
    set_on_receive(server, &onPacketReceive);
    //star channel and listener to new message
    start_listener(server);
    printf("*** Handshake server is start ***\n\n");
    
    wait_channel(server);
    free(server);
}

void onPacketReceive(channel_t *ch, packet_transport_t *p){

    //get record
    record_t *r = deserialize_record(p->message, p->length);
    if(r->type == HANDSHAKE){
        handshake_t *h = deserialize_handshake(r->message, r->length);
        print_handshake(h,2,0);
        if(h->type == CLIENT_HELLO){
            server_client_hello_t *hello = deserialize_client_server_hello(h->message, h->length, CLIENT_MODE);
            print_hello(hello);
			free_hello(hello);
			
			free_record(r);
            free_handshake(h);
			free_packet(p);
            
			stop_channel(ch);
        }
    }
	free_record(r);
    free_packet(p);
	stop_channel(ch);
}