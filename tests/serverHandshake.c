//
//  SSL/TLS Project
//  serverHandshake.h
//
//  Created on 24/12/15.
//  Copyright © 2015 Mello, Darka. All rights reserved.
//

#include <stdio.h>
#include <time.h>

#include "ServerClientHandshakeProtocol.h"
#include "ServerClientRecordProtocol.h"


void onPacketReceive(channel *ch, packet_basic *p);

int main() {
    //setting up the channel
    char *fileName = "channelHandshake.txt";
    char *channelFrom = "Server";
    char *channelTo = "Client";
    channel *server = create_channel(fileName, channelFrom, channelTo, SERVER);
    
    set_on_receive(server, &onPacketReceive);
    //star channel and listener to new message
    start_listener(server);
    printf("*** Handshake server is start ***\n\n");
    
    wait_channel(server);
    free(server);
}

void onPacketReceive(channel *ch, packet_basic *p){

    //get record
    record *r = deserialize_record(p->message, p->messageLen);
    if(r->type == HANDSHAKE){
        handshake *h = deserialize_handshake(r->message, r->lenght);
        print_handshake(h);
        if(h->type == CLIENT_HELLO){
            handshake_hello *hello = deserialize_client_server_hello(h->message, h->length, CLIENT_MODE);
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