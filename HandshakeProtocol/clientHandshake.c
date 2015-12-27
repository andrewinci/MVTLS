//
//  SSL/TLS Project
//  clientHandshake.h
//
//  Created on 24/12/15.
//  Copyright © 2015 Mello, Darka. All rights reserved.
//

#include <stdio.h>
#include "ServerClientHandshakeProtocol.h"

void onPacketReceive(channel *ch, packet *p);

int main() {
    //setting up the channel
    char *fileName = "channelHandshake.txt";
    char *channelFrom = "Client";
    char *channelTo = "Server";
    channel *client = createChannel(fileName, channelFrom, channelTo, CLIENT);
    
    setOnReceive(client, &onPacketReceive);
    //star channel and listener for new message
    startChannel(client);
    printf("*** Handshake client is start ***\n\n");
    
    //make client hello without session
    session_id session;
    session.session_lenght =0x00;
    
    handshake_hello *client_hello = makeClientHello(session);
    
    //make handshake
    handshake h;
    h.type = CLIENT_HELLO;
    h.TLS_version = SSL3_0;
    serialize_client_server_hello(*client_hello, &h.message, &h.length, CLIENT_MODE);
    
    printf("\n***Sending message***\n");
    print_handshake(h);
    print_hello(*client_hello);
    send_handshake(client, &h);
    stopChannel(client);
    //waitChannel(client);
    free(client);
    
}

void onPacketReceive(channel *ch, packet *p){
    
}
