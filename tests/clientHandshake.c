//
//  SSL/TLS Project
//  clientHandshake.h
//
//  Created on 24/12/15.
//  Copyright © 2015 Mello, Darka. All rights reserved.
//

#include <stdio.h>
#include "ServerClientHandshakeProtocol.h"

int main() {
    //setting up the channel
    char *fileName = "channelHandshake.txt";
    char *channelFrom = "Client";
    char *channelTo = "Server";
    channel *client = create_channel(fileName, channelFrom, channelTo, CLIENT);

    printf("*** Handshake client is start ***\n\n");
    
    //make client hello without session
    session_id session;
    session.session_lenght =0x00;
    session.session_id = NULL;
    handshake_hello *client_hello = make_hello(session);
    client_hello->TLS_version = TLS1_2;

    //make handshake
    handshake h;
    h.type = CLIENT_HELLO;
    serialize_client_server_hello(client_hello, &h.message, &h.length, CLIENT_MODE);
    
    printf("\n***Sending message***\n");
    print_handshake(&h);
    print_hello(client_hello);
    send_handshake(client, &h);
    
    
		
    free_hello(client_hello);
    free(h.message);

	//wait_channel(client);
	fclose(client->file);
	free(client);
}
