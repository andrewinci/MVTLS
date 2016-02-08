//
//  SSL/TLS Project
//
//  serverTransport.c
//  Server for testing the transport protocol layer.
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

	// Create channel
	channel_t *server = create_channel(fileName, serverName, "Client");
	// Set function to be called when a message is received
	set_on_receive(server, &onPacketReceive);
	// Start channel and listener for new messages
	start_listener(server);

	printf("\n*** Server is started ***\n");
	wait_channel(server);
	free(server);
}

void onPacketReceive(channel_t *ch, packet_transport_t *p){

	// Print received message
	printf("\nMessage from: %.8s\n", p->source);
	printf("\nMessage length: %d\n", p->length);
	printf("\nMessage:\n%.*s\n\n", p->length, p->message);

	// Prepare new packet to be sent
	// If the 'from' field is NULL it will autofill
	if(*(p->message)<'8'){
		(*(p->message))++;
		packet_transport_t *packet = create_packet(NULL, p->source, p->message, 1);

		if(send_packet(ch, packet))
			printf("\nPacket sent correctly\n");
		else
			printf("\nError in sendPacket\n");

		free_packet(packet);

		if(*(p->message)=='8'){
			free_packet(p);
			stop_channel(ch);
		}
	}
	free_packet(p); 
}
 