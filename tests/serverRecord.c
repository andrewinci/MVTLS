//
//  SSL/TLS Project
//  serverRecord.c
//
//  Created on 23/12/15.
//  Copyright © 2015 Alessandro Melloni, Andrea Francesco Vinci. All rights reserved.
//

#include <stdio.h>

#include "ServerClientRecordProtocol.h"

void onPacketReceive(channel_t *ch, packet_transport_t *p);

int main(int argc, const char * argv[]) {
	// Set up the channel
	char *fileName = "channelRecord.txt";
	char *channelFrom = "Server";
	char *channelTo = "Client";

	// Create channel
	channel_t *server = create_channel(fileName, channelFrom, channelTo);

	set_on_receive(server, &onPacketReceive);
	// Start channel and listener for new messages
	start_listener(server);

	printf("\n*** Record server is started ***\n\n");
	wait_channel(server);
	free(server);
}

void onPacketReceive(channel_t *ch, packet_transport_t *p){

	// Get record
	record_t *r = deserialize_record(p->message, p->length);
	// Print received message
	printf("\n**Transport**\n");
	printf("\nMessage from: %s\n", p->source);
	printf("\nMessage length: %d\n", p->length);
	printf("\n****Record****\n");
	printf("\nType: %02x\n",r->type);
	printf("\nVersion: %04x\n",r->version);
	printf("\nRecord message:\n%.*s\n",r->length, r->message);
	printf("\nHexadecimal: \n");
	for(int i=0;i<p->length;i++)
		printf("%02x ",*(p->message+i));
	printf("\n");

	// Prepare new packet to be sent
	// If the from field is NULL it will autofill
	if(*(r->message)<'8'){
		(*(r->message))++;
		printf("\nSending record:\n");
		unsigned char *message = NULL;
		uint16_t len;
		serialize_record(r, &message, &len);
		for(int i=0;i<len+5;i++)
			printf("%02x ",*(message+i));
		printf("\n");
		if(send_record(ch, r))
			printf("\nPacket sent correctly\n\n");
		else
			printf("\nError in sendPacket\n");
		free(message);
		if(*(r->message)=='6'){
			free(r->message);
			free(r);
			free_packet(p);
			stop_channel(ch);
		}
		free(r->message);
		free(r);
		free_packet(p);
	}
	else{
		free(r->message);
		free(r);
		free_packet(p);
		stop_channel(ch);
	}
}
