//
//  SSL/TLS Project
//  clientRecord.c
//
//  Created on 23/12/15.
//  Copyright © 2015 Alessandro Melloni, Andrea Francesco Vinci. All rights reserved.
//

#include <stdio.h>

#include "ServerClientRecordProtocol.h"

void onPacketReceive(channel_t *ch, packet_transport_t *p);

int main(int argc, const char * argv[]) {
	//setting up the channel
	char *fileName = "channelRecord.txt";
	char *channelFrom = "Client";
	char *channelTo = "Server";
	channel_t *client = create_channel(fileName, channelFrom, channelTo);

	set_on_receive(client, &onPacketReceive);
	//star channel and listener to new message
	start_listener(client);
	printf("\n*** Record client is started ***\n\n");

	record_t *r = malloc(sizeof(record_t));
	r->type = HANDSHAKE;
	r->version = 0x0303;
	r->length = 0x01;
	r->message = malloc(1*sizeof(unsigned char));
	*(r->message)='\x31';

	send_record(client, r);
	free_record(r);
	wait_channel(client);
	free(client);
}

void onPacketReceive(channel_t *ch, packet_transport_t *p){

	// Get record
	record_t *r = deserialize_record(p->message, p->length);

	// Print received message
	printf("\n***Transport***\n");
	printf("\nMessage from: %s\n", p->source);
	printf("\nMessage length: %d\n", p->length);
	printf("\n***Record***\n");
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
		printf("Sending record:\n");
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
		if(*(r->message)=='7'){
			free_record(r);
			free_packet(p);
			stop_channel(ch);
		}
		free_record(r);
		free_packet(p);
	}
	else{
		free_record(r);
		free_packet(p);
		stop_channel(ch);
	}
}
