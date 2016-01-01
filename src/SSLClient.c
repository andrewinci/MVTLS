//
//  SSL/TLS Project
//  SSLClient.c
//
//  Created on 30/12/15.
//  Copyright © 2015 Mello, Darka. All rights reserved.
//
#include <stdio.h>
#include "ServerClientHandshakeProtocol.h"
#include "ServerClientRecordProtocol.h"

void onPacketReceive(channel *ch, packet_basic *p);

int main() {
    //setting up the channel
    char *fileName = "SSLchannel.txt";
    char *channelFrom = "Client";
    char *channelTo = "Server";
    channel *client = create_channel(fileName, channelFrom, channelTo, CLIENT);
    
    set_on_receive(client, &onPacketReceive);
    //star channel and listener for new message
    start_channel(client);
    printf("*** Handshake client is start ***\n\n");
    
    //make client hello without session
    session_id session;
    session.session_lenght =0x00;
    session.session_id = NULL;
    handshake_hello *client_hello = make_hello(session);
    client_hello->TLS_version = TLS1_2;
    
    //make handshake
    handshake client_hello_h;
    client_hello_h.type = CLIENT_HELLO;
    serialize_client_server_hello(client_hello, &client_hello_h.message, &client_hello_h.length, CLIENT_MODE);
    
    printf("Sending client hello\n");
    //print_handshake(&client_hello_h);
    //print_hello(client_hello);
    send_handshake(client, &client_hello_h);
    wait_channel(client);
    
    free_hello(client_hello);
    free(client_hello_h.message);
    free(client);
}

void onPacketReceive(channel *ch, packet_basic *p){
    //get record and print
    record *r = deserialize_record(p->message, p->messageLen);
    if(r->type == HANDSHAKE){
        handshake *h = deserialize_handshake(r->message, r->lenght);
        //print_handshake(h);
        if(h->type == SERVER_HELLO){
            handshake_hello *hello = deserialize_client_server_hello(h->message, h->length, CLIENT_MODE);
            print_hello(hello);
            printf("\nReceived Server Hello\n");
        }
        else if(h->type == CERTIFICATE){
            printf("Received Certificate\n");
            certificate_message *certificate_m = deserialize_certificate_message(h->message, h->length);
            printf("Certificate name: %s",certificate_m->certificate_list->X509_certificate->name);
            stop_channel(ch);
            free_certificate_message(certificate_m);
        }
    }
    free_packet(p);
}