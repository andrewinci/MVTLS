//
//  SSL/TLS Project
//  SSLServer.c
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
    char *channelFrom = "Server";
    char *channelTo = "Client";
    channel *server = create_channel(fileName, channelFrom, channelTo, CLIENT);
    
    set_on_receive(server, &onPacketReceive);
    //star channel and listener to new message
    start_channel(server);
    printf("*** Handshake server is start ***\n\n");
    
    wait_channel(server);
    free(server);
}

void onPacketReceive(channel *ch, packet_basic *p){
    //get record and print
    record *r = deserialize_record(p->message, p->messageLen);
    if(r->type == HANDSHAKE){
        handshake *h = deserialize_handshake(r->message, r->lenght);
        //print_handshake(h);
        if(h->type == CLIENT_HELLO){
            handshake_hello *hello = deserialize_client_server_hello(h->message, h->length, CLIENT_MODE);
            print_hello(hello);
            printf("Received Client Hello\n");
            //choose a cipher suite
            hello->cipher_suites.length = 0x01;
            
            hello->cipher_suites.cipher_id = malloc(2);
            //select the first for testing
            //*(hello->cipher_suites.cipher_id) = hello->cipher_suites.cipher_id[1];
            //session and compression not implemented yet
            //we don't modify them
            
            //make handshake
            handshake server_hello;
            server_hello.type = SERVER_HELLO;
            unsigned char *server_hello_stream =NULL;
            uint32_t server_hello_stream_len = 0;
            serialize_client_server_hello(hello, &server_hello_stream, &server_hello_stream_len, SERVER_MODE);
            
            server_hello.message = server_hello_stream;
            server_hello.length = server_hello_stream_len;
            printf("Sending Server Hello\n");
            send_handshake(ch, &server_hello);
            free_hello(hello);
            
            char cert_names[] = "../certificates/server.pem";
            char **cert_list= malloc(1*sizeof(char *));
            cert_list[0] = cert_names;
            certificate_message *cert_message = make_certificate_message(cert_list, 1);
            handshake certificate_h;
            certificate_h.type = CERTIFICATE;
            serialize_certificate_message(cert_message, &certificate_h.message, &certificate_h.length);
            send_handshake(ch, &certificate_h);
            free_certificate_message(cert_message);

        }
    }
    stop_channel(ch);
    free_packet(p);
}