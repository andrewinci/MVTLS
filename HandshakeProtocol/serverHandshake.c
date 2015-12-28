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
#include "../RecordProtocol/ServerClientRecordProtocol.h"


void onPacketReceive(channel *ch, packet *p);

int main() {
    //setting up the channel
    char *fileName = "channelHandshake.txt";
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

void onPacketReceive(channel *ch, packet *p){
    //get record
    record *r = deserialize_record(p->message, p->messageLen);
    if(r->type == HANDSHAKE){
        handshake *h = deserialize_handshake(r->message, r->lenght);
        print_handshake(h);
        if(h->type == CLIENT_HELLO){
            handshake_hello *hello = deserialize_client_server_hello(h->message, h->length, CLIENT_MODE);
            print_hello(hello);
            free_packet(p);
            stop_channel(ch);
        }
    }
    
//    //print received message
//    printf("**Basic**\n");
//    printf("message from: %s\n", p->from);
//    printf("message len: %d\n", p->messageLen);
//    printf("****Record****\n");
//    printf("type : %02x\n",r->type);
//    printf("version : %04x\n",r->version);
//    printf("record message:\n%.*s\n",r->lenght, r->message);
//    printf("hex : \n");
//    for(int i=0;i<p->messageLen;i++)
//        printf("%02x ",*(p->message+i));
//    printf("\n");
//    
//    //prepare new packet to be send
//    //if the from field is NULL it will be autofill
//    if(*(r->message)<'8'){
//        (*(r->message))++;
//        
//        printf("Sending record:\n");
//        unsigned char *message = NULL;
//        uint16_t len;
//        serializeRecord(r, &message, &len);
//        for(int i=0;i<len+5;i++)
//            printf("%02x ",*(message+i));
//        printf("\n");
//        
//        if(sendRecord(ch, r))
//            printf("\nPacket sent correctly\n\n");
//        else printf("\nError in sendPacket\n");
//        free(r->message);
//        free(r);
//    }
//    else
    stop_channel(ch);
    free_packet(p);
}