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
#include <openssl/rand.h>
#include <openssl/err.h>

void onPacketReceive(channel *ch, packet_basic *p);
void RSA_key_exchange(handshake *h, channel *ch);

uint16_t cipher_suite =0x0000;
X509 *server_certificate = NULL;
uint16_t tls_version = 0x0000;

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
    session_id *session= malloc(sizeof(session_id));
    session->session_lenght =0x00;
    session->session_id = NULL;
    handshake_hello *client_hello = make_hello(*session);
    client_hello->TLS_version = TLS1_2;
    
    //make handshake
    handshake *client_hello_h = malloc(sizeof(handshake));
    client_hello_h->type = CLIENT_HELLO;
    //put message in the handshake packet
    serialize_client_server_hello(client_hello, &(client_hello_h->message), &(client_hello_h->length), CLIENT_MODE);
    
    printf(">>> Client hello\n");
    send_handshake(client, client_hello_h);
    wait_channel(client);
    
	free(session);
    free_hello(client_hello);
    free_handshake(client_hello_h);
    free(client);
}

void onHandshakeReceived(channel *ch, handshake *h){
    certificate_message *certificate_m = NULL;
    if(h->type == SERVER_HELLO){
        //received server hello
        handshake_hello *hello = deserialize_client_server_hello(h->message, h->length, SERVER_MODE);
        //print_hello(hello);
        printf("\n<<< Server Hello\n");
        
        //extract data for next steps
        cipher_suite = *(hello->cipher_suites.cipher_id);
        tls_version = hello->TLS_version;
        
        print_handshake(h);
        free_hello(hello);
    }
    else if(h->type == CERTIFICATE){
        printf("\n<<< Certificate\n");
        print_handshake(h);
        certificate_m = deserialize_certificate_message(h->message, h->length);
        server_certificate = certificate_m->certificate_list->X509_certificate;
        printf("\nCertificate name: %s\n",certificate_m->certificate_list->X509_certificate->name);
        
    }
    else if(h->type == SERVER_DONE){
        printf("<<< Server Hello Done\n");
        print_handshake(h);
        free_handshake(h);
        
        //make Client Key Exchange Message
        key_exchange_algorithm kx = get_kx_algorithm(cipher_suite);
        if(kx == RSA_KX){
            RSA_key_exchange(h, ch);
        }
        free_certificate_message(certificate_m);
        stop_channel(ch);
    }
}

void onPacketReceive(channel *ch, packet_basic *p){
    //get record and print
    record *r = deserialize_record(p->message, p->messageLen);
    if(r->type == HANDSHAKE){
        handshake *h = deserialize_handshake(r->message, r->lenght);    
		free_record(r);
		free_packet(p);
        onHandshakeReceived(ch,h);
		free_handshake(h);
    }
}


void RSA_key_exchange(handshake *h, channel *ch) {
    //get RSA struct
    EVP_PKEY *pubkey = NULL;
    RSA *rsa = NULL;
    
    pubkey = X509_get_pubkey(server_certificate);
    rsa = EVP_PKEY_get1_RSA(pubkey);

    EVP_PKEY_free(pubkey);
    //generate pre master secret key
    unsigned char *pre_master_key = calloc(48,1);
    //the first 2 byte coincide with the tls version
    uint16_t temp = REV16(tls_version);
    memcpy(pre_master_key,&temp , 2);
    
    //the rest are random
    RAND_pseudo_bytes(pre_master_key+2, 46);
    unsigned char pre_master_key_enc[256];
    
    printf("\nPremaster secret:\n");
    for(int i=0;i<46;i++)
        printf("%02x ",pre_master_key[i]);
    //encrypt pre_master_key
    uint32_t key_len = RSA_public_encrypt(48, pre_master_key, pre_master_key_enc, rsa, RSA_PKCS1_PADDING);
    
    //serialize and send
    unsigned char *message = NULL;
    uint32_t len = 0;
    serialize_key_exchange(key_len, pre_master_key_enc, &message, &len, RSA_KX);
    
    //make handshake packet
    handshake *client_key_exchange = malloc(sizeof(handshake));
    client_key_exchange->type = CLIENT_KEY_EXCHANGE;
    client_key_exchange->message = message;
    client_key_exchange->length = len;

    printf("\n>>> Client Key Exchange\n");
    send_handshake(ch, client_key_exchange);
    
    //TODO : make master key
    free(message);
}
