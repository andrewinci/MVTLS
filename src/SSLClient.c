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

void onPacketReceive(channel *ch, packet_basic *p);
void RSA_key_exchange(handshake *h, channel *ch);

uint16_t cipher_suite =0x0000;
certificate_message *server_certificate;
uint16_t tls_version = 0x0000;
uint16_t previous_state = 0x0000;
unsigned char client_random[32] = {0};
unsigned char server_random[32] = {0};

int main() {
    //setting up the channel
    char *fileName = "SSLchannel.txt";
    char *channelFrom = "Client";
    char *channelTo = "Server";
    channel *client = create_channel(fileName, channelFrom, channelTo, CLIENT);
    
    set_on_receive(client, &onPacketReceive);
    //star channel and listener for new message
    start_channel(client);
    printf("*** TLS client is start ***\n\n");
    
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
    
    //save the generated random
    memcpy(client_random,&(client_hello->random.UNIX_time),4);
    memcpy(client_random+4,client_hello->random.random_bytes,28);
    
	free(session);
    free_hello(client_hello);
    free_handshake(client_hello_h);
    
    wait_channel(client);
    free(client);
}

void onHandshakeReceived(channel *ch, handshake *h){

    if(h->type == SERVER_HELLO && previous_state==0x0000){
        //received server hello
        handshake_hello *hello = deserialize_client_server_hello(h->message, h->length, SERVER_MODE);
        //print_hello(hello);
        printf("\n<<< Server Hello\n");
        
        //extract data for next steps
        cipher_suite = *(hello->cipher_suites.cipher_id);

        printf("\nCipher suite :%04x\n",cipher_suite);
        
        tls_version = hello->TLS_version;
        
        //print_handshake(h);
        
        //save server random
        memcpy(server_random,&(hello->random.UNIX_time), 4);
        memcpy(server_random+4, hello->random.random_bytes, 28);
        printf("Server random :\n");
        for(int i=0;i<32;i++)
            printf("%02x ",server_random[i]);
        printf("\nClient random :\n");
        for(int i=0;i<32;i++)
            printf("%02x ",client_random[i]);
        
        free_hello(hello);
        previous_state = SERVER_HELLO;
    }
    else if(h->type == CERTIFICATE && previous_state == SERVER_HELLO){
        printf("\n<<< Certificate\n");
        //print_handshake(h);
        certificate_message *certificate_m = deserialize_certificate_message(h->message, h->length);
        server_certificate = certificate_m;
        printf("\nCertificate name: %s\n",certificate_m->X509_certificate->name);
        previous_state = CERTIFICATE;
        
    }
    else if(h->type == SERVER_DONE && previous_state == CERTIFICATE){
        printf("<<< Server Hello Done\n");
        //print_handshake(h);
        free_handshake(h);
        
        //make Client Key Exchange Message
        key_exchange_algorithm kx = get_kx_algorithm(cipher_suite);
        if(kx == RSA_KX){
            RSA_key_exchange(h, ch);
        }
        free_certificate_message(server_certificate);
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
    
    pubkey = X509_get_pubkey(server_certificate->X509_certificate);
    rsa = EVP_PKEY_get1_RSA(pubkey);

    EVP_PKEY_free(pubkey);
    //generate pre master secret key
    unsigned char *pre_master_key = calloc(PRE_MASTER_KEY_LEN,1);
    //the first 2 byte coincide with the tls version
    uint16_t temp = REV16(tls_version);
    memcpy(pre_master_key,&temp , 2);
    
    //the rest are random
    RAND_pseudo_bytes(pre_master_key+2, 46);
    unsigned char pre_master_key_enc[256];
    
    printf("\nPremaster secret:\n");
    for(int i=0;i<48;i++)
        printf("%02x ",pre_master_key[i]);
    
    //encrypt pre_master_key
    uint32_t key_len = RSA_public_encrypt(PRE_MASTER_KEY_LEN, pre_master_key, pre_master_key_enc, rsa, RSA_PKCS1_PADDING);

    
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
    free_handshake(client_key_exchange);
    
    //make master key
    unsigned char seed[64];
    memcpy(seed, client_random, 32);
    memcpy(seed+32, server_random, 32);
    
    unsigned char *master_key = NULL;
    const EVP_MD *hash_function = get_hash_function(cipher_suite);
    PRF(hash_function, pre_master_key, PRE_MASTER_KEY_LEN, "master secret", 13, seed, 64, 48, &master_key);
    
    printf("\nMaster secret:\n");
    for(int i=0;i<48;i++)
        printf("%02x ",master_key[i]);
    RSA_free(rsa);
    free(pre_master_key);
}