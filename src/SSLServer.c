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
#include <openssl/err.h>

void onPacketReceive(channel *ch, packet_basic *p);

uint16_t previous_state = 0x00; //TODO
uint16_t cipher_suite =0x00;
unsigned char client_random[32] = {0};
unsigned char server_random[32] = {0};

int main() {
    
    //setting up the channel
    char *fileName = "SSLchannel.txt";
    char *channelFrom = "Server";
    char *channelTo = "Client";
    channel *server = create_channel(fileName, channelFrom, channelTo, SERVER);
    
    set_on_receive(server, &onPacketReceive);
    //star channel and listener to new message
    start_channel(server);
    printf("*** TLS server is start ***\n\n");
    
    wait_channel(server);
    free(server);
}

void onHandshakeReceived(channel *ch, handshake *h){
    if(h->type == CLIENT_HELLO){
        handshake_hello *client_hello = deserialize_client_server_hello(h->message, h->length, CLIENT_MODE);
        
        printf("<<< Client Hello\n");
        //print_hello(client_hello);
        //copy client random
        memcpy(client_random,&(client_hello->random.UNIX_time),4);
        memcpy(client_random+4,client_hello->random.random_bytes,28);
        
        //Make server hello without session
        session_id *session= malloc(sizeof(session_id));
        session->session_lenght =0x00;
        session->session_id = NULL;
        handshake_hello *server_hello = make_hello(*session);
        
        //choose a cipher suite
        server_hello->cipher_suites.length = 0x02;

        server_hello->cipher_suites.cipher_id = malloc(2);
        //TODO : choice a cipher suite
        *(server_hello->cipher_suites.cipher_id) = client_hello->cipher_suites.cipher_id[1];
        cipher_suite = *(server_hello->cipher_suites.cipher_id);
        printf("\nCipher suite :%04x\n",cipher_suite);
        
        //copy server random
        memcpy(server_random,&(server_hello->random.UNIX_time), 4);
        memcpy(server_random+4, server_hello->random.random_bytes, 28);
        
        printf("Server random :\n");
        for(int i=0;i<32;i++)
            printf("%02x ",server_random[i]);
        printf("\nClient random :\n");
        for(int i=0;i<32;i++)
            printf("%02x ",client_random[i]);
        //clear received packet
        free_hello(client_hello);
        
        
        //make Server hello handshake
        handshake *server_hello_h = malloc(sizeof(handshake));
        server_hello_h->type = SERVER_HELLO;
        server_hello_h->message = NULL;
        server_hello_h->length = 0;
        serialize_client_server_hello(server_hello, &(server_hello_h->message), &(server_hello_h->length), SERVER_MODE);
        //print_hello(server_hello);
        printf("\n>>> Server Hello\n");
        send_handshake(ch, server_hello_h);
        free_handshake(server_hello_h);
       
        
        //make certificate packet
        char cert_names[] = "../certificates/serverRSA.pem";
        char **cert_list= malloc(1*sizeof(char *));
        cert_list[0] = cert_names;
        
        certificate_message *cert_message = make_certificate_message("../certificates/serverRSA.pem");
        free(cert_list);
        handshake *certificate_h = malloc(sizeof(handshake));
        certificate_h->type = CERTIFICATE;
        serialize_certificate_message(cert_message, &(certificate_h->message), &(certificate_h->length));
        free_certificate_message(cert_message);
        
        printf(">>> Certificate\n");
        send_handshake(ch, certificate_h);
        free_handshake(certificate_h);
        
        /*
         if the key exchange method is one of these:
         DHE_DSS DHE_RSA DH_anon
         send: Server Key Exchange Message
         */
        /*for these key method exchange :
         RSA DH_DSS DH_RSA
         don't send Server Key Exchange
         but server hello done
         */
        key_exchange_algorithm kx = get_kx_algorithm(cipher_suite);
        if(kx==RSA_KX || kx==DH_DSS_KX || kx == DH_RSA_KX){
            //make Server Hello Done
            handshake *server_hello_done = malloc(sizeof(handshake));
            server_hello_done->type = SERVER_DONE;
            server_hello_done->length =0x04;
            server_hello_done->message = calloc(4,1);
            *(server_hello_done->message) = 0x0e;
            printf(">>> Server hello done\n");
            send_handshake(ch, server_hello_done);
            free_handshake(server_hello_done);
        }
        else{
            //TODO : implement server key exchange message
        }
    }
    else if (h->type == CLIENT_KEY_EXCHANGE){
        if(get_kx_algorithm(cipher_suite)==RSA_KX){
            printf("<<< Client Key Exchange\n");
            //RSA key exchange
            
            //extract private key from file
            RSA *privateKey = NULL;
            FILE *fp;
            
            if(NULL != (fp= fopen("../certificates/serverRSA.key", "r")) )
            {
                privateKey=PEM_read_RSAPrivateKey(fp,NULL,NULL,NULL); 
                if(privateKey==NULL)
                {
                    printf("\nerror in retrieve private key");
                    exit(-1);
                }
            }
            fclose(fp);
            
            //extract pre master key encrypted from message
            unsigned char *pre_master_key_enc = NULL;
            uint32_t key_en_len = 0;
            deserialize_key_exchange(h->length, h->message, &pre_master_key_enc, &key_en_len, RSA_KX);
            
            unsigned char pre_master_key[48]={0};
            if(!RSA_private_decrypt(key_en_len, pre_master_key_enc, pre_master_key, privateKey, RSA_PKCS1_PADDING)) //TODO : check
            {
                printf("Error decrypt\n");
                exit(-1);
            }
            printf("\nPremaster secret:\n");
            for(int i=0;i<48;i++)
                printf("%02x ",pre_master_key[i]);
            fflush(stdout);
            printf("\n");
            
            //make master key
            unsigned char seed[64];
            memcpy(seed, client_random, 32);
            memcpy(seed+32, server_random, 32);
            printf("\nSeed:\n");
            for(int i=0;i<64;i++)
                printf("%02x ",seed[i]);
            unsigned char *master_key = NULL;
            const EVP_MD *hash_function = get_hash_function(cipher_suite);
            PRF(hash_function, pre_master_key, PRE_MASTER_KEY_LEN, "master secret", 13, seed, 64, 48, &master_key);
            
            printf("\nMaster secret:\n");
            for(int i=0;i<48;i++)
                printf("%02x ",master_key[i]);
            
            free(pre_master_key_enc);
            RSA_free(privateKey);
            free_handshake(h);
            stop_channel(ch);
        }
    }
}


void onPacketReceive(channel *ch, packet_basic *p){
    //get record and print
    record *r = deserialize_record(p->message, p->messageLen);
    if(r->type == HANDSHAKE){
        handshake *h = deserialize_handshake(r->message, r->lenght);
		free_record(r);
		free_packet(p);
        onHandshakeReceived(ch, h);
		free_handshake(h);
    }
    //stop_channel(ch);
}