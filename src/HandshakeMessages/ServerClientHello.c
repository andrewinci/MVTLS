//
//  SSL/TLS Project
//  serverClientHello.h
//
//  Created on 24/12/15.
//  Copyright © 2015 Mello, Darka. All rights reserved.
//

#ifdef MAKEFILE
#include "HandshakeMessages/ServerClientHello.h"
#else
#include "ServerClientHello.h"
#endif

handshake_hello_t *make_hello(session_id session){
    
    handshake_hello_t *hello = malloc(sizeof(handshake_hello_t));
    
    //compression method by default is setted to null
    hello->compression_methods.length = 0x01;
    hello->compression_methods.compression_id = 0x00;
    
    //add random
    hello->random.UNIX_time = (uint32_t)time(NULL);
    uint8_t *random_stream = malloc(sizeof(uint8_t)*28);
    RAND_pseudo_bytes(random_stream, 28);
    
    for(int i=0;i<28;i++)
        hello->random.random_bytes[i] = *(random_stream+i);
    free(random_stream);
	
    hello->session_id = session;
    
    return hello;
}

void serialize_client_server_hello(handshake_hello_t *hello, unsigned char **stream, uint32_t *streamLen, channel_mode mode){
    
    //compute the lenght
    if(mode == CLIENT_MODE)
        *streamLen = 2 + hello->cipher_suite_len + 2 + hello->compression_methods.length + 1 + 32 + hello->session_id.session_lenght + 1;
    else
        *streamLen = 2 + 2 + 1 + 32 + hello->session_id.session_lenght + 1;

    *stream = malloc(sizeof(unsigned char)*(*streamLen));
    unsigned char *buff = *stream;
    
    //serialize TLS Version
    uint16_t TLS_version = REV16(hello->TLS_version);
    memcpy(buff, &TLS_version,2);
    buff+=2;
    
    //serialize random
    random_data_t rdata = hello->random;
    
    rdata.UNIX_time = REV32(rdata.UNIX_time);
    memcpy(buff, &(rdata.UNIX_time), 4);
    buff+=4;
    
    memcpy(buff, rdata.random_bytes, 28);
    buff+=28;
    
    //serialize session id
    session_id session = hello->session_id;
    
    memcpy(buff, &session.session_lenght, 1);
    buff++;
    
    memcpy(buff, session.session_id, session.session_lenght);
    buff+=session.session_lenght;
    
    //serialize cipher suite
    if(mode == SERVER_MODE){
        //ServerHello
        uint16_t cipher_id = REV16(hello->cipher_suites[0].cipher_id);
        memcpy(buff, &cipher_id, 2); // only one cipher suite has to be in the message
        buff+=2;
    }
    else{
        //ClientHello
        uint16_t cipher_suite_len = REV16(hello->cipher_suite_len);
        memcpy(buff, &cipher_suite_len, 2);
        buff+=2;
        uint16_t temp;
        for(int i=0;i<hello->cipher_suite_len/2;i++){
            temp = REV16(hello->cipher_suites[i].cipher_id);
            memcpy(buff, &temp, 2);
            buff+=2;
        }
    }
    
    //serialize compression method
    if(mode == SERVER_MODE){
        //ServerHello
        memcpy(buff, &hello->compression_methods.compression_id,1);
        buff++;
    }else{
        //ClientHello
        memcpy(buff, &hello->compression_methods.length, 1);
        buff++;
        memcpy(buff, &hello->compression_methods.compression_id, 1);
        buff++;
    }
}

handshake_hello_t *deserialize_client_server_hello(unsigned char *stream, uint32_t streamLen, channel_mode mode){
    
    handshake_hello_t *result = malloc(sizeof(handshake_hello_t));
    
    //deserialize TLSversion
    uint16_t TLS_version;
    memcpy(&TLS_version, stream,2);
    result->TLS_version = REV16(TLS_version);
    stream+=2;
    
    
    //deserialize random
    random_data_t rdata;
    
    memcpy(&rdata.UNIX_time, stream, 4);
    rdata.UNIX_time = REV32(rdata.UNIX_time);
    stream+=4;
    
    memcpy(rdata.random_bytes, stream, 28);
    stream+=28;
    
    result->random = rdata;
    
    //deserialize session id
    session_id session;
    
    session.session_lenght = *stream;
    stream++;
    
    session.session_id = malloc(sizeof(unsigned char)*session.session_lenght);
    memcpy(session.session_id, stream, session.session_lenght);
    stream+=session.session_lenght;
    
    result -> session_id = session;
    
    if(mode == SERVER_MODE){
        //ServerHello
        //extract cipher suite
        uint16_t cipher_id = 0;
        memcpy(&cipher_id, stream, 2); // only one cipher suite has to be in the message
        cipher_id = REV16(cipher_id);

        result->cipher_suites = malloc(sizeof(cipher_suite_t));
        result->cipher_suites[0] = get_cipher_suite_by_id(cipher_id);
        *stream+=2;
        result->cipher_suite_len = 2;
    }
    else{
        //ClientHello
        uint16_t ciphers_len = 0;
        memcpy(&ciphers_len, stream, 2);
        ciphers_len = REV16(ciphers_len);
        result->cipher_suite_len = ciphers_len;
        stream+=2;
        result->cipher_suites = malloc(sizeof(cipher_suite_t)*(ciphers_len/2));
        
        for(int i=0;i<ciphers_len/2;i++){
            uint16_t cipher_id = 0;
            memcpy(&cipher_id, stream, 2);
            cipher_id = REV16(cipher_id);
            
            //getting cipher_suite for each id
            cipher_suite_t temp = get_cipher_suite_by_id(cipher_id);
            memcpy(result->cipher_suites+i, &temp, sizeof(cipher_suite_t));
            stream+=2;
        }
    }
    
    //deserialize compression
    compression_methods_t cmethods;
    
    cmethods.length = *stream;
    stream++;
    
    cmethods.compression_id = *stream;
    
    result->compression_methods = cmethods;
    
    return result;
}

void print_hello(handshake_hello_t *h){
    printf("\n***Client/Server hello***\n");
    printf("Version : %d\n",h->TLS_version);
    printf("UNIX time stamp : %d\n", h->random.UNIX_time);
    printf("Random bytes (28): ");
    for(int i=0;i<28;i++)
        printf("%02x ",*(h->random.random_bytes+i));
    printf("Session id : ");
    for(int i=0; i<h->session_id.session_lenght;i++)
        printf("%02x ",*(h->session_id.session_id+i));
    
    printf("Cipher suites :\n");
    for(int i=0;i<h->cipher_suite_len/2;i++)
        printf("id : %02X name: %s", h->cipher_suites[i].cipher_id ,h->cipher_suites[i].name);
    printf("no compression(not yet implemented)\n");
}

void free_hello(handshake_hello_t *h){
    free(h->cipher_suites);
    free(h->session_id.session_id);
    free(h);
}