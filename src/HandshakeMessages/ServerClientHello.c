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

cipher_suites get_supported_cipher_suites(){
    int nSupported = 3;
    cipher_suites defaultCipherSuites;
    defaultCipherSuites.length = nSupported*2;
    defaultCipherSuites.cipher_id = malloc(nSupported*sizeof(uint16_t));
    defaultCipherSuites.cipher_id[0] = TLS_RSA_WITH_DES_CBC_SHA;
    defaultCipherSuites.cipher_id[1] = TLS_RSA_WITH_AES_256_CBC_SHA256;
    defaultCipherSuites.cipher_id[2] = TLS_RSA_PSK_WITH_NULL_SHA;
    return defaultCipherSuites;
}

uint8_t *getRandomByteStream(int streamLen){
    FILE *randomSource = fopen("/dev/urandom","r");
    uint8_t *result=malloc(streamLen);
    if(!fread(result, streamLen, 1, randomSource)){
        printf("\nError occurs during random generation\n");
        fclose(randomSource);
        exit(-1);
    }
    fclose(randomSource);
    return result;
}

handshake_hello *make_hello(session_id session){
    
    handshake_hello *hello = malloc(sizeof(handshake_hello));
    
    //compression method by default is setted to null
    hello->compression_methods.length = 0x01;
    hello->compression_methods.compression_id = 0x00;
    
    //add random
    hello->random.UNIX_time = (uint32_t)time(NULL);
    
    uint8_t *random_stream =getRandomByteStream(28);
    for(int i=0;i<28;i++)
        hello->random.random_bytes[i] = *(random_stream+i);
    free(random_stream);
	
    hello->session_id = session;
    
    hello->cipher_suites = get_supported_cipher_suites();
    
    return hello;
}

void serialize_client_server_hello(handshake_hello *hello, unsigned char **stream, uint32_t *streamLen, channel_mode mode){
    
    //compute the lenght
    if(mode == CLIENT_MODE)
        *streamLen = 2 + hello->cipher_suites.length + 2 + hello->compression_methods.length + 1 + 32 + hello->session_id.session_lenght + 1;
    else
        *streamLen = 2 + 2 + 1 + 32 + hello->session_id.session_lenght + 1;

    *stream = malloc(*streamLen);
    unsigned char *buff = *stream;
    
    //serialize TLS Version
    uint16_t TLS_version = REV16(hello->TLS_version);
    memcpy(buff, &TLS_version,2);
    buff+=2;
    
    //serialize random
    random_data rdata = hello->random;
    
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
        uint16_t cipher_id =REV16(*(hello->cipher_suites.cipher_id));
        memcpy(buff, &cipher_id, 2); // only one cipher suite has to be in the message
        buff+=2;
    }
    else{
        uint16_t *cipher_ids = hello->cipher_suites.cipher_id;
        //ClientHello
        memcpy(buff, &hello->cipher_suites.length, 1);
        buff++;
        uint16_t temp;
        for(int i=0;i<hello->cipher_suites.length/2;i++){
            temp = REV16(*(cipher_ids+i));
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

handshake_hello *deserialize_client_server_hello(unsigned char *stream, uint32_t streamLen, channel_mode mode){
    
    handshake_hello *result = malloc(sizeof(handshake_hello));
    
    //deserialize TLSversion
    uint16_t TLS_version;
    memcpy(&TLS_version, stream,2);
    result->TLS_version = REV16(TLS_version);
    stream+=2;
    
    
    //deserialize random
    random_data rdata;
    
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
    
    session.session_id = malloc(session.session_lenght);
    memcpy(session.session_id, stream, session.session_lenght);
    stream+=session.session_lenght;
    
    result -> session_id = session;
    
    //deserialize cipher suite
    cipher_suites csuite;
    
    if(mode == SERVER_MODE){
        //ServerHello
        csuite.cipher_id = malloc(2);
        memcpy(csuite.cipher_id, stream, 2); // only one cipher suite has to be in the message
        *csuite.cipher_id = REV16(*csuite.cipher_id);
        *stream+=2;
        csuite.length = 2;
    }
    else{
        //ClientHello
        csuite.length = *stream;
        stream++;
        csuite.cipher_id = malloc(sizeof(uint16_t)*csuite.length);
        for(int i=0;i<csuite.length/2;i++){
            memcpy(csuite.cipher_id+i, stream, 2);
            *(csuite.cipher_id+i) = REV16(*(csuite.cipher_id+i));
            stream+=2;
        }
    }
    result->cipher_suites = csuite;
    
    //deserialize compression
    compression_methods cmethods;
    
    cmethods.length = *stream;
    stream++;
    
    cmethods.compression_id = *stream;
    
    result->compression_methods = cmethods;
    
    return result;
}

void print_hello(handshake_hello *h){
    printf("\n****Client/Server hello***\n");
    printf("Version : %d\n",h->TLS_version);
    printf("**Random**\n");
    printf("UNIX time stamp : %d\n", h->random.UNIX_time);
    printf("Random bytes (28): ");
    for(int i=0;i<28;i++)
        printf("%02x ",*(h->random.random_bytes+i));
    printf("\n**Session**\n");
    printf("Length : %d\n",h->session_id.session_lenght);
    printf("Session id : ");
    for(int i=0; i<h->session_id.session_lenght;i++)
        printf("%02x ",*(h->session_id.session_id+i));

    printf("\n**Cipher suite**\n");
    printf("Length : %d\n", h->cipher_suites.length);
    printf("Cipher suites :\n");
    for(int i=0;i<h->cipher_suites.length/2;i++)
        printf("%04x\n",*(h->cipher_suites.cipher_id+i));
    printf("no compression(not yet implemented)\n");
}

void free_hello(handshake_hello *h){
    free(h->cipher_suites.cipher_id);
    free(h->session_id.session_id);
    free(h);
}