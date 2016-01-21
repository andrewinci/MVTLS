//
//  SSL/TLS Project
//  handshakeConstants.c
//
//  Created on 07/01/15.
//  Copyright © 2015 Mello, Darka. All rights reserved.
//

#include "handshakeConstants.h"

int cipher_suite_len = 62;

cipher_suite_t cipher_suite_list[] ={
    //RSA
    {0x0001 , "TLS_RSA_WITH_NULL_MD5" , 1 , 1 , 0 , 1 },
    {0x0002 , "TLS_RSA_WITH_NULL_SHA" , 1 , 1 , 0 , 2 },
    {0x0004 , "TLS_RSA_WITH_RC4_128_MD5" , 1 , 1 , 128 , 1 },
    {0x0005 , "TLS_RSA_WITH_RC4_128_SHA" , 1 , 1 , 128 , 2 },
    {0x0007 , "TLS_RSA_WITH_IDEA_CBC_SHA" , 1 , 1 , 128 , 2 },
    {0x0009 , "TLS_RSA_WITH_DES_CBC_SHA" , 1 , 1 , 56 , 2 },
    {0x000A , "TLS_RSA_WITH_3DES_EDE_CBC_SHA" , 1 , 1 , 168 , 2 },
    {0x002F , "TLS_RSA_WITH_AES_128_CBC_SHA" , 1 , 1 , 128 , 2 },
    {0x0035 , "TLS_RSA_WITH_AES_256_CBC_SHA" , 1 , 1 , 256 , 2 },
    {0x003B , "TLS_RSA_WITH_NULL_SHA256" , 1 , 1 , 0 , 4 },
    {0x003C , "TLS_RSA_WITH_AES_128_CBC_SHA256" , 1 , 1 , 128 , 4 },
    {0x003D , "TLS_RSA_WITH_AES_256_CBC_SHA256" , 1 , 1 , 256 , 4 },
    {0x0041 , "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA" , 1 , 1 , 128 , 2 },
    {0x0084 , "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA" , 1 , 1 , 256 , 2 },
    {0x0096 , "TLS_RSA_WITH_SEED_CBC_SHA" , 1 , 1 , 128 , 2 },
    {0x009C , "TLS_RSA_WITH_AES_128_GCM_SHA256" , 1 , 1 , 128 , 4 },
    {0x009D , "TLS_RSA_WITH_AES_256_GCM_SHA384" , 1 , 1 , 256 , 5 },
    
    //ECDHE
    {0xC006 , "TLS_ECDHE_ECDSA_WITH_NULL_SHA" , 3 , 3 , 0 , 2 },
    {0xC007 , "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA" , 3 , 3 , 128 , 2 },
    {0xC008 , "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA" , 3 , 3 , 168 , 2 },
    {0xC009 , "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA" , 3 , 3 , 128 , 2 },
    {0xC00A , "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA" , 3 , 3 , 256 , 2 },
    {0xC023 , "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256" , 3 , 3 , 128 , 4 },
    {0xC024 , "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384" , 3 , 3 , 256 , 5 },
    {0xC02B , "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" , 3 , 3 , 128 , 4 },
    {0xC02C , "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" , 3 , 3 , 256 , 5 },
    {0xC010 , "TLS_ECDHE_RSA_WITH_NULL_SHA" , 3 , 1 , 0 , 2 },
    {0xC011 , "TLS_ECDHE_RSA_WITH_RC4_128_SHA" , 3 , 1 , 128 , 2 },
    {0xC012 , "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA" , 3 , 1 , 168 , 2 },
    {0xC013 , "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" , 3 , 1 , 128 , 2 },
    {0xC014 , "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA" , 3 , 1 , 256 , 2 },
    {0xC027 , "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256" , 3 , 1 , 128 , 4 },
    {0xC028 , "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384" , 3 , 1 , 256 , 5 },
    {0xC02F , "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" , 3 , 1 , 128 , 4 },
    {0xC030 , "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" , 3 , 1 , 256 , 5 },
    
    //DHE
    {0x0011 , "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA" , 2 , 2 , 40 , 2 },
    {0x0012 , "TLS_DHE_DSS_WITH_DES_CBC_SHA" , 2 , 2 , 56 , 2 },
    {0x0013 , "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA" , 2 , 2 , 168 , 2 },
    {0x0032 , "TLS_DHE_DSS_WITH_AES_128_CBC_SHA" , 2 , 2 , 128 , 2 },
    {0x0038 , "TLS_DHE_DSS_WITH_AES_256_CBC_SHA" , 2 , 2 , 256 , 2 },
    {0x0040 , "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256" , 2 , 2 , 128 , 4 },
    {0x0044 , "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA" , 2 , 2 , 128 , 2 },
    {0x0063 , "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA" , 2 , 2 , 56 , 2 },
    {0x0065 , "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA" , 2 , 2 , 56 , 2 },
    {0x0066 , "TLS_DHE_DSS_WITH_RC4_128_SHA" , 2 , 2 , 128 , 2 },
    {0x006A , "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256" , 2 , 2 , 256 , 4 },
    {0x0087 , "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA" , 2 , 2 , 256 , 2 },
    {0x0099 , "TLS_DHE_DSS_WITH_SEED_CBC_SHA" , 2 , 2 , 128 , 2 },
    {0x00A2 , "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256" , 2 , 2 , 128 , 4 },
    {0x00A3 , "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384" , 2 , 2 , 256 , 5 },
    {0x0014 , "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA" , 2 , 1 , 40 , 2 },
    {0x0015 , "TLS_DHE_RSA_WITH_DES_CBC_SHA" , 2 , 1 , 56 , 2 },
    {0x0016 , "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA" , 2 , 1 , 168 , 2 },
    {0x0033 , "TLS_DHE_RSA_WITH_AES_128_CBC_SHA" , 2 , 1 , 128 , 2 },
    {0x0039 , "TLS_DHE_RSA_WITH_AES_256_CBC_SHA" , 2 , 1 , 256 , 2 },
    {0x0045 , "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA" , 2 , 1 , 128 , 2 },
    {0x0067 , "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256" , 2 , 1 , 128 , 4 },
    {0x006B , "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256" , 2 , 1 , 256 , 4 },
    {0x0088 , "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA" , 2 , 1 , 256 , 2 },
    {0x009A , "TLS_DHE_RSA_WITH_SEED_CBC_SHA" , 2 , 1 , 128 , 2 },
    {0x009E , "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256" , 2 , 1 , 128 , 4 },
    {0x009F , "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384" , 2 , 1 , 256 , 5 }
};

const EVP_MD *get_hash_function(hash_algorithm h){
    switch (h) {
        case sha1:
            return EVP_sha();
            
        case sha256:
            return EVP_sha256();
        
        case sha384:
            return EVP_sha384();
        
        case md5:
            return EVP_md5();
            
        default:
            return NULL;
    }
}


cipher_suite_t get_cipher_suite(uint16_t id){
    int i=0;
    for(;i<cipher_suite_len && cipher_suite_list[i].cipher_id != id;i++);
    return cipher_suite_list[i];
}