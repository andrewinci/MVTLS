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
    {0x000001 , "TLS_RSA_WITH_NULL_MD5" , 1 , 1 , 0 , 1 },
    {0x000002 , "TLS_RSA_WITH_NULL_SHA" , 1 , 1 , 0 , 2 },
    {0x000004 , "TLS_RSA_WITH_RC4_128_MD5" , 1 , 1 , 128 , 1 },
    {0x000005 , "TLS_RSA_WITH_RC4_128_SHA" , 1 , 1 , 128 , 2 },
    {0x000007 , "TLS_RSA_WITH_IDEA_CBC_SHA" , 1 , 1 , 128 , 2 },
    {0x000009 , "TLS_RSA_WITH_DES_CBC_SHA" , 1 , 1 , 56 , 2 },
    {0x00000A , "TLS_RSA_WITH_3DES_EDE_CBC_SHA" , 1 , 1 , 168 , 2 },
    {0x00002F , "TLS_RSA_WITH_AES_128_CBC_SHA" , 1 , 1 , 128 , 2 },
    {0x000035 , "TLS_RSA_WITH_AES_256_CBC_SHA" , 1 , 1 , 256 , 2 },
    {0x00003B , "TLS_RSA_WITH_NULL_SHA256" , 1 , 1 , 0 , 4 },
    {0x00003C , "TLS_RSA_WITH_AES_128_CBC_SHA256" , 1 , 1 , 128 , 4 },
    {0x00003D , "TLS_RSA_WITH_AES_256_CBC_SHA256" , 1 , 1 , 256 , 4 },
    {0x000041 , "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA" , 1 , 1 , 128 , 2 },
    {0x000084 , "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA" , 1 , 1 , 256 , 2 },
    {0x000096 , "TLS_RSA_WITH_SEED_CBC_SHA" , 1 , 1 , 128 , 2 },
    {0x00009C , "TLS_RSA_WITH_AES_128_GCM_SHA256" , 1 , 1 , 128 , 4 },
    {0x00009D , "TLS_RSA_WITH_AES_256_GCM_SHA384" , 1 , 1 , 256 , 5 },

    //ECDHE
    {0x00C006 , "TLS_ECDHE_ECDSA_WITH_NULL_SHA" , 3 , 3 , 0 , 2 },
    {0x00C007 , "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA" , 3 , 3 , 128 , 2 },
    {0x00C008 , "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA" , 3 , 3 , 168 , 2 },
    {0x00C009 , "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA" , 3 , 3 , 128 , 2 },
    {0x00C00A , "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA" , 3 , 3 , 256 , 2 },
    {0x00C023 , "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256" , 3 , 3 , 128 , 4 },
    {0x00C024 , "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384" , 3 , 3 , 256 , 5 },
    {0x00C02B , "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" , 3 , 3 , 128 , 4 },
    {0x00C02C , "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" , 3 , 3 , 256 , 5 },
    {0x00C010 , "TLS_ECDHE_RSA_WITH_NULL_SHA" , 3 , 1 , 0 , 2 },
    {0x00C011 , "TLS_ECDHE_RSA_WITH_RC4_128_SHA" , 3 , 1 , 128 , 2 },
    {0x00C012 , "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA" , 3 , 1 , 168 , 2 },
    {0x00C013 , "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" , 3 , 1 , 128 , 2 },
    {0x00C014 , "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA" , 3 , 1 , 256 , 2 },
    {0x00C027 , "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256" , 3 , 1 , 128 , 4 },
    {0x00C028 , "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384" , 3 , 1 , 256 , 5 },
    {0x00C02F , "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" , 3 , 1 , 128 , 4 },
    {0x00C030 , "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" , 3 , 1 , 256 , 5 },

    //DHE
    {0x000011 , "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA" , 2 , 2 , 40 , 2 },
    {0x000012 , "TLS_DHE_DSS_WITH_DES_CBC_SHA" , 2 , 2 , 56 , 2 },
    {0x000013 , "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA" , 2 , 2 , 168 , 2 },
    {0x000032 , "TLS_DHE_DSS_WITH_AES_128_CBC_SHA" , 2 , 2 , 128 , 2 },
    {0x000038 , "TLS_DHE_DSS_WITH_AES_256_CBC_SHA" , 2 , 2 , 256 , 2 },
    {0x000040 , "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256" , 2 , 2 , 128 , 4 },
    {0x000044 , "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA" , 2 , 2 , 128 , 2 },
    {0x000063 , "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA" , 2 , 2 , 56 , 2 },
    {0x000065 , "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA" , 2 , 2 , 56 , 2 },
    {0x000066 , "TLS_DHE_DSS_WITH_RC4_128_SHA" , 2 , 2 , 128 , 2 },
    {0x00006A , "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256" , 2 , 2 , 256 , 4 },
    {0x000087 , "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA" , 2 , 2 , 256 , 2 },
    {0x000099 , "TLS_DHE_DSS_WITH_SEED_CBC_SHA" , 2 , 2 , 128 , 2 },
    {0x0000A2 , "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256" , 2 , 2 , 128 , 4 },
    {0x0000A3 , "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384" , 2 , 2 , 256 , 5 },
    {0x000014 , "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA" , 2 , 1 , 40 , 2 },
    {0x000015 , "TLS_DHE_RSA_WITH_DES_CBC_SHA" , 2 , 1 , 56 , 2 },
    {0x000016 , "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA" , 2 , 1 , 168 , 2 },
    {0x000033 , "TLS_DHE_RSA_WITH_AES_128_CBC_SHA" , 2 , 1 , 128 , 2 },
    {0x000039 , "TLS_DHE_RSA_WITH_AES_256_CBC_SHA" , 2 , 1 , 256 , 2 },
    {0x000045 , "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA" , 2 , 1 , 128 , 2 },
    {0x000067 , "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256" , 2 , 1 , 128 , 4 },
    {0x00006B , "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256" , 2 , 1 , 256 , 4 },
    {0x000088 , "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA" , 2 , 1 , 256 , 2 },
    {0x00009A , "TLS_DHE_RSA_WITH_SEED_CBC_SHA" , 2 , 1 , 128 , 2 },
    {0x00009E , "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256" , 2 , 1 , 128 , 4 },
    {0x00009F , "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384" , 2 , 1 , 256 , 5 }
};


// Key exchange

const int RSA_IDS_NUM = 28;
const uint16_t RSA_IDS[] = {0x0001, 0x0002, 0x0004, 0x0005, 0x0007, 0x0009, 0x000A, 0x002E, 0x002F, 0x0035, 0x003B, 0x003C, 0x003D, 0x0041, 0x0084, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x009C, 0x009D, 0x00AC, 0x00AD, 0x00B6, 0x00B7, 0x00B8, 0x00B9
};

const int DHE_IDS_NUM = 12;
const uint16_t DHE_IDS[] = {0x0016, 0x0033, 0x0067, 0x009E, 0x0039, 0x006B, 0x009F, 0x0045, 0x0088, 0x0015, 0x0014, 0x009A};

// Hash
const int SHA_IDS_NUM = 55;
const uint16_t SHA_IDS[] = {0x000B, 0x000C, 0x000D, 0x0030, 0x0036, 0x0042, 0x0085, 0x0097, 0x000E, 0x000F, 0x0010, 0x0031, 0x0037, 0x0043, 0x0086, 0x0098,
    0x0002, 0x0005, 0x0007, 0x0009, 0x000A, 0x002E, 0x002F, 0x0035, 0x0041, 0x0084, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x000013, 0x0032, 0x0038, 0x0044, 0x0087, 0x0012, 0x0063, 0x0011, 0x0066, 0x0065, 0x0099, 0x008F, 0x0090, 0x0091, 0x002D, 0x008E, 0x0016, 0x0033, 0x0039, 0x0045, 0x0088, 0x0015, 0x0014, 0x009A
};

const int SHA256_IDS_NUM = 22;
const uint16_t SHA256_IDS[]={0x00003E, 0x0068, 0x00A4, 0x003F, 0x0069, 0x00A0, 0x003B, 0x003C, 0x003D, 0x009C, 0x00AC, 0x00B6, 0x00B8, 0x000040, 0x00A2, 0x006A, 0x00B2, 0x00AA, 0x00B4, 0x0067, 0x009E, 0x006B
};

const int SHA384_IDS_NUM = 11;
const uint16_t SHA384_IDS[] = {0x00A5, 0x00A1, 0x009D, 0x00AD, 0x00B7, 0x00B9, 0x00A3, 0x00B3, 0x00AB, 0x00B5, 0x009F
};

const int MD5_IDS_NUM = 2;
const uint16_t MD5_IDS[] = {0x0001, 0x0004
};



key_exchange_algorithm get_kx_algorithm(uint16_t cipher_suite_Id){

    for(int i=0;i<RSA_IDS_NUM;i++)
        if(RSA_IDS[i]==cipher_suite_Id)
            return RSA_KX;
    
    for(int i=0;i<DHE_IDS_NUM;i++)
        if(DHE_IDS[i]==cipher_suite_Id)
            return DHE_RSA_KX;
    
    return 0;
}

const EVP_MD *get_hash_function(uint16_t cipher_suite_Id){
    for(int i=0;i<SHA_IDS_NUM;i++)
        if(SHA_IDS[i]==cipher_suite_Id)
            return EVP_sha();
    
    for(int i=0;i<SHA256_IDS_NUM;i++)
        if(SHA256_IDS[i]==cipher_suite_Id)
            return EVP_sha256();
    
    for(int i=0;i<SHA384_IDS_NUM;i++)
        if(SHA384_IDS[i]==cipher_suite_Id)
            return EVP_sha384();
    
    for(int i=0;i<MD5_IDS_NUM;i++)
        if(MD5_IDS[i]==cipher_suite_Id)
            return EVP_md5();
    return NULL;
}


char * readable_cipher_suite(uint16_t cipher_suite){
    return NULL;
}