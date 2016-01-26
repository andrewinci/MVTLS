//
//  Crypto.c
//  SSLXcodeProject
//
//  Created by Darka on 13/01/16.
//  Copyright © 2016 Darka. All rights reserved.
//

#include "Crypto.h"

int sign_with_RSA(unsigned char **signature, unsigned int *signature_length, int to_sign_len, unsigned char *to_sign);
int sign_with_DSS(unsigned char **signature, unsigned int *signature_length, int to_sign_len, unsigned char *to_sign);
int sign_with_ECDSA(unsigned char **signature, unsigned int *signature_length, int to_sign_len, unsigned char *to_sign);

void PRF(const EVP_MD *hash, unsigned char *secret, int secret_len, char *label, unsigned char *seed, int seed_len, int result_len, unsigned char **result){
    int buffer_size = ((1+result_len/hash->md_size)*hash->md_size);
    unsigned char *buff = malloc(buffer_size);
    int label_len = (int)strlen(label);
    *result = buff;
    
    //compute p_hash(secret,seed)
    //secret is equal to secret
    //seed is equal to label concatenate with seed
    unsigned char *seed_p = malloc(label_len+seed_len);
    memcpy(seed_p, label, label_len);
    memcpy(seed_p+label_len, seed, seed_len);
    
    //compute A_i
    int tot_len = 0;
    unsigned int a_len = label_len+seed_len;
    unsigned char *a = seed_p;
    while (tot_len<result_len) {
        unsigned char *temp = NULL;
        temp = HMAC(hash, secret, secret_len, a, a_len, NULL, &a_len);
        a = temp;
        memcpy(buff+tot_len, a, a_len);
        tot_len+=a_len;
    }
    free(seed_p);
}

int verify_DHE_server_key_ex_sign(X509 *certificate, unsigned char *client_random, unsigned char *server_random, DHE_server_key_exchange *server_key_ex, authentication_algorithm au) {
    
    //extract p g pubkey
    int p_len;
    unsigned char *p = malloc(BN_num_bytes(server_key_ex->p));
    p_len = BN_bn2bin(server_key_ex->p, p);
    
    int g_len;
    unsigned char *g = malloc(BN_num_bytes(server_key_ex->g));
    g_len = BN_bn2bin(server_key_ex->g, g);
    
    int pubkey_len;
    unsigned char *pubkey_char = malloc(BN_num_bytes(server_key_ex->pubKey));
    pubkey_len = BN_bn2bin(server_key_ex->pubKey, pubkey_char);
    
    
    const EVP_MD *sha1 = EVP_sha1();
    //compute sha1
    unsigned char sha1_digest[sha1->md_size];
    unsigned int sha1_len;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, sha1, NULL);
    EVP_DigestUpdate(mdctx, client_random, 32);
    EVP_DigestUpdate(mdctx, server_random, 32);
    EVP_DigestUpdate(mdctx, p, p_len);
    EVP_DigestUpdate(mdctx, g, g_len);
    EVP_DigestUpdate(mdctx, pubkey_char, pubkey_len);
    EVP_DigestFinal_ex(mdctx, sha1_digest, &sha1_len);
    EVP_MD_CTX_destroy(mdctx);
    
    const EVP_MD *md5 = EVP_md5();
    //compute md5
    unsigned char md5_digest[md5->md_size];
    unsigned int md5_len;
    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md5, NULL);
    EVP_DigestUpdate(mdctx, client_random, 32);
    EVP_DigestUpdate(mdctx, server_random, 32);
    EVP_DigestUpdate(mdctx, p, p_len);
    EVP_DigestUpdate(mdctx, g, g_len);
    EVP_DigestUpdate(mdctx, pubkey_char, pubkey_len);
    EVP_DigestFinal_ex(mdctx, md5_digest, &md5_len);
    EVP_MD_CTX_destroy(mdctx);
    
    //make stream to be encrypted
    int to_verify_len =sha1->md_size+md5->md_size;
    unsigned char *to_verify = malloc(sha1->md_size+md5->md_size);
    memcpy(to_verify, sha1_digest, sha1->md_size);
    memcpy(to_verify+sha1->md_size, md5_digest, md5->md_size);
    
    int result = 0;
    if(au == RSA_AU){
        
        EVP_PKEY *pubkey = NULL;
        RSA *rsa = NULL;
        
        pubkey = X509_get_pubkey(certificate);
        rsa = EVP_PKEY_get1_RSA(pubkey);
        
        result = RSA_verify(NID_md5_sha1, to_verify, to_verify_len, server_key_ex->signature, server_key_ex->signature_length, rsa);
        
        EVP_PKEY_free(pubkey);
        RSA_free(rsa);
        
    }else if(au == DSS_AU){
        EVP_PKEY *pubkey = NULL;
        DSA *dsa = NULL;
        
        pubkey = X509_get_pubkey(certificate);
        dsa = EVP_PKEY_get1_DSA(pubkey);
        
        result = DSA_verify(NID_md5_sha1, to_verify, to_verify_len, server_key_ex->signature, server_key_ex->signature_length, dsa);
        
        EVP_PKEY_free(pubkey);
        DSA_free(dsa);
    }
    free(to_verify);

    free(p);
    free(g);
    free(pubkey_char);

    return result;
}

int sign_DHE_server_key_ex(unsigned char *client_random, unsigned char *server_random, DHE_server_key_exchange *server_key_ex, authentication_algorithm au) {
    
    //extract p g pubkey
    int p_len;
    unsigned char *p = malloc(BN_num_bytes(server_key_ex->p));
    p_len = BN_bn2bin(server_key_ex->p, p);
    
    int g_len;
    unsigned char *g = malloc(BN_num_bytes(server_key_ex->g));
    g_len = BN_bn2bin(server_key_ex->g, g);
    
    int pubkey_len;
    unsigned char *pubkey_char = malloc(BN_num_bytes(server_key_ex->pubKey));
    pubkey_len = BN_bn2bin(server_key_ex->pubKey, pubkey_char);
    
    
    const EVP_MD *sha1 = EVP_sha1();
    //compute sha1
    unsigned char sha1_digest[sha1->md_size];
    unsigned int sha1_len;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, sha1, NULL);
    EVP_DigestUpdate(mdctx, client_random, 32);
    EVP_DigestUpdate(mdctx, server_random, 32);
    EVP_DigestUpdate(mdctx, p, p_len);
    EVP_DigestUpdate(mdctx, g, g_len);
    EVP_DigestUpdate(mdctx, pubkey_char, pubkey_len);
    EVP_DigestFinal_ex(mdctx, sha1_digest, &sha1_len);
    EVP_MD_CTX_destroy(mdctx);
    
    const EVP_MD *md5 = EVP_md5();
    //compute md5
    unsigned char md5_digest[md5->md_size];
    unsigned int md5_len;
    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md5, NULL);
    EVP_DigestUpdate(mdctx, client_random, 32);
    EVP_DigestUpdate(mdctx, server_random, 32);
    EVP_DigestUpdate(mdctx, p, p_len);
    EVP_DigestUpdate(mdctx, g, g_len);
    EVP_DigestUpdate(mdctx, pubkey_char, pubkey_len);
    EVP_DigestFinal_ex(mdctx, md5_digest, &md5_len);
    EVP_MD_CTX_destroy(mdctx);
    
    //make stream to be encrypted
    int to_sign_len = sha1->md_size+md5->md_size;
    unsigned char *to_sign = (unsigned char *)malloc(to_sign_len*sizeof(unsigned char));
    
    memcpy(to_sign, sha1_digest, sha1->md_size);
    memcpy(to_sign+sha1->md_size, md5_digest, md5->md_size);
    
    int res = 0;
    
    switch (au) {
        case RSA_AU:
            res = sign_with_RSA(&server_key_ex->signature, &server_key_ex->signature_length, to_sign_len, to_sign);
            break;
        case DSS_AU:
            res = sign_with_DSS(&server_key_ex->signature, &server_key_ex->signature_length, to_sign_len, to_sign);
            break;
        default:
            printf("\nerror in sign\n");
            break;
    }
    
    free(p);
    free(g);
    free(pubkey_char);
    free(to_sign);
    return res;
}

int sign_ECDHE_server_key_ex(unsigned char *client_random, unsigned char *server_random, ECDHE_server_key_exchange *server_key_ex, authentication_algorithm au){
    
    //RFC 4492
    int pubkey_len;
    unsigned char *pubkey_char = malloc(BN_num_bytes(server_key_ex->pub_key));
    pubkey_len = BN_bn2bin(server_key_ex->pub_key, pubkey_char);

    
    const EVP_MD *sha1 = EVP_sha1();
    //compute sha1
    unsigned char sha1_digest[sha1->md_size];
    unsigned int sha1_len;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, sha1, NULL);
    EVP_DigestUpdate(mdctx, client_random, 32);
    EVP_DigestUpdate(mdctx, server_random, 32);
    EVP_DigestUpdate(mdctx, &server_key_ex->named_curve, 2);
    EVP_DigestUpdate(mdctx, pubkey_char, pubkey_len);
    EVP_DigestFinal_ex(mdctx, sha1_digest, &sha1_len);
    EVP_MD_CTX_destroy(mdctx);
    
    const EVP_MD *md5 = EVP_md5();
    //compute md5
    unsigned char md5_digest[md5->md_size];
    unsigned int md5_len;
    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md5, NULL);
    EVP_DigestUpdate(mdctx, client_random, 32);
    EVP_DigestUpdate(mdctx, server_random, 32);
    EVP_DigestUpdate(mdctx, &server_key_ex->named_curve, 2);
    EVP_DigestUpdate(mdctx, pubkey_char, pubkey_len);

    EVP_DigestFinal_ex(mdctx, md5_digest, &md5_len);
    EVP_MD_CTX_destroy(mdctx);

    int to_sign_len = md5->md_size + sha1->md_size;
    unsigned char *to_sign = (unsigned char*)malloc(sizeof(unsigned char)*to_sign_len);

    memcpy(to_sign, sha1_digest, sha1->md_size);
    memcpy(to_sign+sha1->md_size, md5_digest, md5->md_size);

    int res=0;
    switch (au) {
        case RSA_AU:
            res = sign_with_RSA(&server_key_ex->signature, &server_key_ex->signature_length, to_sign_len, to_sign);
            break;
        case ECDSA_AU:
            res = sign_with_ECDSA(&server_key_ex->signature, &server_key_ex->signature_length, to_sign_len, to_sign);
        default:
            break;
    }
    
    printf("\nsignature:\n");
    for(int i=0;i<server_key_ex->signature_length;i++)
        printf("%02X ",server_key_ex->signature[i] );
    
    free(pubkey_char);
    return res;
}

int verify_ECDHE_server_key_ex_sign(X509 *certificate, unsigned char *client_random, unsigned char *server_random, ECDHE_server_key_exchange *server_key_ex, authentication_algorithm au){
    
    printf("\nsignature:\n");
    for(int i=0;i<server_key_ex->signature_length;i++)
        printf("%02X ",server_key_ex->signature[i]);
    
    
    int pubkey_len;
    unsigned char *pubkey_char = malloc(BN_num_bytes(server_key_ex->pub_key));
    pubkey_len = BN_bn2bin(server_key_ex->pub_key, pubkey_char);
    
    
    const EVP_MD *sha1 = EVP_sha1();
    //compute sha1
    unsigned char sha1_digest[sha1->md_size];
    unsigned int sha1_len;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, sha1, NULL);
    EVP_DigestUpdate(mdctx, client_random, 32);
    EVP_DigestUpdate(mdctx, server_random, 32);
    EVP_DigestUpdate(mdctx, &server_key_ex->named_curve, 2);
    EVP_DigestUpdate(mdctx, pubkey_char, pubkey_len);
    EVP_DigestFinal_ex(mdctx, sha1_digest, &sha1_len);
    EVP_MD_CTX_destroy(mdctx);
    
    const EVP_MD *md5 = EVP_md5();
    //compute md5
    unsigned char md5_digest[md5->md_size];
    unsigned int md5_len;
    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md5, NULL);
    EVP_DigestUpdate(mdctx, client_random, 32);
    EVP_DigestUpdate(mdctx, server_random, 32);
    EVP_DigestUpdate(mdctx, &server_key_ex->named_curve, 2);
    EVP_DigestUpdate(mdctx, pubkey_char, pubkey_len);
    
    EVP_DigestFinal_ex(mdctx, md5_digest, &md5_len);
    EVP_MD_CTX_destroy(mdctx);

    
    //make stream to be encrypted
    int to_verify_len =sha1->md_size+md5->md_size;
    unsigned char *to_verify = malloc(sha1->md_size+md5->md_size);
    memcpy(to_verify, sha1_digest, sha1->md_size);
    memcpy(to_verify+sha1->md_size, md5_digest, md5->md_size);
    
    int result = 0;
    if(au == RSA_AU){
        
        EVP_PKEY *pubkey = NULL;
        RSA *rsa = NULL;
        
        pubkey = X509_get_pubkey(certificate);
        rsa = EVP_PKEY_get1_RSA(pubkey);
        
        result = RSA_verify(NID_md5_sha1, to_verify, to_verify_len, server_key_ex->signature, server_key_ex->signature_length, rsa);
        
        EVP_PKEY_free(pubkey);
        RSA_free(rsa);
        
    }else if(au == ECDSA_AU){
        EVP_PKEY *pubkey = NULL;
        EC_KEY *ecdsa = NULL;
        
        pubkey = X509_get_pubkey(certificate);
        ecdsa = EVP_PKEY_get1_EC_KEY(pubkey);
        
        // ToDo:ERROR, INVALID SIGNATURE
        result = ECDSA_verify(NID_md5_sha1, to_verify, to_verify_len, server_key_ex->signature, server_key_ex->signature_length, ecdsa);
        
        EVP_PKEY_free(pubkey);
        EC_KEY_free(ecdsa);
    }
    free(to_verify);
    free(pubkey_char);
    
    return result;
}

int sign_with_DSS(unsigned char **signature, unsigned int *signature_length, int to_sign_len, unsigned char *to_sign){
    // get private key for sign
    FILE *private_key_file = fopen("../certificates/serverDSA.key", "r");
    if (!private_key_file) {
        fprintf(stderr, "unable to open DSA private key file, store it in : certificates/serverDSA.key\n");
        exit(-1);
    }
    
    DSA *dsa_private = PEM_read_DSAPrivateKey(private_key_file, NULL, NULL, NULL);
    fclose(private_key_file);
    
    //allocate memory for signature
    *signature = malloc(DSA_size(dsa_private));
    
    int res = DSA_sign(NID_md5_sha1, to_sign, to_sign_len, *signature, signature_length, dsa_private );
    
    DSA_free(dsa_private);
    
    return res;
}

int sign_with_RSA(unsigned char **signature, unsigned int *signature_length, int to_sign_len, unsigned char *to_sign) {
    //get private key from file
    int res;
    RSA *rsa_private = NULL;
    FILE *fp;
    
    if(NULL != (fp= fopen("../certificates/serverRSA.key", "r")) )
    {
        rsa_private=PEM_read_RSAPrivateKey(fp,NULL,NULL,NULL);
        if(rsa_private==NULL)
        {
            printf("\nunable to open RSA private key, store it in : ../certificates/serverRSA.key\n");
            exit(-1);
        }
    }
    fclose(fp);
    
    //allocate memory for signature
    *signature = malloc(RSA_size(rsa_private));
    
    res = RSA_sign(NID_md5_sha1, to_sign, to_sign_len, *signature, signature_length, rsa_private);
    
    RSA_free(rsa_private);
    return res;
}

int sign_with_ECDSA(unsigned char **signature, unsigned int *signature_length, int to_sign_len, unsigned char *to_sign){
    // get private key for sign
    FILE *private_key_file = fopen("../certificates/serverECDSA.key", "r");
    if (!private_key_file) {
        fprintf(stderr, "unable to open ECDSA private key file, store it in : certificates/serverECDSA.key\n");
        exit(-1);
    }
    
    EC_KEY *ecdsa_private = PEM_read_ECPrivateKey(private_key_file, NULL, NULL, NULL);
    
    fclose(private_key_file);
    
    //allocate memory for signature
    *signature = malloc(ECDSA_size(ecdsa_private));
    
    int res = ECDSA_sign(NID_md5_sha1, to_sign, to_sign_len, *signature, signature_length, ecdsa_private );
    
    EC_KEY_free(ecdsa_private);
    
    return res;
}

