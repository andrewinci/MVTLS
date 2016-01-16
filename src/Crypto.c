//
//  Crypto.c
//  SSLXcodeProject
//
//  Created by Darka on 13/01/16.
//  Copyright © 2016 Darka. All rights reserved.
//

#include "Crypto.h"

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

//int verify_signature( unsigned char *message, int message_len, unsigned char *signature, int signature_len ) {
//    unsigned char *decrypted_signature = NULL;
//    int decrypted_signature_length;
//    
//    const EVP_MD *sha1 = EVP_sha1();
//    //compute sha1
//    unsigned char sha1_digest[EVP_MAX_MD_SIZE];
//    unsigned int sha1_len;
//    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
//    EVP_DigestInit_ex(mdctx, sha1, NULL);
//    EVP_DigestUpdate(mdctx, parameters->client_random, 32);
//    EVP_DigestUpdate(mdctx, parameters->server_random, 32);
//    EVP_DigestUpdate(mdctx, message, message_len);
//    EVP_DigestFinal_ex(mdctx, sha1_digest, &sha1_len);
//    EVP_MD_CTX_destroy(mdctx);
//    
//    const EVP_MD *md5 = EVP_md5();
//    //compute sha1
//    unsigned char md5_digest[EVP_MAX_MD_SIZE];
//    unsigned int md5_len;
//    mdctx = EVP_MD_CTX_create();
//    EVP_DigestInit_ex(mdctx, md5, NULL);
//    EVP_DigestUpdate(mdctx, parameters->client_random, 32);
//    EVP_DigestUpdate(mdctx, parameters->server_random, 32);
//    EVP_DigestUpdate(mdctx, message, message_len);
//    EVP_DigestFinal_ex(mdctx, md5_digest, &md5_len);
//    EVP_MD_CTX_destroy(mdctx);
//    
//    uint16_t kx_alg = get_kx_algorithm(parameters->cipher_suite);
//    if(kx_alg == DHE_RSA_KX){
//        //verify RSA sign
//        EVP_PKEY *pubkey = NULL;
//        RSA *rsa = NULL;
//        
//        pubkey = X509_get_pubkey(parameters->server_certificate);
//        rsa = EVP_PKEY_get1_RSA(pubkey);
//        
//        decrypted_signature_length = RSA_public_decrypt(signature_len, signature, decrypted_signature, rsa, RSA_PKCS1_PADDING);
//        
//        //verify with memcmp
//        if ( memcmp( sha1_digest, decrypted_signature, sha1->md_size ) || memcmp( md5_digest, decrypted_signature + sha1->md_size, md5->md_size ) ) {
//            
//            return 0;
//        }
//    }else if (kx_alg == DHE_DSS_KX){
//        //verify DSA sign
//    }
//    free(decrypted_signature);
//    return 1;
//    
//}

int sign_DH_server_key_ex(uint16_t kx_alg, unsigned char *client_random, unsigned char *server_random, DH_server_key_exchange *server_key_ex) {
    
    //extract p g pubkey
    int p_len;
    unsigned char *p = malloc(BN_num_bytes(server_key_ex->p));
    p_len = BN_bn2bin(server_key_ex->p, p);
    
    int g_len;
    unsigned char *g = malloc(BN_num_bytes(server_key_ex->g));
    g_len = BN_bn2bin(server_key_ex->g, g);
    
    int pubkey_len;
    unsigned char *pubkey = malloc(BN_num_bytes(server_key_ex->pubKey));
    pubkey_len = BN_bn2bin(server_key_ex->pubKey, pubkey);
    
    
    const EVP_MD *sha1 = EVP_sha1();
    //compute sha1
    unsigned char sha1_digest[EVP_MAX_MD_SIZE];
    unsigned int sha1_len;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, sha1, NULL);
    EVP_DigestUpdate(mdctx, client_random, 32);
    EVP_DigestUpdate(mdctx, server_random, 32);
    EVP_DigestUpdate(mdctx, p, p_len);
    EVP_DigestUpdate(mdctx, g, g_len);
    EVP_DigestUpdate(mdctx, pubkey, pubkey_len);
    EVP_DigestFinal_ex(mdctx, sha1_digest, &sha1_len);
    EVP_MD_CTX_destroy(mdctx);
    
    const EVP_MD *md5 = EVP_md5();
    //compute md5
    unsigned char md5_digest[EVP_MAX_MD_SIZE];
    unsigned int md5_len;
    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md5, NULL);
    EVP_DigestUpdate(mdctx, client_random, 32);
    EVP_DigestUpdate(mdctx, server_random, 32);
    EVP_DigestUpdate(mdctx, p, p_len);
    EVP_DigestUpdate(mdctx, g, g_len);
    EVP_DigestUpdate(mdctx, pubkey, pubkey_len);
    EVP_DigestFinal_ex(mdctx, md5_digest, &md5_len);
    EVP_MD_CTX_destroy(mdctx);
    
    //make stream to be encrypted
    unsigned char *to_enc = malloc(sha1->md_size+md5->md_size);
    memcpy(to_enc, sha1_digest, sha1->md_size);
    memcpy(to_enc+sha1->md_size, md5_digest, md5->md_size);
    
    if(/* DISABLES CODE */ (1)){
        
        //sign with RSA
        EVP_PKEY *prvkey = NULL;
        RSA *rsa = NULL;
        //TODO get private key
        //prvkey = X509_get_pubkey(parameters->server_certificate);
        rsa = EVP_PKEY_get1_RSA(prvkey);
        
        //alocate memory for signature
        server_key_ex->signature = malloc(RSA_size(rsa));
        server_key_ex->signature_length = RSA_private_encrypt(sha1->md_size+md5->md_size, to_enc, server_key_ex->signature, rsa, RSA_PKCS1_PADDING);
    }else if (kx_alg == DHE_DSS_KX){
        //sign with dsa
    }
    
    //free and return
    free(p);
    free(g);
    free(pubkey);
    free(to_enc);
    return 1;
}






