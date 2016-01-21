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

int verify_DH_server_key_ex_sign(X509 *certificate, unsigned char *client_random, unsigned char *server_random, DHE_server_key *server_key_ex) {
    
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
    unsigned char sha1_digest[EVP_MAX_MD_SIZE];
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
    unsigned char md5_digest[EVP_MAX_MD_SIZE];
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
    
    
    
    //ToDo : distinguish between rsa and dsa signature
    EVP_PKEY *pubkey = NULL;
    RSA *rsa = NULL;
    
    pubkey = X509_get_pubkey(certificate);
    rsa = EVP_PKEY_get1_RSA(pubkey);
    
    EVP_PKEY_free(pubkey);
    
    //encrypt pre_master_key
    unsigned char *decrypted_signature = malloc(RSA_size(rsa));
    RSA_public_decrypt(server_key_ex->signature_length, server_key_ex->signature, decrypted_signature, rsa, RSA_PKCS1_PADDING);
    RSA_free(rsa);
    
    //verify
    int result = 1;
    if ( memcmp( sha1_digest, decrypted_signature, sha1->md_size ) || memcmp( md5_digest, decrypted_signature + sha1->md_size, md5->md_size ) )
        result = 0;
    
    free(p);
    free(g);
    free(pubkey_char);

    return result;
}

int sign_DHE_server_key_ex(unsigned char *client_random, unsigned char *server_random, DHE_server_key *server_key_ex) {
    
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
    
    //get private key from file
    RSA *privateKey = NULL;
    FILE *fp;
    
    if(NULL != (fp= fopen("../certificates/server.key", "r")) )
    {
        privateKey=PEM_read_RSAPrivateKey(fp,NULL,NULL,NULL);
        if(privateKey==NULL)
        {
            printf("\nerror in retrieve private key");
            exit(-1);
        }
    }
    fclose(fp);
    
    //ToDo : distinguish between rsa and dsa signature
    
    //alocate memory for signature
    server_key_ex->signature = malloc(RSA_size(privateKey));
    server_key_ex->signature_length = RSA_private_encrypt(sha1->md_size+md5->md_size, to_enc, server_key_ex->signature, privateKey, RSA_PKCS1_PADDING);
    
    free(p);
    free(g);
    free(pubkey);
    free(to_enc);
    RSA_free(privateKey);
    return 1;
}






