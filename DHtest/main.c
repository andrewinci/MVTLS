//
//  main.c
//  DHtest
//
//  Created by Darka on 11/01/16.
//  Copyright © 2016 Darka. All rights reserved.
//

#include <stdio.h>
#include <openssl/dh.h>

typedef struct{
    BIGNUM *p;
    
    BIGNUM *g;
    
    BIGNUM *pubKey;
    
    //signature hash algorithm, 1 for hash, 1 for signature alg
    uint16_t sign_hash_alg; //SHA512, RSA 0x0601
    
    uint16_t signature_length;
    char *signature;
}DH_server_key_exchange;


int main(int argc, const char * argv[]) {
    DH *privkey;
    int codes; //for handle errors
    int secret_size;
    
    /* Generate the parameters to be used */
    if(NULL == (privkey = DH_new())){
        printf("error in DH new\n");
    }
    if(1 != DH_generate_parameters_ex(privkey, 1, DH_GENERATOR_5 , NULL)){
         printf("error in parameter generate\n");
    }
    
    if(1 != DH_check(privkey, &codes)){
         printf("error in DH check\n");
    }
    if(codes != 0)
    {
        /* Problems have been found with the generated parameters */
        /* Handle these here - we'll just abort for this example */
        printf("DH_check failed\n");
        abort();
    }
    
    /* Generate the public and private key pair */
    if(1 != DH_generate_key(privkey)){
        printf("Error in DH_generate_key\n");
    }
    
    // get and print private key
    char *private_key_char;
    private_key_char = BN_bn2hex(privkey->p);
    printf("\n Private key : %s\n",private_key_char);
    
    //get and print public key
    char *public_key_char;
    public_key_char = BN_bn2hex(privkey->pub_key);
    printf("\n Public key : %s\n",public_key_char);
    
    /* Send the public key to the peer.
     * How this occurs will be specific to your situation (see main text below) */
    
    //CLIENT PART
    
    /* Receive the public key from the peer. In this example we're just hard coding a value */
    BIGNUM *pubkey = NULL;
    if(0 == (BN_dec2bn(&pubkey, "01234567890123456789012345678901234567890123456789"))){
        printf("error in parsing public key\n");
    }
    /* Compute the shared secret */
    unsigned char *secret;
    if(NULL == (secret = OPENSSL_malloc(sizeof(unsigned char) * (DH_size(privkey))))){
        printf("Error in compute shared secret\n");
    }
    
    if(0 > (secret_size = DH_compute_key(secret, pubkey, privkey))){
        printf("error in DH_compute_key\n");
    }
    
    /* Do something with the shared secret */
    /* Note secret_size may be less than DH_size(privkey) */
    printf("The shared secret is:\n");
    BIO_dump_fp(stdout, (const char *)secret, secret_size);
    
    /* Clean up */
    OPENSSL_free(secret);
    BN_free(pubkey);
    DH_free(privkey);
    printf("ok");
    return 0;
}



