/**
 *	SSL/TLS Project
 *	\file TLS.h
 *	This file provide a set of function for the TLS protocol.
 *
 *	\date Created on 13/01/16.
 *	\copyright Copyright © 2016 Alessandro Melloni, Andrea Francesco Vinci. All rights reserved.
 *
 */

#ifndef TLS_h
#define TLS_h
#include <stdio.h>
#include <time.h>
#include "ServerClientHandshakeProtocol.h"

/** Verbosity of the output */
extern int verbosity;

/** Connection parameters */
extern handshake_parameters_t connection_parameters;

#endif

/**
 * Do the handshake - client side.
 *
 *	\param to_send_cipher_suite_len: the number of cipher suites to add in the client hello
 *	\param to_send_cipher_suite: contains the choosen cipher suites for the client hello
 */
void do_client_handshake(int to_send_cipher_suite_len, cipher_suite_t to_send_cipher_suite[]);

/**
 * Do the handshake - server side.
 */
void do_server_handshake();

/**
 * Free the TLS connection parameters. 
 */
void free_tls_connection();
