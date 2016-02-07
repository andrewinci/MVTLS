/**
 *	SSL/TLS Project
 *	\file TLS.h
 *	This file provide a set of function for the TLS
 *	handshake. The function are used to make TLS message
 *	for both server and client.
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


/** verbosity of the output */
extern int verbosity;

/** connection parameters */
extern handshake_parameters_t TLS_param;

#endif

void onClientPacketReceive(channel_t *channel, packet_transport_t *p);

void do_client_handshake(int to_send_cipher_suite_len, cipher_suite_t to_send_cipher_suite[]);

void compute_set_master_key_RSA(client_key_exchange_t *client_key_exchange);

void compute_set_master_key_DHE(client_key_exchange_t *client_key_exchange);

void compute_set_master_key_ECDHE(client_key_exchange_t *client_key_exchange);

void onServerPacketReceive(channel_t *channel, packet_transport_t *p);

void do_server_handshake();