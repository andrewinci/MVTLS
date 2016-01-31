//
//  SSL/TLS Project
//  ServerClientFileSocket.h
//  Basic client/server communication through file.
//
//  PROTOCOL:
//  The protocol is very basic
//  8 byte for source
//  8 byte for receiver
//  4 byte for packet length
//  message
//
//  both server and client after read a message they blank the file
//  both server and client cannot write if the file is not blank, they wait
//
//
//  Created on 22/12/15.
//  Copyright © 2015 Mello, Darka. All rights reserved.
//

#ifndef ServerClientBasic_h
#define ServerClientBasic_h

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <pthread.h>
#include <time.h>

#endif

#define DELAY_TIME 50

#ifndef struct_packet
#define struct_packet
/** This struct substitute the TCP in our implementation*/
typedef struct{
	/** Packet source name, 8 Byte length*/
	char *source;

	/** Packet destination name, 8 Byte length*/
	char *destination;

	/** Message to send length*/
	uint32_t length;

	/** Message byte stream of lenght lenght*/
	unsigned char *message;
}packet_basic_t;
#endif

#ifndef struct_channel
#define struct_channel
/** \struct channel Struct for model and manage a file channel
 between client and server*/
typedef struct channel_t{
	/** Channel source name e.g. server*/
	char *channel_source;

	/** Channel destination name e.g. client*/
	char *channel_destination;

	/** File to use for exchange messages,
	the channel between client and server */
	char *fileName;

	/** Channel file descriptor */
	int fd;

	/** Function to be called when a packet is received */
	void (*onPacketReceive)(struct channel_t *ch, packet_basic_t *p);

	/** If the listener is running it is setted to 1 otherwise it is 0*/
	int isEnabled;

	/** Secondary thread for reading/writing */
	pthread_t thread;
}channel_t;
#endif

/*
 * Create a server/client using the fileName as comunication channel
 *
 * fileName : file name of the channel
 * serverName : name of the server/client
 * return the created channel
 */
channel_t *create_channel(char *fileName, char *channelFrom, char *channelTo);

/*
 * Set the function to be called when a message is received
 *
 * ch : channel interested
 * onPacketReceive : pointer to the function
 * return : 1 if the function was setted, 0 otherwise
 */
int set_on_receive(channel_t *ch, void (*onPacketReceive)(channel_t *ch, packet_basic_t *p));

/**
 * Send a message trough the channel ch
 *
 * ch : channel to be used
 * p : pointer to packet to be sent
 * return : 1 if the message was sent, 0 otherwise
 */
int send_packet(channel_t *ch, packet_basic_t *p);

/**
 * Start the channel. We open another thread for the reading
 * and the current thread for writing. From now on (if the operation
 * is succesfull) the client/server read continously from channel.
 * (for STOP use stop())
 *
 * ch : channel to start
 * return : 1 if the thread was started, 0 otherwise
 */
int start_listener(channel_t *ch);

/*
 * Stop the main and wait untill stop is called
 */
void wait_channel(channel_t *ch);

/**
 * Stop the reading/write thread and the channel.
 * Note: the function doesn't free the channel.
 * \param ch : channel to stop
 */
void stop_channel(channel_t *ch);

/**
 * Create a packet starting from a byte stream 
 * source and destination
 *
 * \param source        : packet source
 * \param destination   : packet receiver
 * \param message       : message stream to be 
                        encapsulate into packet
 * \param message_length: message lenght
 * \return a pointer to a builded packet
 */
packet_basic_t *create_packet(char *source, char *destination, unsigned char *message, uint32_t message_length);

/**
 * Delete and free memory allocated by packet
 * \param p : pointer to packet to free
 */
void free_packet(packet_basic_t *p);
