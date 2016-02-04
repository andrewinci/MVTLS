/**
 *	SSL/TLS Project
 *	\file ServerClientTransportProtocol.h
 *	Basic client/server communication through file. 
 *	It substitutes the transport layer in OSI stack.
 *
 *	PROTOCOL:
 *	The protocol is very simple
 *	8 byte for source
 *	8 byte for receiver
 *	4 byte for packet length
 *	message
 *
 *	Both server and client, after reading a message, blank the file
 *	both server and client cannot write if the file is not blank, they wait
 *
 *
 *	\date Created on 22/12/15.
 *	\copyright Copyright © 2015 Alessandro Melloni, Andrea Francesco Vinci. All rights reserved.
 */

#ifndef ServerClientTransportProtocol_h
#define ServerClientTransportProtocol_h

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

/** \def DELAY_TIME 
 *	the time to wait between 2 readings of the file.
 *	Important to don't use too much CPU.
 */
#define DELAY_TIME 50

/** \struct packet_basic
 * This struct substitutes the transport layer in our implementation
 */
typedef struct{
	/** Packet source name, 8 bytes length*/
	char *source;

	/** Packet destination name, 8 bytes length*/
	char *destination;

	/** Message to send length*/
	uint32_t length;

	/** Message byte stream of lenght lenght*/
	unsigned char *message;
}packet_transport_t;

/** \struct channel 
* Struct to model and manage a file channel
* between client and server
*/
typedef struct channel_t{
	/** Channel source name e.g. server*/
	char *channel_source;

	/** Channel destination name e.g. client*/
	char *channel_destination;

	/** File to use to exchange messages,
	the channel between client and server */
	char *fileName;

	/** Channel file descriptor */
	int fd;

	/** Function to be called when a packet is received */
	void (*onPacketReceive)(struct channel_t *ch, packet_transport_t *p);

	/** If the listener is running it is set to 1, otherwise it is 0*/
	int isEnabled;

	/** Secondary thread for reading/writing */
	pthread_t thread;
}channel_t;
#endif

/**
 * Create a server/client channel using the fileName as communication channel
 *
 *	\param fileName: file name of the channel
 * 	\param channelFrom: name of the channel owner
 *	\param channelTo: name of the other peer
 * 	\return the created channel
 */
channel_t *create_channel(char *fileName, char *channelFrom, char *channelTo);

/**
 * Set the function to be called when a message is received
 *
 * \param ch: channel interested
 * \param onPacketReceive: pointer to the function to be called
 * \return: 1 if the function was set, 0 otherwise
 */
int set_on_receive(channel_t *ch, void (*onPacketReceive)(channel_t *ch, packet_transport_t *p));

/**
 * Send a message through the channel ch
 *
 * \param ch: channel to be used
 * \param p: pointer to packet to be sent
 * \return: 1 if the message was sent, 0 otherwise
 */
int send_packet(channel_t *ch, packet_transport_t *p);

/**
 * Start the channel. We open another thread for the reading
 * and the current thread for writing. From now on (if the operation
 * is successful) the client/server read continously from channel.
 * (to STOP use stop())
 *
 * \param ch: channel to start
 * \return: 1 if the thread was started, 0 otherwise
 */
int start_listener(channel_t *ch);

/**
 * Stop the caller and wait until stop() is called
 * \param ch: the channel to wait
 */
void wait_channel(channel_t *ch);

/**
 * Stop the reading/writing thread and the channel.
 * Note: the function doesn't free the channel.
 * \param ch: channel to stop
 */
void stop_channel(channel_t *ch);

/**
 * Create a packet starting from a byte stream 
 * source and destination
 *
 * \param source: packet source
 * \param destination: packet receiver
 * \param message: message stream to be encapsulate into packet
 * \param message_length: message lenght
 * \return a pointer to a built packet
 */
packet_transport_t *create_packet(char *source, char *destination, unsigned char *message, uint32_t message_length);

/**
 * Deallocate memory allocated by packet
 * \param p: pointer to packet to free
 */
void free_packet(packet_transport_t *p);
