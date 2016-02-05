/**
 *	SSL/TLS Project
 *	\file ServerClientTransportProtocol.c
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
 *	Both server and client cannot write if the file is not blank, they wait
 *
 *
 *	\date Created on 22/12/15.
 *	\copyright Copyright © 2015 Alessandro Melloni, Andrea Francesco Vinci. All rights reserved.
 */

#include "ServerClientTransportProtocol.h"


void free_packet(packet_transport_t *p);
long long get_file_size(int fd);
uint32_t read_all_file(int fd, unsigned char **p);
packet_transport_t *deserialize_packet(unsigned char *str, uint32_t fileLen);
void serialize_packet(packet_transport_t *p, unsigned char **str, uint32_t *strLen);

/**
 * Create a server/client channel using the fileName as communication channel
 *
 *	\param fileName: file name of the channel
 * 	\param channelFrom: name of the channel owner
 *	\param channelTo: name of the other peer
 * 	\return the created channel
 */
channel_t *create_channel(char *fileName, char *channelFrom, char *channelTo){
	channel_t *ch = malloc(sizeof(channel_t));
	ch->channel_source = channelFrom;
	ch->channel_destination = channelTo;
	ch->fileName = fileName;
	ch->onPacketReceive = NULL;
	ch->isEnabled = 0;
	ch->fd = open(fileName, O_RDWR | O_CREAT | O_TRUNC, 0666);

	return ch;
}

/**
 * Set the function to be called when a message is received
 *
 *	\param ch: channel interested
 * 	\param onPacketReceive: pointer to the function to call
 * 	\return: 1 if the function was set, 0 otherwise
 */
int set_on_receive(channel_t *ch, void (*onPacketReceive)(channel_t *ch, packet_transport_t *p)){
	if(ch->onPacketReceive == NULL){
		// Check if the packet is for the channel owner
		ch->onPacketReceive = onPacketReceive; 
		return 1;
	}

	return 0;
}

/**
 * Listener on the file. This function continuously read the entire file
 * until the message is for the channel owner. The cycle halt when the 
 * stop_channel function is called and start with start_listener.
 *
 *	\param data: a pointer to the channel.
 */
void reader(void *data){
	channel_t *ch;
	ch = (channel_t*)data;
	unsigned char *str = NULL;
	while (ch->isEnabled) {
		uint32_t fileLen = read_all_file(ch->fd, &str);
		if(fileLen>=16){
			// The file is not empty
			packet_transport_t *received = deserialize_packet(str, fileLen); 
			free(str);
			if(received != NULL && strcmp(received->destination, ch->channel_source) == 0){
				// Blank the file
				truncate(ch->fileName, 0);
				// Fire event
				ch->onPacketReceive(ch, received);
			}
			else
				free_packet(received);
		}
		else
			free(str);
		str = NULL;
		usleep(DELAY_TIME);
	}
}

/**
 * Start the channel. We open another thread for the reading
 * and the current thread for writing. From now on (if the operation
 * is succesfull) the client/server read continously from channel.
 * (to STOP use stop())
 *
 * \param ch: channel to start
 * \return: 1 if the thread was started, 0 otherwise
 */
int start_listener(channel_t *ch){
	if(ch->onPacketReceive==NULL)
		return 0;

	pthread_t thread;
	pthread_attr_t attr ;
	pthread_attr_init(&attr);

	ch->isEnabled = 1;
	int rc = pthread_create(&thread, &attr, (void *)&reader, (void *)ch);
	if (rc){
		printf("\nError: return code from pthread_create() is %d\n", rc);
		exit(-1);
	}
	ch->thread = thread;
	return 1;
}

/**
 * Stop the reading/writing thread and the channel.
 * Note: the function doesn't free the channel.
 * \param ch: channel to stop
 */
void stop_channel(channel_t *ch){
	ch->isEnabled = 0;
	close(ch->fd);
	pthread_exit(NULL);
}

/**
 * Stop the caller and wait until stop() is called
 * \param ch: the channel to wait
 */
void wait_channel(channel_t *ch){
	pthread_join(ch->thread, NULL);
}

/**
 * Create a packet starting from a byte stream 
 * source and destination
 *
 * \param source: packet source
 * \param destination: packet receiver
 * \param message: message stream to be encapsulated into packet
 * \param message_length: message lenght
 * \return a pointer to a built packet
 */
packet_transport_t *create_packet(char *source, char *destination, unsigned char *message, uint32_t message_length){
	packet_transport_t *result = malloc(sizeof(packet_transport_t));

	if(source != NULL){
		result->source = calloc(8,1);
		memcpy(result->source, source, 8);
	}
	else
		result->source = NULL;

	if(destination != NULL){
		result->destination = calloc(8,1);
		memcpy(result->destination, destination, 8);
	}
	else
		result->destination = NULL;
	if(message != NULL){
		result->message = malloc(sizeof(unsigned char)*message_length);
		memcpy(result->message, message, message_length);
	}
	else
		result->message = NULL;

	result->length = message_length;
	return result;
}

/**
 * Send a message through the channel ch
 *
 * \param ch: channel to be used
 * \param p: pointer to packet to be sent
 * \return: 1 if the message was sent, 0 otherwise
 */
int send_packet(channel_t *ch, packet_transport_t *p){

	if(ch == NULL){
		printf("Error: no channel is avaible (ch == NULL)");
		return -1;
	}
	if(ch->fd == -1)
		return 0;

	unsigned char *message = NULL;
	uint32_t strLen;

	if(p->source == NULL ){
		p->source = calloc(8,1);
		memcpy(p->source, ch->channel_source, strlen(ch->channel_source));
	}

	if(p->destination == NULL){
		p->destination = calloc(8,1);
		memcpy(p->destination, ch->channel_destination, strlen(ch->channel_destination));
	}

	serialize_packet(p, &message, &strLen);
	if(message == NULL){
		printf("\nError in send_packet\n");
		exit(-1);
	}

	// Waiting untill the file is blank
	while (get_file_size(ch->fd)!=0)
		usleep(100);
	// Now the file is empty
	unsigned long writeResult = write(ch->fd, message, strLen);
	free(message);
	if(writeResult)
		return 1;
	return 0;
}


/**
 * Deallocate memory allocated by packet
 * \param p: pointer to packet to free
 */
void free_packet(packet_transport_t *p){
	if(p == NULL)
		return;

	free(p->source);
	free(p->destination);
	free(p->message);
	free(p);
}

/********* Utilities function for file managing *********/

/**
 * Compute the byte size of a file
 * 
 *	\param fd: file descriptor
 *	\return the length of the file in byte
 */
long long get_file_size(int fd){
	struct stat *info;
	info = malloc(sizeof(struct stat));
	fstat(fd, info);
	long long res = info->st_size;
	free(info);

	return res;
}

/**
 * Read the entire file and store it in the provided pointer
 * 
 *	\param fd: file descriptor
 *	\param p: return pointer
 *	\return the file size
 */
uint32_t read_all_file(int fd, unsigned char **p){
	long long fileSize = get_file_size(fd);
	if(fileSize>UINT32_MAX){
		printf("\nThe message is too long\n");
		exit(-1);
	}
	unsigned char *temp = calloc(sizeof(unsigned char),fileSize);
	read(fd, temp, fileSize);
	*p = temp;

	return (uint32_t)fileSize;
}


/********* Serialization, deserialization *********/

/**
 * De-serialize message into a transport packet
 *
 *	\param str: string received
 *	\param fileLen: received string length
 *	\return the de-serialized message as transport struct
 */
packet_transport_t *deserialize_packet(unsigned char *str, uint32_t fileLen){

	char *from = calloc(8, 1);
	char *to = calloc(8, 1);
	uint32_t packLen = 0;
	unsigned char *message=NULL;

	memcpy(from, str, 8);
	memcpy(to, str+8, 8);
	memcpy(&packLen, str+16, 4);
	if(packLen>20){
		message = malloc(sizeof(unsigned char)*(fileLen-20));
		memcpy(message, str+20, fileLen-20);
	}

	if(packLen>fileLen){
		free(from);
		free(to);
		free(message);
		return NULL;
	}

	packet_transport_t *result = create_packet(from, to, message, packLen-20);

	// Clean up
	free(from);
	free(to);
	free(message);

	return result;
}

/**
 * Serialize the packet into a byte stream
 *
 *	\param p: packet to serialize
 *	\param str: pointer to a null string (used to return the stream)
 *	\param strLen: pointer to stream length (used to return the stream length)
 */
void serialize_packet(packet_transport_t *p, unsigned char **str, uint32_t *strLen){
	if(p->source == NULL || p->destination == NULL ){
		*str = NULL;
		*strLen = 0;
		return;
	}

	int len = p->length+4+8+8;
	unsigned char *buff = malloc(sizeof(unsigned char)*len);

	*str = buff;
	*strLen = len;
	if(buff!=NULL){
		memcpy(buff, p->source, 8);
		memcpy(buff+8, p->destination, 8);
		memcpy(buff+16, strLen, 4);
		if(p->length>0)
			memcpy(buff+20,p->message,p->length);
	}
	else{
		printf("\nMalloc fail in serialize_packet\n");
		exit(-1);
	}
}
