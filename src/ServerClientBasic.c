//
//  SSL/TLS Project
//  ServerClientFileSocket.c
//
//  Created on 22/12/15.
//  Copyright © 2015 Mello, Darka. All rights reserved.
//

#include "ServerClientBasic.h"


void free_packet(packet_basic *p);
long get_file_size(FILE *f);
uint32_t read_all_file(FILE *f, unsigned char **p);
packet_basic *deserialize_packet(unsigned char *str, uint32_t fileLen);
void serialize_packet(packet_basic *p, unsigned char **str, uint32_t *strLen);


channel *create_channel(char *fileName, char *channelFrom, char *channelTo, mode channelMode){
    channel *ch = malloc(sizeof(channel));
    ch->mod = channelMode;
    ch->channel_source = channelFrom;
    ch->channel_destination = channelTo;
    if(channelMode == SERVER)
        ch->file = fopen(fileName, "w+");
    else
    	ch->file = fopen(fileName, "a+");
    ch->fileName = fileName;
    ch->onPacketReceive = NULL;
    ch->isEnabled = 0;
    return ch;
}

int set_on_receive(channel *ch, void (*onPacketReceive)(channel *ch, packet_basic *p)){
    if(ch->onPacketReceive == NULL){
        //check if the packet is for the channel owner
        ch->onPacketReceive = onPacketReceive; //channel and struct channel_t are the same TODO: cast
        return 1;
    }
    return 0;
}

int send_packet(channel *ch, packet_basic *p){
	if(ch == NULL)
		printf("Error ch is null");
    if(ch->file==NULL)
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
		printf("\nerror in send packet\n");
		exit(-1);
	}

    //printf("Packet to send:\n%.*s\n",strLen,message);
    //TODO : do better
    //waiting untill the file is blank
    while (get_file_size(ch->file)!=0)
        usleep(100);
	//at this point the file is empty
    fclose(ch->file);
	ch->file = fopen(ch->fileName, "w+");
    unsigned long writeResult = fwrite(message, 1, strLen, ch->file);
    fflush(ch->file); //for update
    free(message);
    if(writeResult)
        return 1;
    return 0;
}

void reader(void *data){
    channel *ch;
    ch = (channel*)data;
    unsigned char *str = NULL;
    while (ch->isEnabled) {
        ch->file = fopen(ch->fileName, "r");
        uint32_t fileLen = read_all_file(ch->file, &str);
        if(fileLen>=16){
            //the file is not empty
            packet_basic *received = deserialize_packet(str, fileLen); 
			free(str);
            if(received!=NULL && strcmp(received->destination, ch->channel_source)==0){
                //blank the file
                fclose(ch->file);
                ch->file = fopen(ch->fileName, "w+");
				//fire event
				ch->onPacketReceive(ch,received);
            }else
                free_packet(received);
        }else
			free(str);
        str = NULL;
        fclose(ch->file);
        usleep(DELAY_TIME);
    }
}

int start_listener(channel *ch){
    if(ch->onPacketReceive==NULL)
        return 0;
    
    pthread_t thread;
    pthread_attr_t attr ;
    pthread_attr_init(&attr);
    //pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    ch->isEnabled = 1;
    int rc = pthread_create(&thread, &attr, (void *)&reader, (void *)ch);
    if (rc){
        printf("ERROR; return code from pthread_create() is %d\n", rc);
        exit(-1);
    }
    ch->thread = thread;
    return 1;
}

void stop_channel(channel *ch){
    ch->isEnabled = 0;
    fclose(ch->file);
    pthread_exit(NULL);
}

void wait_channel(channel *ch){
    pthread_join(ch->thread, NULL);
}

packet_basic *create_packet(char *from, char *to, unsigned char *message, uint32_t messageLen){
    packet_basic *result = malloc(sizeof(packet_basic));    
    
	if(from!=NULL){
        result->source = calloc(8,1);
        memcpy(result->source, from, 8);
    }else result->source = NULL;
	
    if(to!=NULL){
        result->destination = calloc(8,1);
        memcpy(result->destination, to, 8);
    }else result->destination = NULL;
    if(message!=NULL){
        result->message = malloc(messageLen);
        memcpy(result->message, message, messageLen);
    }else result->message = NULL;
    
    result->messageLen = messageLen;
    return result;
}

void free_packet(packet_basic *p){
    if(p==NULL)
        return;

	free(p->source);
	free(p->destination);
	free(p->message);
    free(p);
}

/********* Utility function for file managing *********/

/*
 * Compute the byte size of a file
 * f : file indentificator
 * return : the lenght of the file in byte
 */
long get_file_size(FILE *f){
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f,0,SEEK_SET);
    return fsize;
}

/*
 * Reading the entire file
 * f : file identificator
 * p : return pointer
 * return : the file size
 */
uint32_t read_all_file(FILE *f, unsigned char **p){
    long fileSize = get_file_size(f);
    if(fileSize>UINT32_MAX)
    {
        printf("\nThe message is too long, something went wrong\n");
        exit(-1);
    }
    unsigned char *temp=malloc(fileSize*sizeof(unsigned char));
    fread(temp,fileSize,1,f);
    //printf("\n%.*s\n",fileSize,temp);
    *p=temp;
    return (uint32_t)fileSize;
}


/********* Serialization deserialization *********/

/*
 * Parse the message into packet
 * str : string received
 * fileLen : received string length
 */
packet_basic *deserialize_packet(unsigned char *str, uint32_t fileLen){
    
    char *from = calloc(8, 1);
    char *to = calloc(8, 1);
    uint32_t packLen = 0;
    unsigned char *message=NULL;
    
    memcpy(from, str, 8);
    memcpy(to, str+8, 8);
    memcpy(&packLen, str+16, 4);
    if(packLen>20){
        message = malloc(fileLen-20);
        memcpy(message, str+20, fileLen-20);
    }
    
    if(packLen!=fileLen){//the packet is malformed
        free(from);
        free(to);
		free(message);
        return NULL;
    }
    
    packet_basic *result = create_packet(from, to, message, packLen-20);
    free(from);
    free(to);
	free(message);
    return result;
}

/*
 * Serialize the packet into a byte stream
 * p : pacjet to serialize
 * str : pointer to a null string (used for return the stream)
 * strlen : pointer to stream length (used for return the stream length)
 */
void serialize_packet(packet_basic *p, unsigned char **str, uint32_t *strLen){
    if(p->source == NULL || p->destination == NULL )//|| p->message == NULL)
    {
        *str = NULL;
        *strLen = 0;
        return;
    }
    *strLen = p->messageLen+4+8+8;
    *str = malloc(*strLen);

    if(*str!=NULL){
        memcpy(*str, p->source, 8);
        memcpy(*str+8, p->destination, 8);
        memcpy(*str+16, strLen, 4);
        if(p->messageLen>0)
            memcpy(*str+20,p->message,p->messageLen);
    }else
    {
        printf("\nMalloc fail in serialize_packet\n");
        exit(-1);
    }
}





