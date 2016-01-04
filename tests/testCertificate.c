#include <stdio.h>
#include <stdint.h>
#include <HandshakeMessages/Certificate.h>

int main(){
	char cert_names[] = "../certificates/server.pem";
	char **cert_list= malloc(1*sizeof(char *));
	cert_list[0] = cert_names;
	certificate_message *cert_message = make_certificate_message(cert_list, 1);
	printf("Serialize\nCertificate name: %s\n",cert_message->certificate_list->X509_certificate->name);
	unsigned char *message = NULL;
	uint32_t message_len = 0;
	serialize_certificate_message(cert_message, &message, &message_len);
	certificate_message *deserialized = deserialize_certificate_message(message,message_len);
	printf("Deserialized\nCertificate name: %s\n",deserialized->certificate_list->X509_certificate->name);
	free(message);
	free(cert_list);
	free_certificate_message(cert_message);
	free_certificate_message(deserialized);
	return 0;
}