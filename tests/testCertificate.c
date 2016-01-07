#include <stdio.h>
#include <stdint.h>
#include "HandshakeMessages/Certificate.h"

int main(){
	certificate_message *cert_message = make_certificate_message("../certificates/serverRSA.pem");
	printf("Serialize\nCertificate name: %s\n",cert_message->X509_certificate->name);
	unsigned char *message = NULL;
	uint32_t message_len = 0;
	serialize_certificate_message(cert_message, &message, &message_len);
	certificate_message *deserialized = deserialize_certificate_message(message,message_len);
	printf("Deserialized\nCertificate name: %s\n",deserialized->X509_certificate->name);

    free(message);
	free_certificate_message(cert_message);
	free_certificate_message(deserialized);
	return 0;
}