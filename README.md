# Progetto di Advanced Programming of Cryptographic methods
## ToDo list
+ SSL/TLS 
+ In particolare, lo schema di comunicazione client<->server
+ In particolare, l'handshaking
+ [hello client]
+ Tutta la comunicazione client<->server (senza socket)
+ Il mezzo di comunicazione da usare sarà un file condiviso
+ Ogni entità legge il file e lo ripulisce
+ Nella comunicazione ci sarà un token
+ 2 file: uno di comunicazione, l'altro con il token di chi deve parlare
+ La comunicazione prosegue finché non si genera un master secret (la chiave condivisa)
+ Per la generazione del master secret usare hash, md5, generatori random
+ Si possono usare librerie già fatte
+ Devono essere due programmi: Client e Server
+ Il protocollo è diviso in 4 fasi, arrivare fino alla 4ª fase
+ CI FERMIAMO AL SEGRETO COMUNE

## PARAMETRI DI VALUTAZIONE:
+ Funzionante
+ Porcherie di programmazione
+ La relazione che sarà una spiegazione di cosa abbiamo fatto
+ Come lo abbiamo pensato ed implementato

## Libro: William Stallings - Network Security Applications and Standards
