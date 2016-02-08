# Progetto di Advanced Programming of Cryptographic methods
##MVTLS TLS 1.2 handshake over file
The TLS handshake using as channel a file. 
The software require **OpenSSL**.

Compile with 

    make
and start running 

    cd bin/
    MVTLS server 
then 
    
    MVTLS client
The documentation is in the **doc** folder in HTML format. 
For more args you can type:

    MVTLS --help

You can also...
+ Clean the project with **make clean**
+ Build tests with **make tests**

For re-genearate documentation use Doxygen and graphviz with **/doc/Doxyfile**. 



