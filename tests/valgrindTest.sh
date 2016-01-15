#!/bin/sh

RED="\033[0;31m"
NC="\033[0m" # No Color
GREEN="\033[0;32m"

pause(){
	wait
	echo "Press [Enter] key to continue..."
	read key 
}
echo ""
echo $RED"**** THIS SCRIPT TEST THE ALLOCATION USING VALGRIND ****"
echo "**** MAKE SURE TO MAKE ALL TESTS BEFORE RUNNING THIS SCRIPT ****"
echo "**** MAKE SURE TO HAVE valgrind ( love it <3 ) INSTALLED ****"$NC
pause

echo ""
echo $GREEN"-----TESTING MAIN SSL SERVER/CLIENT-------"$NC
echo $RED"NOTE: this test use OpenSSL hence there is some suppressed "
echo "warning due to the OpenSSL implementation. DON'T WORRY ABOUT THAT"$NC
echo ""
pause
cd ../bin
valgrind --leak-check=full --show-leak-kinds=all --suppressions=../tests/valgrindSuppression.txt ./TLSServer &
valgrind --leak-check=full --show-leak-kinds=all --suppressions=../tests/valgrindSuppression.txt ./TLSClient
pause
exit

echo ""
echo $GREEN"-----TESTING CERTIFICATE SERIALIZE/DESERIALIZE-------"$NC
echo $RED"NOTE: this test use OpenSSL hence there is some suppressed "
echo "warning due to the OpenSSL implementation. DON'T WORRY ABOUT THAT"$NC
echo ""
pause
valgrind --leak-check=full --show-leak-kinds=all --suppressions=valgrindSuppression.txt ../bin/testCertificate
pause

echo ""
echo $GREEN"-----TESTING BASIC PROTOCOL-------"$NC
echo ""
pause
cd ../bin/testBasic/
valgrind --leak-check=full --show-leak-kinds=all ./serverBasic &
valgrind --leak-check=full --show-leak-kinds=all ./clientBasic
pause

echo ""
echo $GREEN"-----TESTING RECORD PROTOCOL-------"$NC
echo ""
pause
cd ../testRecord
valgrind --leak-check=full --show-leak-kinds=all ./serverRecord &
valgrind --leak-check=full --show-leak-kinds=all ./clientRecord

pause
echo ""
echo $GREEN"-----TESTING HANDSHAKE PROTOCOL-------"$NC
echo ""
pause

cd ../testHandshake
valgrind --leak-check=full --show-leak-kinds=all ./serverHandshake &
valgrind --leak-check=full --show-leak-kinds=all ./clientHandshake
wait
echo "Press [Enter] to end"
read key
