#include <iostream>
#include <netdb.h>
#include <arpa/inet.h>

int main(int argc, char *argv[]) {

    if(argc != 2) {
		printf("Usage: %s <hostname>\n", argv[0]);
		exit(1);
	}

    hostent *host = gethostbyname(argv[1]);
    if (host == NULL) {
        printf("./output: %s: No address associated with hostname\n", argv[1]);
        exit(EXIT_FAILURE);
    }

    in_addr *addr = (in_addr*)host->h_addr;
    std::string ip_addr = inet_ntoa(*addr); 

    std::cout << "PING " << argv[1] << " " << ip_addr << " 56(84) bytes of data." <<std::endl;
    return 0;
}