#include <iostream>
#include <string.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

// Automatic port number
#define PORT_NO 0
#define DEFAULT_PACKET_SIZE 64


/**
 * Given a hostname, this function would perform a DNS lookup and returns an IP address
 * in standard dot notation.
 * 
 */
char *dns_lookup(char *fst_arg, char *addr_host, struct sockaddr_in *addr_con) {

    std::cout << "Resolving DNS...\n" << std::endl;
    struct hostent *host;
    char *ip_addr = (char*)malloc(NI_MAXHOST * sizeof(char));

    if ((host = gethostbyname(addr_host)) == NULL) {
        printf("%s: %s: No address associated with hostname\n", fst_arg, addr_host);
        exit(EXIT_FAILURE);
    }

    strcpy(ip_addr, inet_ntoa(*(struct in_addr*)host->h_addr));

    (*addr_con).sin_family = host->h_addrtype;
    (*addr_con).sin_port = htons(PORT_NO);
    (*addr_con).sin_addr.s_addr = *(uint32_t*)host->h_addr;

    return ip_addr;
}

/**
 *  Given an ip address, this function resolves the reverse lookup of its hostname and returns
 *  the socket address to a corresponding host.
 * 
 */
char *rev_dns_lookup(char *ip_addr) {

    struct sockaddr_in rev_addr;
    socklen_t addr_len;
    char hbuf[NI_MAXHOST], *ret_hbuf;

    rev_addr.sin_family = AF_INET;
    rev_addr.sin_addr.s_addr = inet_addr(ip_addr);
    addr_len = sizeof(rev_addr);

    if (getnameinfo((struct sockaddr*) &rev_addr, addr_len, hbuf, sizeof(hbuf), NULL, 0, NI_NAMEREQD)) {
        printf("Could not resolve hostname.\n");
        return NULL;
    } else {
        printf("Hostname: %s\n", hbuf);
    }

    ret_hbuf = (char*)malloc((strlen(hbuf) + 1) * sizeof(char));
    strcpy(ret_hbuf, hbuf);
    return ret_hbuf;
}



int main(int argc, char *argv[]) {

    struct sockaddr_in addr_con;
    char *ip_addr, *rev_dns;
    int sock_fd;

    if (argc != 2) {
		printf("Usage: %s <hostname>\n", argv[0]);
		exit(1);
	}

    ip_addr = dns_lookup(argv[0], argv[1], &addr_con);
    if (ip_addr == NULL) {
        printf("\nDNS lookup failed! Could not resolve hostname!\n");
        return 0;
    }

    rev_dns = rev_dns_lookup(ip_addr);

    // sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    // if (sock_fd < 0) {
    //     printf("\nSocket file descriptor not received.\n");
    //     return 0;
    // } else {
    //     printf("\nSocket file descriptor %d received\n", sock_fd);
    //     return 0;
    // }

    std::cout << "PING " << argv[1] << " (" << ip_addr << ") 56(84) bytes of data." <<std::endl;
    return 0;
}