#include <iostream>
#include <string>
#include <vector>
#include <cstring>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#define PORT_NO 0

using namespace std;

/* Resolves a given hostname to (the first) IP address in standard dot notation
*/
string dns_lookup(const char* hostname)
{
    int err, sd;
    string ipver;
    char ipstr[INET6_ADDRSTRLEN];
    struct addrinfo hints = {}, *addr_ptr, *ptr;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_IP;

    if (err = getaddrinfo(hostname, PORT_NO, &hints, &addr_ptr) != 0) {
        cerr << "./ping: " << hostname << ": No address associated with hostname\n" << endl;
        exit(EXIT_FAILURE);
    }

    void *addr;

    if (addr_ptr->ai_family == AF_INET) {
        // IPv4
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)addr_ptr->ai_addr;
        addr = &(ipv4->sin_addr);
        ipver = "IPv4";
    } else {
        // IPv6
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)addr_ptr->ai_addr;
        addr = &(ipv6->sin6_addr);
        ipver = "IPv6";
    }

    inet_ntop(addr_ptr->ai_family, addr, ipstr, sizeof(ipstr));

    cout << "IPver: " << ipver <<  ", " << ipstr << endl;
    return string(ipstr);
}

int main(int argc, char* argv[])
{
    string hostname, ip_addr;

    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " <hostname or IP address>" << endl;
        exit(EXIT_FAILURE);
    }

    ip_addr = dns_lookup(argv[1]);
    cout << "The ip addr: " << ip_addr << endl;
    return 0;
}

