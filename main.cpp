#include <stdio.h> 
#include <iostream>
#include <sys/types.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 
#include <netdb.h> 
#include <unistd.h> 
#include <string.h> 
#include <stdlib.h> 
#include <netinet/ip_icmp.h> 
#include <time.h> 
#include <fcntl.h> 
#include <signal.h> 
#include <time.h>

// Automatic port number
#define PORT_NO 0
#define RECV_TIMEOUT 1
#define DEFAULT_PKT_S 64
#define SLEEP_RATE 1000000

int ping_loop = 1;

struct ping_pkt { 
    struct icmphdr hdr; 
    char msg[DEFAULT_PKT_S - sizeof(struct icmphdr)]; 
};

// Calculating the Check Sum 
unsigned short checksum(void *b, int len) {    
    unsigned short *buf = b; 
    unsigned int sum=0; 
    unsigned short result; 
  
    for ( sum = 0; len > 1; len -= 2 ) 
        sum += *buf++; 
    if ( len == 1 ) 
        sum += *(unsigned char*)buf; 
    sum = (sum >> 16) + (sum & 0xFFFF); 
    sum += (sum >> 16); 
    result = ~sum; 
    return result; 
} 

void irq_handler(int val) {
    ping_loop = 0;
}

/**
 * Given a hostname, this function would perform a DNS lookup and returns an IP address
 * in standard dot notation.
 * 
 */
char *dns_lookup(char *fst_arg, char *addr_host, struct sockaddr_in *addr_con) {

    struct hostent *host;
    char *ip_addr = (char*)malloc(NI_MAXHOST * sizeof(char));

    if ((host = gethostbyname(addr_host)) == NULL) {
        printf("%s: %s: No address associated with hostname\n", fst_arg, addr_host);
        exit(EXIT_FAILURE);
    }

    strcpy(ip_addr, inet_ntoa(*(struct in_addr*)host->h_addr));

    addr_con->sin_family = host->h_addrtype;
    addr_con->sin_port = htons(PORT_NO);
    addr_con->sin_addr.s_addr = *(uint32_t*)host->h_addr;

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
    addr_len = sizeof(struct sockaddr_in);

    if (getnameinfo((struct sockaddr*) &rev_addr, addr_len, hbuf, sizeof(hbuf), NULL, 0, NI_NAMEREQD)) {
        printf("Could not resolve hostname.\n");
        return NULL;
    }

    ret_hbuf = (char*)malloc((strlen(hbuf) + 1) * sizeof(char));
    strcpy(ret_hbuf, hbuf);
    return ret_hbuf;
}



void send_ping(int sock_fd, struct sockaddr_in *ping_addr, char *ping_dns, char *ping_ip, char *rev_dns) {

    int ttl_val = 114, i, addr_len, flag = 1, msg_count = 0, msg_recv_count = 0;
    long double rtt_msec = 0, total_msec = 0;
    struct ping_pkt pckt;
    struct sockaddr_in r_addr;
    struct timespec time_start, time_end, ts_start, ts_end;
    struct timeval tv_out;

    tv_out.tv_sec = RECV_TIMEOUT;
    tv_out.tv_usec = 0;

    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    // Change the time to live to 64 hops
    if (setsockopt(sock_fd, SOL_IP, IP_TTL, &ttl_val, sizeof(ttl_val) != 0)) {
        printf("Setting socket options error\n");
        return;
    }

    // Setting of timeout for receiving.
    setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*) &tv_out, sizeof(tv_out));

    // Send ICMP pings in an infinite loop
    while (ping_loop) {

        //flag for if the packet was sent
        flag = 1;

        // Fill packet with null bytes
        bzero(&pckt, sizeof(pckt)); 
          
        pckt.hdr.type = ICMP_ECHO;
        pckt.hdr.code = 0;
        pckt.hdr.un.echo.id = getpid(); 
          
        for ( i = 0; i < sizeof(pckt.msg)-1; i++ ) 
            pckt.msg[i] = i+'0'; 
          
        pckt.msg[i] = 0; 
        pckt.hdr.un.echo.sequence = msg_count++; 
        pckt.hdr.checksum = checksum(&pckt, sizeof(pckt)); 
        // memset(&pckt, 'J', DEFAULT_PKT_S - sizeof(struct icmphdr));

        usleep(SLEEP_RATE);

        // Sending the packet
        clock_gettime(CLOCK_MONOTONIC, &time_start);

        if (sendto(sock_fd, &pckt, sizeof(pckt), 0, (struct sockaddr*) ping_addr, sizeof(*ping_addr)) <= 0) {
            printf("Packet failed to send\n");
            flag = 0;
        }

        // Receiving the packet
        addr_len = sizeof(r_addr);

        if (recvfrom(sock_fd, &pckt, sizeof(pckt), 0, (struct sockaddr*)&r_addr, (socklen_t*) &addr_len) <= 0 && msg_count > 1 ) { 
            printf("Packet reception failed\n");
        } else {
            clock_gettime(CLOCK_MONOTONIC, &time_end);
            double time_elapsed = ((double)(time_end.tv_nsec - time_start.tv_nsec)) / 1000000.0;
            rtt_msec = (time_end.tv_sec - time_start.tv_sec) * 1000.0 + time_elapsed;

            // If the packet was unable to be sent, do not receive
            if (flag) {

                // Literally no idea why the same implementation is giving an unexpected code of 128 instead of 0
                // if(!(pckt.hdr.type == 69 && pckt.hdr.code == 0)) {
                //     printf("Packet received with ICMP type %d and error code %d\n", pckt.hdr.type, pckt.hdr.code);
                // } else {
                    // 64 bytes from lhr48s11-in-f14.1e100.net (216.58.210.206): icmp_seq=2 ttl=114 time=11.5 ms
                    printf("%d bytes from %s (%s) : icmp_seq=%d ttl=%d time=%.1f ms\n", DEFAULT_PKT_S, ping_dns, ping_ip, msg_count, ttl_val, (double) rtt_msec);
                    msg_recv_count++;
                //}
            }
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &ts_end);

    double time_elapsed = ((double)(ts_end.tv_nsec -  ts_start.tv_nsec)) / 1000000.0;
    total_msec = (ts_end.tv_sec - ts_start.tv_sec) * 1000.0 + time_elapsed;

    printf("\n--- %s ping statistics ---\n", rev_dns);
    printf("%d packets transmitted, %d received, %d packet loss, time %dms\n", msg_count, msg_recv_count, (int) (((msg_count - msg_recv_count) / msg_count) * 100.0), (int) total_msec);
    printf("rtt min/avg/max/mdev = \n");
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

    sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); 
    if (sock_fd < 0) {
        perror("Socket error");
        exit(EXIT_FAILURE);
    } 

    std::cout << "PING " << argv[1] << " (" << ip_addr << ") 56(84) bytes of data." <<std::endl;

    signal(SIGINT, irq_handler);

    send_ping(sock_fd, &addr_con, rev_dns, ip_addr, argv[1]);
    return 0;
}
