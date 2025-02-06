
██████╗ ██████╗  ██████╗ ██████╗ ███████╗ ██████╗██╗ █████╗ ██████╗ 
██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝██╔════╝██║██╔══██╗╚════██╗
██████╔╝██████╔╝██║   ██║██████╔╝█████╗  ██║     ██║███████║ █████╔╝
██╔═══╝ ██╔══██╗██║   ██║██╔═══╝ ██╔══╝  ██║     ██║██╔══██║██╔═══╝ 
██║     ██║  ██║╚██████╔╝██║     ███████╗╚██████╗██║██║  ██║███████╗
╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚══════╝ ╚═════╝╚═╝╚═╝  ╚═╝╚══════╝
                                                                    
                    [ p r o p e c i a 2 . c ]

an update to the propecia.c   scans for one port any subnet from /16 to /30


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define DEFAULT_PORT 23

// Function to calculate the network and broadcast addresses
void calculate_range(const char *cidr, struct in_addr *start_ip, struct in_addr *end_ip) {
    char network[INET_ADDRSTRLEN];
    int prefix_length;
    unsigned int mask, ip;

    // Parse CIDR (e.g., "10.8.4.0/21")
    if (sscanf(cidr, "%15[^/]/%d", network, &prefix_length) != 2 || prefix_length < 16 || prefix_length > 31) {
        fprintf(stderr, "Invalid CIDR. Use format X.X.X.X/Y (16 <= Y <= 31).\n");
        exit(1);
    }

    // Convert network address to integer
    if (!inet_aton(network, start_ip)) {
        fprintf(stderr, "Invalid IP address in CIDR.\n");
        exit(1);
    }

    ip = ntohl(start_ip->s_addr);

    // Calculate subnet mask
    mask = (0xFFFFFFFF << (32 - prefix_length)) & 0xFFFFFFFF;

    // Calculate start and end IP addresses
    start_ip->s_addr = htonl(ip & mask);               // Network address
    end_ip->s_addr = htonl((ip & mask) | (~mask));     // Broadcast address
}

int main(int argc, char *argv[]) {
    int sockfd, result, counter = 0;
    char host[INET_ADDRSTRLEN];
    int port;
    struct sockaddr_in address;
    struct in_addr start_ip, end_ip, current_ip;

    if (argc < 2) {
        printf("Usage: %s [X.X.X.X/Y] <port>\n", argv[0]);
        exit(1);
    }

    // Parse port or use default
    if (argc >= 3) {
        port = atoi(argv[2]);
    } else {
        port = DEFAULT_PORT;
    }

    // Calculate the range of IP addresses
    calculate_range(argv[1], &start_ip, &end_ip);

    // Iterate over the range of IP addresses
    current_ip = start_ip;
    while (ntohl(current_ip.s_addr) <= ntohl(end_ip.s_addr)) {
        // Convert current IP to string
        inet_ntop(AF_INET, &current_ip, host, INET_ADDRSTRLEN);

        if ((fork()) == 0) {
            address.sin_family = AF_INET;
            address.sin_port = htons(port);
            address.sin_addr = current_ip;

            sockfd = socket(AF_INET, SOCK_STREAM, 0);
            if (sockfd < 0) {
                perror("Socket");
                exit(2);
            }

            alarm(3);
            result = connect(sockfd, (struct sockaddr *)&address, sizeof(address));

            if (result == 0) {
                printf("%s\n", host);
                close(sockfd);
                exit(0);
            }
            close(sockfd);
            exit(0);
        }

        // Move to the next IP address
        current_ip.s_addr = htonl(ntohl(current_ip.s_addr) + 1);
    }

    sleep(1);
    close(sockfd);
    exit(0);
}


