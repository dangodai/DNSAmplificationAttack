#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>


//Use netinet IP and UDP headers
typedef struct iphdr ip_header;
typedef struct udphdr udp_header;

// Pseudoheader struct
typedef struct
{
    u_int32_t saddr;
    u_int32_t daddr;
    u_int8_t filler;
    u_int8_t protocol;
    u_int16_t len;
}pseudo_header;

// DNS header struct
typedef struct
{
	unsigned short id;
	unsigned short flags;
	unsigned short qcount;
	unsigned short ans;
	unsigned short auth;
	unsigned short add;
}dns_header;

// Question types
typedef struct
{
	unsigned short qtype;
	unsigned short qclass;
}query;
