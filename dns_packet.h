#ifndef __DNS_PACKET_H
#define __DNS_PACKET_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "net_hdr.h"
#include "raw_tcp.h"
#include "types.h"

#define DNS_PORT 53

typedef struct{
	u16 dns_id ;
	char name[50];
	int name_len;
	int flag;
	//struct dnsquery query;
}DNS_NEED;

int show_dns_requset(u8 *content,u16 content_length,DNS_NEED *);
int fake_dns_packet(DNS_NEED *dns,UDP_NEED *udp_need,IP_NEED *ip_need,struct ethhdr *ethdr,char *dev_name);



#endif
