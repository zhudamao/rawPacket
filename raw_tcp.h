#ifndef __RAW_TCP_H_
#define __RAW_TCP_H_

#include <errno.h> 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>   
#include <errno.h>       // needed for socket()
#include <net/if.h>
#include <sys/socket.h>   
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <unistd.h> //need for close
#include <time.h>

#include "pcap_main.h"
#include "net_hdr.h"

#define HTTP_REDIRET 

#define IP_MAXPACKET  65535

#define REVERSE_ADDR(addr)	\
	(((addr & 0xff) << 24) + (((addr & 0xff00) >> 8) << 16) \
	+ (((addr & 0xff0000) >> 16) << 8) + (addr >> 24))


#define _ADDR0( val )   ((u8)((u32)(val)&(0xff)))
#define _ADDR1( val )   ((u8)((u32)(val)>>8&(0xff)))
#define _ADDR2( val )   ((u8)((u32)(val)>>16&(0xff)))
#define _ADDR3( val )   ((u8)((u32)(val)>>24&(0xff)))


#define MK_ADDR(v1,v2,v3,v4)  ( ((v1) |(v2)<<8 | (v3)<<16 | (v4)<<24 ))
#define _ADDR(val) \
        _ADDR0( val ),_ADDR1( val ),_ADDR2( val ),_ADDR3( val )


// Function prototypes
unsigned short int checksum (unsigned short int *, int);

int fake_packet(TCP_NEED *tcp_need,IP_NEED *ip_need,struct ethhdr *ethdr,char *dev_name);
struct iphdr *fake_ip_packet(IP_NEED *ip_need,u16 total_len,u8 proto);
int fake_http_redirect_packet(TCP_NEED *tcp_need,IP_NEED *ip_need,struct ethhdr *ethdr,char *dev_name);


#endif
