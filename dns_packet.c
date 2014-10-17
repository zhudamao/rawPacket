#include <arpa/inet.h>
 
#include "dns_packet.h"

extern u8 dst_mac[6] ;

extern unsigned rev_addr;	
extern unsigned rev_mask;

static u16  udp_check_sum(struct iphdr *ip,struct udphdr *udp,u8 *content,int content_len){
	char buf[IP_MAXPACKET] = {0};
	struct pseudohdr psh = {};
	memset(&psh,0,sizeof(struct pseudohdr));

	psh.saddr = ip->saddr;
    	psh.daddr = ip->daddr;
    	psh.pad = 0;
    	psh.protocol = IPPROTO_UDP;
    	psh.len = htons(8+content_len);/**payload 's length **/

	memcpy(buf,&psh,12);
	memcpy(buf + 12 ,udp,20);
	memcpy(buf+ 12 + 8,content,content_len);

	return checksum((unsigned short int *)buf , 12+8+content_len);
}



int show_dns_requset(u8 *content,u16 content_length,DNS_NEED *p_dns){
	struct dnshdr *dns_hdr = (struct dnshdr *)content;
	
	if (content_length < 12){
		printf("the packet may not usuall dns request packet!%s %d\n",__FUNCTION__,__LINE__);
		return -1;
	}

#if defined RST_DEBUG
	printf("the id is %d ===\n",ntohs(dns_hdr->id));
	printf("the flags is %d\n",ntohs(dns_hdr->flags));
	printf("the qdcount is %d\n",ntohs(dns_hdr->qdcount));
	printf("the  ancount is %d\n",ntohs(dns_hdr->ancount));

	printf("the nscount is %d\n",ntohs(dns_hdr->nscount));
	printf("the is arcont is %d \n",ntohs(dns_hdr ->arcount));

	/*usual only request a address*/
	int len = (content + content_length - 4) - (content + 12) > 49 ? 
	49:(content + content_length - 4) - (content + 12);
	
	memcpy(name,content + 12,len);
	printf("the name is %s the len is %d \n",name,len);
	
	struct dnsquery *ds_qery = (struct dnsquery *)(content + content_length -4);
	printf("the qtype = %d \n",ntohs(ds_qery ->qtype));
	printf("the qclass = %d \n",ntohs(ds_qery ->qclass));
#endif 

	p_dns ->dns_id = ntohs(dns_hdr->id);
	int len = content + content_length- (content + 12);
	if(len  > 49) {
		printf("the dns request packet too larger!%s %d\n",__FUNCTION__,__LINE__);
		return -1;
	}
	
#ifdef RST_DEBUG	
	printf("the name is %s \n",content + 12);
	printf("the len = %d \n",len);
#endif

	memcpy(p_dns->name,content + 12 ,len);
	p_dns ->name_len = len;
	p_dns ->flag = ntohs(dns_hdr->flags) >> 16;/*2013-5-15 11:08:33 fix the bug  0  request ; 1 answer */
	
#if 0	
	struct dnsquery *ds_qery = (struct dnsquery *)(content + content_length -4);
	p_dns ->query.qclass = ntohs(ds_qery ->qclass);
	p_dns ->query.qtype = ntohs(ds_qery ->qtype);
#endif

#ifdef RST_DEBUG
	printf("p_dns ->flag = %d  p_dns= %s len = %d \n",p_dns ->flag,p_dns->name, p_dns ->name_len);
#endif

	return 0;
}

static struct udphdr *fake_udp_packet(UDP_NEED *udp_need){
	struct udphdr * udp = NULL;

	if (!(udp = malloc (sizeof (struct udphdr)))){
		printf("malloc for udp error!%s %d\n",__FUNCTION__,__LINE__);
		return NULL;
	}

	udp->dest = htons(udp_need ->src_port); 
	udp->source = htons(udp_need ->des_port);

	return udp;
}


static struct dnshdr *fake_dns_content(DNS_NEED *dns,int *dns_len){
	struct dnshdr* p_dns = NULL;

	if (!(p_dns = (struct dnshdr *)malloc (sizeof (u8)*100))){
		printf("malloc for dnshdr error!%s %d\n",__FUNCTION__,__LINE__);
		return NULL;
	}
	memset(p_dns,0,100);
	
	p_dns->id = htons(dns ->dns_id);
	p_dns->flags = htons(0x8180);
	p_dns ->qdcount = htons(1);
	p_dns ->ancount = htons(1);
	p_dns ->arcount = htons(0);
	p_dns ->nscount = htons(0);

	memcpy((u8 *)p_dns + 12,dns->name,dns->name_len);
	struct dnsrr *dns_rr = (struct dnsrr *)((u8*)p_dns + 12 + dns->name_len);
	dns_rr->name = htons(0xc00c);
	dns_rr ->type = htons(TYPE_A);
	dns_rr->class = htons(CLASS_IN);
	dns_rr ->ttl = htonl(65535);
	dns_rr ->rdlength = htons(4);
	dns_rr ->rdata[0] = 61;
	dns_rr ->rdata[1] = 135;
	dns_rr ->rdata[2] = 169;
	dns_rr ->rdata[3] = 105;
	
	*dns_len = 12 + dns->name_len + sizeof(struct dnsrr);
	return p_dns;
}

int fake_dns_packet(DNS_NEED *dns,UDP_NEED *udp_need,IP_NEED *ip_need,struct ethhdr *ethdr,char *dev_name){
	int bytes = 0;
	struct sockaddr_ll device ={};
	int sd =0 ;

	struct udphdr * udp = NULL;
	struct iphdr *ip = NULL;
	struct dnshdr *p_dns = NULL;
	u8 *frame = NULL;
	
	int dns_len = 0;
	if (!(p_dns = fake_dns_content(dns,&dns_len))){
		printf("FAKE the dns packet error!%s %d\n",__FUNCTION__,__LINE__);
		goto error;
	}

	if (!(udp = fake_udp_packet(udp_need))){
		printf("FAKE the udp packet error!%s %d\n",__FUNCTION__,__LINE__);
		goto error;
	}


	/*only do once */
	if (!(ip = fake_ip_packet(ip_need,dns_len + 20 + 8,IPPROTO_UDP))){
		printf("FAKE the ip packet error!%s %d\n",__FUNCTION__,__LINE__);
		goto error;
	}
	
	/* fix the data before fake the dns packet*/
	
	udp ->check = htons(0) ;
	udp ->len = htons(dns_len + 8) ;
	udp ->check = udp_check_sum( ip, udp, (u8 *)p_dns, dns_len);
	
#if RST_DEBUG
	printf("totlen = %d ",dns_len + 28);
	printf("udp_len = %d ",dns_len +8);
	printf("dns_len is %d ",dns_len);
	printf("the check sum is %x ",ip->check);
#endif

#if 1
	frame = (u8 *)malloc(IP_MAXPACKET *sizeof(u8));
	if (!frame){
		printf("FAKE the frame error!%s %d\n",__FUNCTION__,__LINE__);
		goto error;
	}
	memset(frame,0,IP_MAXPACKET *sizeof(u8));

	memcpy (frame, ethdr ->h_source, 6);
	memcpy (frame+6,ethdr ->h_dest,6);
	frame[12] = ETH_P_IP / 256;
	frame[13] = ETH_P_IP % 256;
	memcpy(frame + 14,ip,20);
	memcpy(frame + 14 + 20,udp,8);
	memcpy(frame + 14 + 20 + 8,p_dns,dns_len);
	/*Моід
	memcpy(frame + 14 + 20 + 20,"00000",6);*/
	
	/********* Fill out sockaddr_ll.****************/
	if ((device.sll_ifindex = if_nametoindex (dev_name)) == 0) {
		perror ("if_nametoindex() failed to obtain interface index ");
		goto error;
	}
	
	device.sll_family = AF_PACKET;
	memcpy (device.sll_addr, ethdr ->h_dest, ETH_ALEN);/*src mac address*/
	device.sll_halen = htons (ETH_ALEN);

	if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {/*ETH_P_ALL Promiscuous mode*/
		perror ("socket() failed to get socket descriptor for using ioctl() ");
		return -1;
	}

	if ((bytes = sendto (sd, frame, 14 +20 +8+dns_len, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
		perror ("sendto() failed");
		goto error;
	}
//	printf("bytes = %d\n",bytes);
#endif		
		
	close(sd);
	if (p_dns){
		free(p_dns);
		p_dns = NULL;
		}
	if (udp){
		free(udp);
		udp = NULL;
		}
	if (ip){
		free(ip);
		ip = NULL;
		}
	if(frame){
		free(frame);
		frame = NULL;
		}
	
	return 0;
error:
	close(sd);
	if (p_dns){
		free(p_dns);
		p_dns = NULL;
		}
	if (udp){
		free(udp);
		udp = NULL;
		}
	if (ip){
		free(ip);
		ip = NULL;
		}
	if(frame){
		free(frame);
		frame = NULL;
		}
 	return -1;
}


