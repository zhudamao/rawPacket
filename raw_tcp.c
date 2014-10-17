#include "raw_tcp.h"

extern u8 dst_mac[6] ;

extern unsigned rev_addr;	
extern unsigned rev_mask;
extern char location[100];
unsigned short int checksum (unsigned short int *addr, int len)
{
  int nleft = len;
  int sum = 0;
  unsigned short int *w = addr;
  unsigned short int answer = 0;

  while (nleft > 1) {
    sum += *w++;
    nleft -= sizeof (unsigned short int);
  }

  if (nleft == 1) {
    *(unsigned char *) (&answer) = *(unsigned char *) w;
    sum += answer;
  }

  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  answer = ~sum;
  return (answer);
}


static short int tcp_check_sum(struct iphdr *ip,struct tcphdr *tcp,u8 * content ,int content_length){
	char buf[IP_MAXPACKET] = {0};
	struct pseudohdr psh = {};
	memset(&psh,0,sizeof(struct pseudohdr));

	psh.saddr = ip->saddr;
    	psh.daddr = ip->daddr;
    	psh.pad = 0;
    	psh.protocol = IPPROTO_TCP;
#ifndef HTTP_REDIRET
    	psh.len = htons(20);

	memcpy(buf,&psh,12);
	memcpy(buf + 12 ,tcp,20);

	return checksum((unsigned short int *)buf , 32);
#else
	psh.len = htons(20 + content_length);

	memcpy(buf,&psh,12);
	memcpy(buf + 12 ,tcp,20);
	memcpy(buf + 12 + 20 ,content, content_length);

	return checksum((unsigned short int *)buf , 32 + content_length);
#endif

}

static struct tcphdr *fake_tcp_packet(TCP_NEED *tcp_need,int num){
	struct tcphdr * tcp = NULL;

	if (!(tcp = malloc(sizeof(struct tcphdr)))){
		printf("bad mem alloc for tcp !%s %d\n",__FUNCTION__,__LINE__);
		return NULL;
	}
	memset(tcp,0,sizeof(struct tcphdr));
	
	tcp->source = htons(tcp_need ->des_port);
	tcp->dest = htons(tcp_need ->src_port); 
#ifndef HTTP_REDIRET
/*to do this for just send three packet seq and rst flag may different */
	switch(num){
		case 0:
			tcp->seq = htonl(tcp_need ->ack_seq + 1460*3);
			tcp->ack_seq = htonl(tcp_need->expect_seq );
			tcp->rst = 1;
			tcp->ack = 1;
			break;
		case 1:
			tcp->seq = htonl(tcp_need ->ack_seq);
			tcp->rst = 1;
			tcp->ack_seq = htonl(tcp_need->expect_seq );
			tcp->ack = 1;
			break;
		case 2:
			tcp->seq = htonl(tcp_need ->ack_seq + 1460);
			tcp->rst = 1;
			tcp->ack_seq = htonl(tcp_need->expect_seq );
			tcp->ack = 1;
			break;
		case 3:
			tcp->seq = htonl(tcp_need ->ack_seq);
			tcp->rst = 0;
			tcp->ack_seq = htonl(tcp_need->expect_seq );
			tcp->ack = 1;
			break;
		case 4:
			tcp->seq = htonl(tcp_need ->ack_seq);
			tcp->rst = 1;
			tcp->ack_seq = htonl(0);
			tcp->ack = 0;
			break;
		default:
			tcp->seq = htonl(tcp_need ->ack_seq);
			tcp->rst = 1;
			tcp->ack_seq = htonl(tcp_need->expect_seq );
			tcp->ack = 1;
			break;
	}
	
	tcp->res1 = 0;
	tcp->doff = 5;/*ÒÔ32bit ¼ÆËã 20*8 / 32*/
	tcp->fin = 0;
	tcp->syn =0;

	tcp->psh = 0;

	tcp->urg = 0;
	tcp->ece = 0;
	tcp->cwr = 0;
	tcp->window = htons(65535);
	tcp->urg_ptr = htons (0);
		
	if(num == 4){
		tcp ->window =  htons(0);
	}
#else
	tcp ->ack = 1;
	tcp ->ack_seq = htonl(tcp_need->expect_seq );
	tcp->seq = htonl(tcp_need ->ack_seq);
	tcp ->doff = 5;
	tcp->window = htons(65535);
	
#endif 
	return tcp;
}

struct iphdr *fake_ip_packet(IP_NEED *ip_need,u16 total_len,u8 proto){
	struct iphdr * ip = NULL;

	if (!(ip = malloc(sizeof(struct iphdr)))){
		printf("bad mem alloc for ip !%s %d\n",__FUNCTION__,__LINE__);
		return NULL;
	}
	memset(ip,0,sizeof(struct iphdr));
	
	ip->version = 4;
	ip->ihl = 5;
	ip->tos = 0;
	ip->tot_len = htons(total_len);
	ip->id = htons(0);
	ip->frag_off = htons(0);
	ip->ttl = 255;
	ip->protocol = proto;
	ip->check = 0;
	ip->saddr = htonl(ip_need ->det);
	ip->daddr = htonl(ip_need ->src);
	ip->check = 0;
	ip->check = checksum((unsigned short int * )ip, 20);
	
	return ip;
}

int fake_packet(TCP_NEED *tcp_need,IP_NEED *ip_need,struct ethhdr *ethdr,char *dev_name)
{
	int bytes = 0;
	struct sockaddr_ll device ={};
	int sd =0 ;

	struct tcphdr * tcp = NULL;
	struct iphdr *ip = NULL;
	u8 *frame = NULL;
	
/*only do once to less the code*/
	if (!(ip = fake_ip_packet(ip_need,40,IPPROTO_TCP))){
		printf("FAKE the ip packet error!%s %d\n",__FUNCTION__,__LINE__);
		goto error;
	}

	
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
	
	/*Ìî³ä
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

	int i = 0;
	for (; i < NUM_PCK ; i++){
		if (!(tcp = fake_tcp_packet(tcp_need,i))){
			printf("FAKE the tcp packet error!%s %d\n",__FUNCTION__,__LINE__);
			goto error;
		}
		tcp->check = tcp_check_sum(ip,tcp,NULL,0);
		memcpy(frame + 14 + 20 ,tcp,20);
		if ((bytes = sendto (sd, frame, 54, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
			perror ("sendto() failed");
			goto error;
		}
		else{
			free(tcp);
			tcp = NULL;
		}
	}
//	printf("bytes = %d\n",bytes);
		
		
	close(sd);
	if (tcp){
		free(tcp);
		tcp = NULL;
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
	if (tcp){
		free(tcp);
		tcp = NULL;
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

/*fake the http_redirect packet  */
int fake_http_redirect_packet(TCP_NEED *tcp_need,IP_NEED *ip_need,struct ethhdr *ethdr,char *dev_name)
{
	int bytes = 0;
	struct sockaddr_ll device ={};
	int sd =0 ;

	struct tcphdr * tcp = NULL;
	struct iphdr *ip = NULL;
	u8 http_content[1024] = {0};
	u8 *frame = NULL;
	int http_len = 0;
	
/*fake the http _content */	
	char date[32] = {0};
    	struct tm tm;
   	time_t tick = time(NULL);
   	gmtime_r(&tick, &tm);
    	strftime(date, 32, "%a, %d %b %Y %T GMT", &tm);

	http_len = snprintf((char *)http_content, 1024,
              "HTTP/1.1 302  Moved Temporarily\r\n"
              "Location: %s\r\n"
              "Content-Type: text/html\r\n"
              "Content-Length: 0\r\n"
              "Cache-Control: no-cache\r\n"
              "Connection: close\r\n"
              "Date: %s\r\n"
              "\r\n", location, date);

	if (http_len == 1024 && strcmp((char *)http_content + 1024 - 4, "\r\n\r\n")) {
		printf("FAKE the http packet error!%s  %d\n",__FILE__,__LINE__);
		return -1;
	}
	
/*only do once to less the code*/
	if (!(ip = fake_ip_packet(ip_need,40 + http_len,IPPROTO_TCP))){
		printf("FAKE the ip packet error!%s %d\n",__FUNCTION__,__LINE__);
		goto error;
	}
/*fake the tcp packet */
	if (!(tcp = fake_tcp_packet(tcp_need,0))){
		printf("FAKE the ip packet error!%s %d\n",__FUNCTION__,__LINE__);
		goto error;
	}

/* fake the frame */
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
	memcpy(frame + 14 + 20, tcp,20);
	memcpy(frame + 14 + 20 + 20, http_content,http_len);

	struct tcphdr *temp = (struct tcphdr *)(frame + 14 + 20 );
	temp ->check = tcp_check_sum(ip, tcp, http_content,http_len);
	
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

	if ((bytes = sendto (sd, frame, 54 + http_len , 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
			perror ("sendto() failed");
			goto error;
		}
//	printf("bytes = %d\n",bytes);
		
		
	close(sd);
	if (tcp){
		free(tcp);
		tcp = NULL;
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
	if (tcp){
		free(tcp);
		tcp = NULL;
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


