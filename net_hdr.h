#ifndef  __NET_HEADER_H__
#define  __NET_HEADER_H__

#include <net/ethernet.h>

#include "types.h"

/*-------------------------------------------------------------------------*/

#define ETH_ALEN    6        /* Octets in one ethernet addr     */
#define ETH_HLEN    14        /* Total octets in header.     */
#define ETH_ZLEN    60        /* Min. octets in frame sans FCS */
#define ETH_DATA_LEN    1500        /* Max. octets in payload     */
#define ETH_FRAME_LEN    1514        /* Max. octets in frame sans FCS */
#define ETH_FCS_LEN    4        /* Octets in the FCS */

/*
 *    These are the defined Ethernet Protocol ID's.
 */
#define ETH_P_LOOP   0x0060        /* Ethernet Loopback packet    */
#define ETH_P_PUP    0x0200        /* Xerox PUP packet        */
#define ETH_P_PUPAT  0x0201        /* Xerox PUP Addr Trans packet    */
#define ETH_P_IP     0x0800        /* Internet Protocol packet    */
#define ETH_P_X25    0x0805        /* CCITT X.25            */
#define ETH_P_ARP    0x0806        /* Address Resolution packet    */
#define ETH_P_BPQ    0x08FF        /* G8BPQ AX.25 Ethernet Packet    [ NOT AN OFFICIALLY REGISTERED ID ] */
#define ETH_P_IEEEPUP    0x0a00        /* Xerox IEEE802.3 PUP packet */
#define ETH_P_IEEEPUPAT  0x0a01        /* Xerox IEEE802.3 PUP Addr Trans packet */
#define ETH_P_DEC       0x6000          /* DEC Assigned proto           */
#define ETH_P_DNA_DL    0x6001          /* DEC DNA Dump/Load            */
#define ETH_P_DNA_RC    0x6002          /* DEC DNA Remote Console       */
#define ETH_P_DNA_RT    0x6003          /* DEC DNA Routing              */
#define ETH_P_LAT       0x6004          /* DEC LAT                      */
#define ETH_P_DIAG      0x6005          /* DEC Diagnostics              */
#define ETH_P_CUST      0x6006          /* DEC Customer use             */
#define ETH_P_SCA       0x6007          /* DEC Systems Comms Arch       */
#define ETH_P_TEB       0x6558        /* Trans Ether Bridging        */
#define ETH_P_RARP      0x8035        /* Reverse Addr Res packet    */
#define ETH_P_ATALK     0x809B        /* Appletalk DDP        */
#define ETH_P_AARP      0x80F3        /* Appletalk AARP        */
#define ETH_P_8021Q     0x8100          /* 802.1Q VLAN Extended Header  */
#define ETH_P_IPX     0x8137        /* IPX over DIX            */
#define ETH_P_IPV6    0x86DD        /* IPv6 over bluebook        */
#define ETH_P_PAUSE   0x8808        /* IEEE Pause frames. See 802.3 31B */
#define ETH_P_SLOW    0x8809        /* Slow Protocol. See 802.3ad 43B */
#define ETH_P_WCCP    0x883E        /* Web-cache coordination protocol
                     * defined in draft-wilson-wrec-wccp-v2-00.txt */
#define ETH_P_PPP_DISC   0x8863        /* PPPoE discovery messages     */
#define ETH_P_PPP_SES    0x8864        /* PPPoE session messages    */
#define ETH_P_MPLS_UC    0x8847        /* MPLS Unicast traffic        */
#define ETH_P_MPLS_MC    0x8848        /* MPLS Multicast traffic    */
#define ETH_P_ATMMPOA    0x884c        /* MultiProtocol Over ATM    */
#define ETH_P_ATMFATE    0x8884        /* Frame-based ATM Transport
                     * over Ethernet
                     */
#define ETH_P_PAE    0x888E        /* Port Access Entity (IEEE 802.1X) */
#define ETH_P_AOE    0x88A2        /* ATA over Ethernet        */
#define ETH_P_TIPC   0x88CA        /* TIPC             */
#define ETH_P_1588   0x88F7        /* IEEE 1588 Timesync */
#define ETH_P_FCOE   0x8906        /* Fibre Channel over Ethernet  */
#define ETH_P_FIP    0x8914        /* FCoE Initialization Protocol */
#define ETH_P_EDSA   0xDADA        /* Ethertype DSA [ NOT AN OFFICIALLY REGISTERED ID ] */

/*
 *    Non DIX types. Won't clash for 1500 types.
 */

#define ETH_P_802_3  0x0001        /* Dummy type for 802.3 frames  */
#define ETH_P_AX25   0x0002        /* Dummy protocol id for AX.25  */
#define ETH_P_ALL    0x0003        /* Every packet (be careful!!!) */
#define ETH_P_802_2  0x0004        /* 802.2 frames         */
#define ETH_P_SNAP    0x0005        /* Internal only        */
#define ETH_P_DDCMP     0x0006          /* DEC DDCMP: Internal only     */
#define ETH_P_WAN_PPP   0x0007          /* Dummy type for WAN PPP frames*/
#define ETH_P_PPP_MP    0x0008          /* Dummy type for PPP MP frames */
#define ETH_P_LOCALTALK 0x0009        /* Localtalk pseudo type     */
#define ETH_P_CAN    0x000C        /* Controller Area Network      */
#define ETH_P_PPPTALK    0x0010        /* Dummy type for Atalk over PPP*/
#define ETH_P_TR_802_2    0x0011        /* 802.2 frames         */
#define ETH_P_MOBITEX    0x0015        /* Mobitex (kaz@cafe.net)    */
#define ETH_P_CONTROL    0x0016        /* Card specific control frames */
#define ETH_P_IRDA    0x0017        /* Linux-IrDA            */
#define ETH_P_ECONET    0x0018        /* Acorn Econet            */
#define ETH_P_HDLC    0x0019        /* HDLC frames            */
#define ETH_P_ARCNET    0x001A        /* 1A for ArcNet :-)            */
#define ETH_P_DSA    0x001B        /* Distributed Switch Arch.    */
#define ETH_P_TRAILER    0x001C        /* Trailer switch tagging    */
#define ETH_P_PHONET    0x00F5        /* Nokia Phonet frames          */
#define ETH_P_IEEE802154 0x00F6        /* IEEE802.15.4 frame        */


#if 0
/*
 *    This is an Ethernet frame header.
 */

struct ethhdr {
    unsigned char    h_dest[ETH_ALEN];    /* destination eth addr    */
    unsigned char    h_source[ETH_ALEN];    /* source ether addr    */
    __be16        h_proto;        /* packet type ID field    */
} __attribute__((packed));
#endif


/*-------------------------------------------------------------------*/
#define VLAN_HLEN    4        

/*
 *    struct vlan_hdr - vlan header
 *    @h_vlan_TCI: priority and VLAN ID
 *    @h_vlan_encapsulated_proto: packet type ID or len
 */
struct vlan_hdr {
    __be16    h_vlan_TCI;
    __be16    h_vlan_encapsulated_proto;
};

/*------------------------------------------------------------------*/


#define MPLS_HLEN       4  /*mpls header length*/
#define MAX_MPLS_LABELS 16 /* This is the max label stack depth */
#define MPLS_STACK_BOTTOM htonl(0x00000100)

/* ------------------------------------------------------------------ */
#if 0
enum {
  IPPROTO_IP = 0,        /* Dummy protocol for TCP        */
  IPPROTO_ICMP = 1,        /* Internet Control Message Protocol    */
  IPPROTO_IGMP = 2,        /* Internet Group Management Protocol    */
  IPPROTO_IPIP = 4,        /* IPIP tunnels (older KA9Q tunnels use 94) */
  IPPROTO_TCP = 6,        /* Transmission Control Protocol    */
  IPPROTO_EGP = 8,        /* Exterior Gateway Protocol        */
  IPPROTO_PUP = 12,        /* PUP protocol                */
  IPPROTO_UDP = 17,        /* User Datagram Protocol        */
  IPPROTO_IDP = 22,        /* XNS IDP protocol            */
  IPPROTO_DCCP = 33,        /* Datagram Congestion Control Protocol */
  IPPROTO_RSVP = 46,        /* RSVP protocol            */
  IPPROTO_GRE = 47,         /* Cisco GRE tunnels (rfc 1701,1702)    */

  IPPROTO_IPV6     = 41,        /* IPv6-in-IPv4 tunnelling        */

  IPPROTO_ESP = 50,            /* Encapsulation Security Payload protocol */
  IPPROTO_AH = 51,             /* Authentication Header protocol       */
  IPPROTO_BEETPH = 94,           /* IP option pseudo header for BEET */
  IPPROTO_PIM    = 103,        /* Protocol Independent Multicast    */

  IPPROTO_COMP   = 108,                /* Compression Header protocol */
  IPPROTO_SCTP   = 132,        /* Stream Control Transport Protocol    */
  IPPROTO_UDPLITE = 136,    /* UDP-Lite (RFC 3828)            */

  IPPROTO_RAW     = 255,        /* Raw IP packets            */
  IPPROTO_MAX
};
#endif

/*------------------------------------------------------------------*/

#define __LITTLE_ENDIAN_BITFIELD

struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8    ihl:4,
        version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
    __u8    version:4,
          ihl:4;
#else
#error  "Adjust your byteorder defines"
#endif
    __u8    tos;
    __be16    tot_len;
    __be16    id;
    __be16    frag_off;
    __u8    ttl;
    __u8    protocol;
    __sum16    check;
    __be32    saddr;
    __be32    daddr;
    /*The options start here. */
};
/*------------------------------------------------------------------*/

struct tcphdr {
    __be16    source;
    __be16    dest;
    __be32    seq;
    __be32    ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u16    res1:4,
        doff:4,
        fin:1,
        syn:1,
        rst:1,
        psh:1,
        ack:1,
        urg:1,
        ece:1,
        cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u16    doff:4,
        res1:4,
        cwr:1,
        ece:1,
        urg:1,
        ack:1,
        psh:1,
        rst:1,
        syn:1,
        fin:1;
#else
#error    "Adjust your byteorder defines"
#endif    
    __be16    window;
    __sum16    check;
    __be16    urg_ptr;
};

/*Pseudo head*/
struct pseudohdr {
    __be32        saddr;
    __be32        daddr;
    __u8        pad;
    __u8        protocol;
    __be16        len;
};

/*------------------------------------------------------------------*/

struct udphdr {
    __be16    source;
    __be16    dest;
    __be16    len;
    __sum16    check;
};

/*------------------------------------------------------------------*/
/* GRE Version field */
#define GRE_VERSION_1701    0x0
#define GRE_VERSION_PPTP    0x1

/* GRE Protocol field */
#define GRE_PROTOCOL_PPTP    0x880B

/* GRE Flags */
#define GRE_FLAG_C        0x80
#define GRE_FLAG_R        0x40
#define GRE_FLAG_K        0x20
#define GRE_FLAG_S        0x10
#define GRE_FLAG_A        0x80

#define GRE_IS_C(f)    ((f)&GRE_FLAG_C)
#define GRE_IS_R(f)    ((f)&GRE_FLAG_R)
#define GRE_IS_K(f)    ((f)&GRE_FLAG_K)
#define GRE_IS_S(f)    ((f)&GRE_FLAG_S)
#define GRE_IS_A(f)    ((f)&GRE_FLAG_A)


struct gre_hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8  rec:3,
        srr:1,
        seq:1,
        key:1,
        routing:1,
        csum:1;
    __u8    version:3,
        reserved:4,
        ack:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u8    csum:1,
        routing:1,
        key:1,
        seq:1,
        srr:1,
        rec:3;
    __u8    ack:1,
        reserved:4,
        version:3;
#else
#error    "Adjust your byteorder defines"
#endif
    __be16    protocol;
};


/* DNS CLASS values we care about */
#define CLASS_IN	1

/* DNS TYPE values we care about */
#define TYPE_A		1
#define TYPE_CNAME	5

/*
 * The DNS header structure
 *Use this attribute to the variable or structure member using the alignment of the smallest, 
 *is a byte alignment of variables, the domain (field) is an alignment.
 */
struct dnshdr {
    __u16 id;
    __u16 flags;
    /* number of entries in the question section */
    __u16 qdcount;
    /* number of resource records in the answer section */
    __u16 ancount;
    /* number of name server resource records in the authority records section*/
    __u16 nscount;
    /* number of resource records in the additional records section */
    __u16 arcount;
} ;

/*
 * The DNS query structure
 */
struct dnsquery {
    u16 qtype;
    u16 qclass;
} ;

/*
 * The DNS Resource recodes structure
 */
struct dnsrr {
u16 name;
    u16 type;
    u16 class;
    u32 ttl;
    u16 rdlength;   /* The lenght of this rr data */
    char     rdata[4];
}__attribute__ ((packed));

/*
 *	DHCP/BOOTP support. copy  form kernel
 *    2013-5-15 18:36:36 add by zhudm
*/

/* packet ops */
#define BOOTP_REQUEST	1
#define BOOTP_REPLY	2

/* DHCP message types */
#define DHCPDISCOVER	1
#define DHCPOFFER	2
#define DHCPREQUEST	3
#define DHCPDECLINE	4
#define DHCPACK		5
#define DHCPNAK		6
#define DHCPRELEASE	7
#define DHCPINFORM	8

struct bootp_pkt {		/* BOOTP packet format */
	u8 op;			/* 1=request, 2=reply */
	u8 htype;		/* HW address type */
	u8 hlen;		/* HW address length */
	u8 hops;		/* Used only by gateways */
	__be32 xid;		/* Transaction ID */
	__be16 secs;		/* Seconds since we started */
	__be16 flags;		/* Just what it says */
	__be32 client_ip;		/* Client's IP address if known */
	__be32 your_ip;		/* Assigned IP address */
	__be32 server_ip;		/* (Next, e.g. NFS) Server's IP address */
	__be32 relay_ip;		/* IP address of BOOTP relay */
	u8 hw_addr[16];		/* Client's HW address */
	u8 serv_name[64];	/* Server host name */
	u8 boot_file[128];	/* Name of boot file */
	u8 exten[312];		/* DHCP options / BOOTP vendor extensions */
};

#endif



