#ifndef __PACP_MAIN_H_
#define __PACP_MAIN_H_
/*debug infomation*/
//#define RST_DEBUG 

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "types.h"

typedef struct {
	u32 src ;
	u32 det ;
	u16 tot_len ;
}IP_NEED;


typedef struct {
	u16 	src_port ;
	u16 des_port ;
}UDP_NEED;

typedef struct {
	u16 	src_port ;
	u16 des_port ;
	u32    seq ;
    	u32    ack_seq ;
	u32  expect_seq;
}TCP_NEED;

#define calcu_ab_seq(seq, offbase) (seq+ offbase  >(u32)0x100000000LL? ( (seq+ offbase) -(u32)0x100000000LL) : ( offbase + seq))
#define NUM_PCK 5

#endif

