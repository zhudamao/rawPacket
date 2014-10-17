#ifndef __TYPES_H__
#define __TYPES_H__

typedef unsigned long long u64;
typedef signed long long   s64;
typedef unsigned int       u32;
typedef signed int         s32;
typedef unsigned short     u16;
typedef signed short       s16;
typedef unsigned char      u8;
typedef signed char        s8;

typedef u8   __u8;
typedef u16  __u16;
typedef u32  __u32;
typedef u64  __u64;

typedef u16   __be16;
typedef u32   __be32;
typedef u16   __sum16;

typedef  unsigned long  ulong;
typedef  unsigned char  uchar;
typedef  unsigned int   uint;
typedef  unsigned short ushort;

#ifndef ALIGN
#define ALIGN(x, a)    (((x) + (a) - 1) & ~((a) - 1))
#endif

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#ifndef container_of
/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:    the pointer to the member.
 * @type:   the type of the container struct this is embedded in.
 * @member: the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({            \
    const typeof(((type *)0)->member) * __mptr = (ptr);    \
    (type *)((char *)__mptr - offsetof(type, member)); })
#endif


#define _ADDR0( val )   ((u8)((u32)(val)&(0xff)))
#define _ADDR1( val )   ((u8)((u32)(val)>>8&(0xff)))
#define _ADDR2( val )   ((u8)((u32)(val)>>16&(0xff)))
#define _ADDR3( val )   ((u8)((u32)(val)>>24&(0xff)))


#define MK_ADDR(v1,v2,v3,v4)  ( ((v1) |(v2)<<8 | (v3)<<16 | (v4)<<24 ))
#define _ADDR(val) \
        _ADDR0( val ),_ADDR1( val ),_ADDR2( val ),_ADDR3( val )

#endif  /* __TYPES_H__ */



