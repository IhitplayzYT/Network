/* Networks.h */
/*Includes*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <stdoslib/stdoslib.h>
/*Includes*/

/* Typedefinations */
typedef unsigned char i8;
typedef unsigned short i16;
typedef unsigned int i32;
typedef unsigned long i64;
/* Typedefinations */

/* MACROS */
#define public __attribute__((visibility("default")))
#define private static
#define packed __attribute__((packed))
#define internal __attribute__((visibility("hidden")))
#define show(x,y) _Generic((x),\
Icmp*: show_icmp,        \
Ip*:   show_ip,         \
Mac*:show_mac,           \
Ethernet*:show_ether,   \
Bytestr*:show_bs \
)((x),(y))
#define eval(x) _Generic((x),\
Ip*:eval_ip,\
Icmp*:eval_icmp,\
Ethernet*:eval_ether,\
i8 *:eval_raw\
)(x)
#define mkmac(x) _Generic((x),\
i64: to_mac,\
i8*: to_macs \
)(x)
#define FREE(...) freeall(__VA_ARGS__,NULL)
//#define usage(x) _usage((i8*)x)
#define MAX_PACKET_SIZE 2048
#define SRC_ADDR "0.0.0.0"
#define SRC_MAC "00:00:00:00:00:00"
#define TIMEOUT (1)
#define sendping(src,dst,mssg,len) _sendping((i8*)src,(i8*)dst,(i8*)mssg,(i16)len)
#define sendether () _sendether()
/* MACROS */

/* Definations */
enum e_t{unset,e_IP = 0x0800,e_ARP=0x0806}packed;
typedef enum e_t EtherType;

enum public e_type{
None,
echo,
echo_reply,
ICMP,
TCP,
UDP,
Raw
};

typedef enum e_type Type;

struct s_rawicmp{   // 5 bytes
    i8 type;
    i8 code;
    i16 checksum;
    i8 header[];
} packed;
typedef struct s_rawicmp Raw_icmp;

struct s_icmp{
Type type:3;
i16 size;
i8 *header;
}packed;

typedef struct s_icmp Icmp;

union layer{
    Icmp * ip_pkt;
    i8 * raw_pkt;
};
typedef union layer Layer;

struct s_ip{
i32 srcaddr;
i32 dstaddr; 
i16 id;
Type type:3;
Layer payload;
}packed;




typedef struct s_ip Ip;

struct s_raw_ip{    // 20 Bytes
i8 ihl:4;
i8 version:4;
i8 dscp:6;
i8 ecn:2;
i16 len;
i16 id;
i8 flags:3;
i16 frag_offset:13;
i8 ttl;
i8 protocol;
i16 checksum;
i32 srcaddr;
i32 dstaddr;
i8 options[];
}packed;

struct s_ping {
i16 id;
i16 seq;
i8 data[];
}packed;
typedef struct s_ping Ping;

typedef struct s_raw_ip Raw_ip;

struct s_mac{
i8 addr[6];
} packed;

typedef struct s_mac Mac;

struct s_ether{
EtherType protocol;
Mac src,dst;
Ip* payload;
}packed;
typedef struct s_ether Ethernet;

struct s_ether_raw{
Mac dst,src;
i16 ethtype;
}packed;
typedef struct s_ether_raw Raw_Ethernet;

struct s_bytestr{
i16 len;
i8 *data;
} packed;

typedef struct s_bytestr Bytestr;

/* Function Signatures */
int main(int,char**);
public Bytestr * eval_icmp(Icmp*);
public void show_icmp(Icmp*,i8); 
public void helper_ip_icmp(Icmp*,i8); 
public void print_hex(void *,i32);
public i16 checksum(i8*,i16);
public i32 ipaddr(i8*);
public void show_ip(Ip*,i8);
public i8* ipstr(i32);
public Bytestr * eval_ip(Ip*);
public int send_ip(i32,Ip*);
public Ip * recv_ip(i32);
public i32 setup_ip_sock();
public i8 hex2ascii(i8*);
public i8* ascii2hex(i8);
public void show_mac(Mac *,i8);
public Mac* to_macs(i8*);
public Mac* to_mac(i64);
public i8* mac2strf(Mac *);
public i8* mac2str(Mac *);
public void show_ether(Ethernet*,i8);
public Bytestr* eval_ether(Ethernet *);
public i8 _sendping(i8*,i8*,i8*,i16);
public void usage_ip(i8* );
public void usage_ether(i8* );
public void show_bs(Bytestr*,i8);
public i32 setup_ether_sock();
public Icmp * init_icmp(Type,i8*,i16);
public Ip * init_ip(Type,i8*,i8*,i16);
public i32 ipaddr(i8* );
public Ping * init_ping(i8*,i16,i16,i16);
public Ethernet * init_ether(Mac*,Mac*,EtherType);
public Bytestr* init_bytestr(i8*,i16);
public i32 ipaddr(i8* );
public Bytestr* concat_bs(Bytestr*,Bytestr*);
public void freeall(void *,...);
public i8 _sendether(i32,Ethernet * );
public Bytestr * eval_raw(i8 *);
public i8 str2hex(i8 * );
/* Function Signatures */
