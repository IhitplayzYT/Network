#include "Networks.h"
extern i32 global_id;
/*
*
*    CONTAINS CONSTRUCTORS
*
*/


public Ip * init_ip(Type t,i8* s,i8* d,i16 id){
if (!t || !s || !d ) return (Ip*)0;
Ip * ip = (Ip*)malloc(sizeof(Ip));
if (!ip) return (Ip *)0;
ip->id = (!id)? global_id++:id;
ip->type = t;
ip->srcaddr = ipaddr(s);
ip->dstaddr = ipaddr(d);
ip->payload = (Icmp*)0;
if (!ip->dstaddr){free(ip);return (Ip*)0;}
return ip;
}

public Icmp * init_icmp(Type type,i8* data,i16 size){
if (!data || !size){return (Icmp*)0;}
Icmp * icmp = (Icmp*)malloc(sizeof(Icmp));
if (!icmp) {return (Icmp*)0;}
icmp->type = type;
icmp->size = size;
icmp->header = data;
return icmp;
}

public Ping * init_ping(i8* str,i16 len,i16 id,i16 seq){
if (!len || !str) return (Ping *)0;
if (!id) id = rand() % 50000;
Ping * ping = (Ping *)malloc(sizeof(Ping) + len);
if (!ping) return (Ping*)0;
ping->id = id;
ping->seq = seq;
memcopy(ping->data,str,len);
return ping;
}

public Ethernet * init_ether(Mac* src,Mac* dst,EtherType type){
if (!src || !dst || !type) return (Ethernet*)0;
Ethernet * ether = (Ethernet*)malloc(sizeof(Ethernet));
if (!ether) return (Ethernet*)0;
ether->protocol = type;
ether->src = *src;
ether->dst = *dst;
ether->payload = (Ip*)0;
return ether;
}

public Bytestr* init_bytestr(i8* str,i16 n){
if (!*str || !n) return (Bytestr*)0;
Bytestr * bs = (Bytestr*)malloc(sizeof(Bytestr
) + n);
if (!bs) return (Bytestr*)0;
bs->data = str;
bs->len = n;
return bs;
}