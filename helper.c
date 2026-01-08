#include "Networks.h"

public void _copyn(i8 *a,i8 *b,i16 n,i8 z){
if (!a || !b) return;
if (z==1) for (;n;n--,a++,b++) *a = *b;
else{
for (;n && *a != '\0' && *b != '\0';n--,a++,b++)*a = *b;
*a = '\0';
}
}

public void zero(i8* str,i32 n){
i8* p;
for (p =str;n;n--,p++) *p = 0;
}

void print_hex(void *str, i32 n) {
i32 i, j;
i8 *data = (i8*)str;
for (i = 0; i < n; i += 16) {
for (j = 0; j < 16; j++) {
    if (i + j < n) printf("0x%02hhX ", data[i + j]);
    else printf("     "); }
printf(" ");
for (j = 0; j < 16 && i + j < n; j++) {
    i8 c = data[i + j];
    printf("%c", (c >= 32 && c <= 126) ? c : '.');}
printf("\n");
}}

public void show_icmp(Icmp* icmp,i8 df){
if (!icmp){return;}
printf("\n---ICMP HEADER---\nType : %s\nSize : %d Bytes\n",(icmp->type == None)?"Default":(icmp->type == echo)?"Echo":(icmp->type == echo_reply)?"Echo Reply":"Invalid Type",icmp->size);
if (icmp->type == echo || icmp->type == echo_reply){
Ping * ping = (Ping *)icmp->header;
printf("Id: %d\nSeq: %d\n",endian(ping->id),endian(ping->seq));
}
if (df) print_hex(icmp->header,icmp->size);
printf("-------------\n\n");
}

public void helper_ip_icmp(Icmp* icmp,i8 df){
if (!icmp){return;}
printf("\n  [Payload]\n\tType : %s\n\tSize : %d Bytes\n\t",(icmp->type == None)?"Default":(icmp->type == echo)?"Echo":(icmp->type == echo_reply)?"Echo Reply":"Invalid Type",icmp->size);
if (icmp->type == echo || icmp->type == echo_reply){
Ping * ping = (Ping *)icmp->header;
printf("Id: %d\n\tSeq: %d\n",endian(ping->id),endian(ping->seq));
}
if (df) print_hex(icmp->header+4,icmp->size-sizeof(Ping)-1);
printf("-------------\n\n");
}

public void show_ip(Ip* ip,i8 flag){
if (!ip) return;
printf("\n---IP HEADER---\nID : %d\nType : %s\n[ %s ] -> [ %s ]\n   (SRC)      ->     (DST)\n",ip->id,(ip->type == TCP)?"TCP":(ip->type == UDP)?"UDP":(ip->type == ICMP)?"ICMP":"Invalid Type",ipstr(ip->srcaddr),ipstr(ip->dstaddr));
if (ip->payload) helper_ip_icmp((Icmp*)ip->payload,flag);
else printf("-------------\n\n");}

public i32 ipaddr(i8* s){
i8 a[4] = {0},*p,c = 0;
i32 ret;
for (p = s;*p;p++){
if (*p == '.' || *p == '-' || *p == ':') c++;
else{
a[c] *= 10;
a[c] += *p - '0';
}}
ret = (a[3] << 24) | (a[2] << 16) | (a[1] << 8) | a[0];
return ret;
}

public i8* ipstr(i32 addr){
i8 *buff = (i8*)malloc(16);
zero(buff,16);
i8 a[4];
a[0] = (addr & 0xff000000) >> 24;
a[1] = (addr & 0x00ff0000) >> 16;
a[2] = (addr & 0x0000ff00) >> 8;
a[3] = (addr & 0x000000ff);
snprintf((char*)buff, 16, "%u.%u.%u.%u", a[3], a[2], a[1], a[0]);
return buff;
}

public i16 endian(i16 x){
i8 a,b;
i16 c;
a = x & 0x00ff;
b = (x & 0xff00) >> 8;
c = (a << 8) | b;
return c;
}

public i16 _len(i8* str){
i8* p = str;
for (;*p;p++);
return (p - str);
}

public i16 _pow(i16 x,i16 n){
if (x <= 1 || n == 1) return x;
if (n == 0) return 1;
i16 ret = 1;
for (i16 i = 0 ; i < n; i++){
ret *= x;
}
return ret;
}

public i16 _stoi(i8*s){
i16 l = len(s);
i16 ret = 0;
for (i16 i = 0 ;i < l;i++){
if (s[i] >= '0' && s[i] <= '9') ret += (s[i] - '0') * _pow(10,l-i-1);
else if (s[i] == '+' || s[i] == ',' || s[i] == '_') continue;
else return 0;
}
return ret;
}

public void _usage(i8* name){
fprintf(stderr,"Usage : %s <Dest_IP> [MSSG] [Mssg_len]\n",name);
}

public i8 hex2ascii(i8* s){
i8 t = len(s) - 1;
i8 ret=0,k=1;
for (int i = t; i > -1 ;i--){
if (s[i] >= 'A' && s[i] <= 'F'){ret += ((s[i] -'A'+10) * k);}
else if(s[i] >= 'a' && s[i] <= 'f'){ret += ((s[i] -'a'+10) * k);}
else{ ret += ((s[i] - '0') * k);}
k *= 16;
}
return ret;
}

public i8* ascii2hex(i8 x){
if (!x) return (i8*)0;
i8* ret = (i8*)malloc(3);
*ret = *(ret+1) = *(ret+2) = 0;
if (!ret) return (i8*)0;
while (x > 16) {
i8 rem = x % 16;
if (rem > 9) ret[1] = 'A' + (rem-10);
else ret[1] = '0' + rem;
x /= 16;
}
if (x > 9) ret[0] = 'A' + (x-10);
else ret[0] = x + '0';
return ret;
}

public i8 _strcomp(i8* a,i8* b){
i8 * p = a,*q = b;
while (*p && *q){
if (*p > *q) return 1;
if (*p < *q) return -1;
p++;q++;}
return (*p == *q)?0:(!*p)?-1:1;
}