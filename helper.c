#include <ctype.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <stdoslib/stdoslib.h>
#include <sys/socket.h>
#include "Networks.h"
extern int seq,id;


/**
 * @brief Prints hex of the ptr provided
 * @param ptr Pointer to memory location being printed
 * @param n NO of bytes to print the hex of
 * @return void
 */
void print_hex(void *ptr, i32 n) {
i32 i, j;
i8 *data = (i8*)ptr;
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


/**
 * @brief Prints an ICMP packet with it's fields
 * @param icmp The pointer to the icmp packet being printed
 * @param df when true prints the underling payload
 * @return void
 */
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

/**
 * @brief Prints an Ethernet struct with it's fields
 * @param pkt The pointer to the ethernet struct being printed
 * @param df when true prints the underling payload
 * @return void
 */
public void show_ether(Ethernet* pkt,i8 df){
printf("---Ethernet---\nPROTOCOL: %s\nSRC: %s\nDST: %s\n\n<PAYLOAD>\n",(pkt->protocol == 0)?"UNSET":(pkt->protocol == 0x08)?"IP":(pkt->protocol = 0x0806)?"ARP":"UNDEFINED",mac2strf(&pkt->src),mac2strf(&pkt->dst));
if(df){show(pkt->payload,1);}
printf("\n--------------\n");
}

/**
 * @brief Prints the byte string struct
 * @param bs The pointer to the Bytestring struct being printed
 * @param flag when true prints the length
 * @return void
 */
public void show_bs(Bytestr* bs,i8 flag){
if (!bs) return;
if (flag) printf("[%d]-",bs->len);
printf("[%s]\n",bs->data);
}


/**
 * @brief Prints the Payload of Icmp packet
 * @param icmp The pointer to the Icmp packet being printed
 * @param df when true prints the header in hex
 * @return void
 */
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

/**
 * @brief Prints the Ip packet
 * @param ip The pointer to the IP packet being printed
 * @param flag when true prints the header in hex 
 * @return void
 */
public void show_ip(Ip* ip,i8 flag){
if (!ip) return;
printf("\n---IP HEADER---\nID : %d\nType : %s\n[ %s ] -> [ %s ]\n   (SRC)      ->     (DST)\n",ip->id,(ip->type == TCP)?"TCP":(ip->type == UDP)?"UDP":(ip->type == ICMP)?"ICMP":"Invalid Type",ipstr(ip->srcaddr),ipstr(ip->dstaddr));
if (ip->payload.ip_pkt) helper_ip_icmp((Icmp*)ip->payload.ip_pkt,flag);
else printf("-------------\n\n");
}


/**
 * @brief Converts a IP address string into 32 bit packed IPv4 integer
 * @param ipstr The pointer to the IP packet being printed
 * @return 32 bit integer 
 */
public i32 ipaddr(i8* ipstr){
i8 a[4] = {0},*p,c = 0;
i32 ret;
for (p = ipstr;*p;p++){
if (*p == '.' || *p == '-' || *p == ':') c++;
else{
a[c] *= 10;
a[c] += *p - '0';
}}
ret = (a[3] << 24) | (a[2] << 16) | (a[1] << 8) | a[0];
return ret;
}

/**
 * @brief Converts a 32 bit packed IPv4 integer into an IP address string
 * @param addr The pointer to the IP packet being printed
 * @return IP address as a string
 */
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

/**
 * @brief Helper fxn for len [MACRO]
 * @param str
 * @return 16 bit unsigned length
 */
public i16 _len(i8* str){
i8* p = str;
for (;*p;p++);
return (p - str);
}

/**
 * @brief Helper fxn for usage [MACRO]
 * @param name
 * @return void 
 */
public void usage_ip(i8* name){
fprintf(stderr,"Usage : %s <Dest_IP> [MSSG] [Mssg_len]\n",name);
}
public void usage_ether(i8* name){
fprintf(stderr,"Usage : %s <SRC_MAC> <DST_MAC> <SRC_IP> <DST_IP> <MSSG> <MSSG_LEN>\n",name);
}

/**
 * @brief Converts a hex string into ascii value 
 * @param str Hex string to be converted
 * @return i8 returns a single scii code
 */
public i8 hex2ascii(i8* str){
i8 t = len(str) - 1;
i8 ret=0,k=1;
for (int i = t; i > -1 ;i--){
if (str[i] >= 'A' && str[i] <= 'F'){ret += ((str[i] -'A'+10) * k);}
else if(str[i] >= 'a' && str[i] <= 'f'){ret += ((str[i] -'a'+10) * k);}
else{ ret += ((str[i] - '0') * k);}
k *= 16;
}
return ret;
}

/**
 * @brief Converts a ascii value into a hex string
 * @param x AScii value to be converted
 * @return string returns the string hex representation
 */
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

public i8 _sendether(i32 sock, Ethernet * eth){
if (!sock | !eth) return 0;
Bytestr * bs = eval(eth);
int ret = send(sock, bs->data, bs->len, 0);
    return ret;
}


/**
 * @brief sends a ping request
 * @param src the source ip string 
 * @param dst the destination ip string 
 * @param mssg the message to be transmitted in the packet
 * @param len the length of the message to eb sent 
 * @return i8 return 0 for success else fail 
 */
public i8 _sendping(i8* src,i8*dst,i8* mssg,i16 len){
if (!*src || !*dst || !*mssg) return 1;  //  Checking for NULL args
Ping * str = init_ping((i8*)mssg,len+1,endian((i32)id),endian((i32)seq)); // To init the ping packet
seq++;  // To manage the autoincrementation of the seq inorder to have unqiue IDs
if (!str) return 2;
Icmp *pkt = init_icmp(echo,(i8*)str,sizeof(Ping) + len+1);   // To init the Icmp packet
if (!pkt) return 3;
Ip* ip = init_ip(ICMP,(i8*)src,(i8*)dst,0);
if (!ip) return 4;
ip->payload.ip_pkt = pkt;
i32 sock = setup_ip_sock();
if (!sock) {close(sock);free(ip->payload.ip_pkt);free(ip);return 5;}

int x = send_ip(sock,ip);
if (!x){close(sock);free(ip->payload.ip_pkt);free(ip);return 6;}
Ip* reply = recv_ip(sock);
if (!reply){
    close(sock);free(ip->payload.ip_pkt);free(ip);free(reply);return 7;}
close(sock);
free(ip->payload.ip_pkt);
free(ip);
if (reply->payload.ip_pkt && reply->payload.ip_pkt->header)free(reply->payload.ip_pkt);
if (reply->payload.ip_pkt) free(reply);
return 0;
}

/**
 * @brief Converts a icmp packet into a Bytestring holding the reply recieved
 * @param icmp Pointer to the icmp packet recieved
 * @return Pointer to the reply buffer as Bytestring
 */
public Bytestr* eval_icmp(Icmp* icmp){
if (!icmp) return (Bytestr*)0;
i8 * p;
Raw_icmp raw;
switch(icmp->type){
case echo:
raw.type = 8;
raw.code = 0;
break;
case echo_reply:
raw.type = 0;
raw.code = 0;
break;
case None:
default:
return (Bytestr*)0;
break;
}
i32 size = sizeof(Raw_icmp) + icmp->size;
if (size & 1) size++;
p = (i8*)malloc(size);
if (!p) return (Bytestr*)0;
i16 t = sizeof(Raw_icmp);
memcopy(p,&raw,t);
memcopy(p+t,icmp->header,icmp->size);
i16 check = checksum(p,size); 
Raw_icmp * rawp = (Raw_icmp*)p;
rawp->checksum = check;
Bytestr* bs = init_bytestr(p,size);
return bs;
}

/**
 * @brief Calculates the checksum of a struct of size 'size'
 * @param str The packet/struct/arbitary pointer whose checksunm being calculated
 * @param size The size of the packet/struct/arbitraty pointer whose checksum to be calculated
 * @return 16 bit checksum
 */
public i16 checksum(i8* str,i16 size){
i32 acc = 0;
i16 carry,n = size,b,sum;
i16 *p;
for (p = (i16*)str;n;p++,n-=2){
b =*p;
acc += b;
}
carry = (acc & 0xffff0000) >> 16;
sum = acc & 0x0000ffff;
return ~(sum + carry);
}

/**
 * @brief Converts a Ip packet into a Bytestring holding the reply recieved
 * @param ip Pointer to the Ip packet recieved
 * @return Pointer to the reply buffer as Bytestring
 */
public Bytestr* eval_ip(Ip* ip){
if (!ip) return (Bytestr*)0;

Raw_ip raw;
raw.version = 4;
raw.ihl = (sizeof(Raw_ip))/4;
raw.dscp = 0;
raw.ecn = 0;
raw.len = endian(sizeof(Raw_ip) + (ip->payload.raw_pkt ? ((ip->type == ICMP) ? ip->payload.ip_pkt->size + sizeof(Raw_icmp) : len(ip->payload.raw_pkt)) : 0)) ;
raw.id = endian(ip->id);
raw.flags = 0;
raw.frag_offset= 0;
raw.ttl = 250;
raw.protocol = (ip->type == ICMP)?1:(ip->type == Raw)?0:-1;
raw.checksum = 0;
raw.srcaddr = ip->srcaddr;
raw.dstaddr = ip->dstaddr;
i8 * p = (i8*)malloc(raw.len);
if (!p) return (Bytestr*)0;
i8* k = p;
zero(p,raw.len);
memcopy(p,&raw,sizeof(Raw_ip));
p+=sizeof(Raw_ip);
if (ip->payload.raw_pkt){
    Bytestr* bs = (ip->type ==  ICMP) ? eval((Icmp*)ip->payload.ip_pkt):eval((i8 *)ip->payload.raw_pkt);
    if (bs) {
    if (k) copy(p,bs->data,bs->len);
    free(bs);
    }
}
Raw_ip * rawp;
rawp = (Raw_ip*)k;
rawp->checksum = endian(checksum(p,endian(raw.len)));
Bytestr* bs = init_bytestr(k,endian(raw.len));
return bs;
}

/**
 * @brief Fuinction that recives raw bytes and parses the data to IP packet
 * @param s The RawBytes
 * @return IP packet Pointer
 */
public Ip * recv_ip(i32 s){
if (!s) return (Ip *)0;
i8 buff[MAX_PACKET_SIZE];
zero((i8*)&buff,MAX_PACKET_SIZE);
Raw_ip * raw;
Raw_icmp * rawicmp;
int n = recvfrom(s,&buff,MAX_PACKET_SIZE-1,0,0,0);
if (n < 0) return (Ip*)0;
raw = (Raw_ip*)buff;
i16 id = endian(raw->id);
i16 csum = checksum(buff,((n % 2) ? ++n : n));
if (csum){fprintf(stderr,"IP Checksum Error %.04hx! Packets Comprimised!\n",raw->checksum);return (Ip*)0;}
Type kind = (raw->protocol == 1) ? ICMP:None;
if (kind != ICMP){fprintf(stderr,"Unsupported Packet Type\n");return (Ip*)0;}
Ip* ip = init_ip(kind,ipstr(raw->srcaddr),ipstr(raw->dstaddr),id);
if (!ip) return (Ip *)0;
n -= sizeof(Raw_ip);
if (!n){ip->payload.ip_pkt = (Icmp*)0;return ip;}

rawicmp = (Raw_icmp*)(buff+sizeof(Raw_ip));
Ping * ping;
Type t;
if (rawicmp->type == 8 && rawicmp->code == 0) {t = echo;}
else if (rawicmp->type == 0 && rawicmp->code == 0) {t = echo_reply;}
else {fprintf(stderr,"Unsupported Packet Type\n");return (Ip*)0;}

csum = checksum((i8*)rawicmp,(n%2)?++n:n);
if (csum){fprintf(stderr,"ICMP Checksum Error %.04hx! Packets Comprimised!\n",rawicmp->checksum);return (Ip*)0;}

n -= sizeof(Raw_icmp);
if (!n) ping = (Ping *)0;
else {ping = (Ping *)malloc(n);
if (!ping) return (Ip *)0;}
zero((i8*)ping,n);
memcopy(ping,rawicmp->header,n);
Icmp * pv = init_icmp(t,(i8*)ping,n);
if (!pv) return (Ip *)0;
ip->payload.ip_pkt = pv;

return ip;
}

/**
 * @brief Fuinction that sends the packet to the open socket 
 * @param s The Socket where we are supposed to send to 
 * @param ip Packet to be sent
 * @return returns 1 for success else failure
 */
public int send_ip(i32 s,Ip* ip){
if (!s || !ip) return 0;
Bytestr * t = eval(ip);
i8 * raw = t->data;
i16 l = t->len;
signed int ret;
struct sockaddr_in sock; 
zero((i8*)&sock,sizeof(sock));
sock.sin_family  = AF_INET;
sock.sin_addr.s_addr = (in_addr_t)ip->dstaddr;
// i32 len = sizeof(Raw_ip);
// len += (ip->payload && ip->payload->size)? sizeof(Raw_icmp) + ip->payload->size:0;
ret = sendto((int)s,raw,(int)l,0,(const struct sockaddr *)&sock,sizeof(sock));
if (ret < 0) return  0;
return 1;
}

/**
 * @brief Setup the socket properties to send and recive IP packets and adding a timer
 * @return The Socket
 */
public i32 setup_ip_sock(){
i32 one = 1;
i32 s = socket(AF_INET,SOCK_RAW,1);
if (s <= 2) return 0;
struct timeval t;
t.tv_sec = TIMEOUT;
t.tv_usec = 0;
if (setsockopt(s,SOL_IP,IP_HDRINCL,(const void *)&one,sizeof(i32)) == -1) return 0;
if (setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,&t,sizeof(t)) == -1) {close(s);return 0;}
  return s;
}

/**
 * @brief Setup the socket properties to send and recive Ethernet packets and adding a timer
 * @return The Socket
 */
public i32 setup_ether_sock(){
struct timeval t;
t.tv_sec =  TIMEOUT;
t.tv_usec = 0;
i32 one = 1;
int s = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
if (s==-1) return 0;

if (setsockopt(s,SOL_IP,IP_HDRINCL,(const void *)&one,sizeof(i32)) == -1) return 0;
if (setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,&t,sizeof(t)) == -1) {close(s);return 0;}
return s;
}


/**
 * @brief Function to show the Mac structure 
 * @param m Pointer to Mac struct being displayed
 * @param x To Choose between the seperator(0 -> 1.2.3.4, 1 -> 1:2:3:4)
 * @return void
 */
public void show_mac(Mac * m,i8 x){
if (x == 0){
for (int i = 0;i < 6;i++){
if (i && !(i & 1)){
printf(".");
}
printf("%.02X",m->addr[i]);
}
printf("\n");}
else if (x == 1){
for (int i = 0;i < 6;i++){
if (i) printf(":");
printf("%.02X",m->addr[i]);
}
printf("\n");   
}
}

/**
 * @brief Converts Mac struct to a Formatted Mac address string 
 * @param mac The pointer to Mac address struct
 * @return string 
 */
public i8* mac2strf(Mac * mac){
if (!mac) return (i8*)0;
i8 * buff = (i8*)malloc(16);
if (!buff) return (i8*)0;
i8 k = 0;
for (int i = 0 ; i < 6;i++){
i8* t = ascii2hex(mac->addr[i]);
buff[k++] = t[0];
buff[k++] = t[1];
if (k > 16) continue;
if (k % 3) buff[k++] = ':';
}
return buff;
}

/**
 * @brief Converts Mac struct to a unformatted Mac address string 
 * @param mac The pointer to Mac address struct
 * @return string 
 */

public i8* mac2str(Mac * mac){
if (!mac) return (i8*)0;
i8 * ret = (i8*)malloc(20);
if (!ret) return (i8*)0;
zero(ret,20);
snprintf((char *)ret,19,"%.03hhu%.03hhu%.03hhu%.03hhu%.03hhu%.03hhu",mac->addr[0],mac->addr[1],mac->addr[2],mac->addr[3],mac->addr[4],mac->addr[5]);
return ret;
}

/**
 * @brief convert packed mac address number to mac struct
 * @param arg packed mac address int
 * @return pointer to a mac address struct
 */
public Mac * to_mac(i64 arg){
Mac * mac = (Mac *)malloc(sizeof(Mac));
if (!mac) return (Mac*)0;
for (int i = 0 ; i < 6 ; i++) mac->addr[0] = arg & (0x00000000000000ff << i);
return mac;
}

/**
 * @brief convert string mac address number to mac struct
 * @param str String mac address int
 * @return pointer to a mac address struct
 */
public Mac* to_macs(i8* str){
if (!*str) return (Mac*)0;
Mac * mac = (Mac *)malloc(sizeof(Mac));
if (!mac) return (Mac*)0;
char delim = (freq(str,(i8)'.') == 0)?':':'.';
struct s_Tok_ret *tokens= tokenise(str, delim);
if (tokens->n == 6) {
for (int i = 0 ; i < tokens->n;i++) {
mac->addr[i] = str2hex(tokens->ret[i]);
}
}
else if (tokens->n == 3) {
// 1234:2345:2345
for (int i = 0 ; i < tokens->n;i++) {
i8 * first = NULL;
strncopy(first, tokens->ret[i], 2);
mac->addr[2 * i] = str2hex(first);
mac->addr[2 * i + 1] = str2hex(tokens->ret[i]+2);
}
}else{
    free(mac);
    return 0;
}
//i8 k = 0,j = 0;
//i8 buff[3] = {0};
//for (int i = 0 ;str[i];i++){
//if (str[i] == ':' || str[i] == '.') continue;
//buff[j++] = str[i];
//if (j == 2){
//mac->addr[k++] = hex2ascii(buff);
//j = buff[0] = buff[1] = buff[2] = 0;}
//}
//if (k != 6) {return (Mac*)0;}
free(tokens);
return mac;
}

/**
 * @brief Convert an Ethernet packet into Bystestr struct
 * @param ether The ethernet packet being converted into a Bytestr
 * @return pointer to a Bytestr struct 
 */
public Bytestr* eval_ether(Ethernet * ether){
if (!ether) return (Bytestr*)0;
Raw_Ethernet *raw;
i8* ret = (i8*)malloc(sizeof(Raw_Ethernet));
if (!ret) return (Bytestr*)0;
raw = (Raw_Ethernet*)ret;
raw->dst = ether->dst;
raw->src = ether->src;
raw->ethtype = ether->protocol;
Bytestr *b1 = init_bytestr(ret,sizeof(Raw_Ethernet));
if (!ether->payload) return b1;
Bytestr * b2 = eval(ether->payload);
if (!b2) {free(b1);return (Bytestr*)0;}
return concat_bs(b1,b2);
}

/**
 * @brief To concat/append two Bytestrings
 * @param b1 Bytestring 1
 * @param b2 Bytestring 2
 * @return Pointer to New Allocated Bytestring
 */
public Bytestr* concat_bs(Bytestr* b1,Bytestr* b2){
if ((!b1 && !b2) || (!b1->len && !b2->len)) return (Bytestr*)0;
else if (!b1->len) return b2;
else if (!b2->len) return b1;
else{
i8 * ret = (i8*)malloc(sizeof(b1->len+b2->len));
if (!ret) return (Bytestr*)0;
memcopy(ret,b1->data,b1->len);
memcopy(ret+b1->len,b2->data,b2->len);
Bytestr * bs = init_bytestr(ret,b1->len+b2->len);
free(b1);
free(b2);
return bs;
}
}

void freeall(void * first,...){
va_list args;
va_start(args, first);
void * ptr = first;
while (ptr){
    free(ptr);
    ptr = va_arg(args, void *);
}
va_end(args);
}

Bytestr * eval_raw(i8 * raw) {
    return init_bytestr(raw, len(raw));
}

public i8 str2hex(i8 * str) {
int l = len(str);
i8 ret=0;
if (l > 2 ) return -1;
for (int i = 0 ; i < l ; i++) {
    if (str[i] >= '0' && str[i] <= '9'){
        ret += str[i]-'0';
    }
    else{
        char lwr = tolower(str[i]);
        ret += (lwr >= 'a' && lwr <= 'z') ? lwr - 'a': 0;
    }

}
return ret;
}