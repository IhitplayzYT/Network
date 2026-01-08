/* Networks.c */
#include "Networks.h"

i16 global_id;
i16 seq,id;
/*
int main(int argc,char * argv[]) { 
srand(getpid());
global_id = rand() % 50000;
seq = 0;
i16 count = 5;
id = rand() % 50000;
i8* dst,*mssg;
i16 l;
if (argc < 2) {usage(argv[0]);return -1;}
else if (argc == 2) {
if (strcomp(argv[1],"-h")==0 || strcomp(argv[1],"-help")==0 ){usage(argv[0]);return -1;}
dst = (i8*)argv[1];
mssg = (i8*)"Hello";
l = 5;
}
else if (argc == 3){
dst = (i8*)argv[1];
mssg = (i8*)argv[2];
l = len(mssg);
}
else if (argc == 4){
dst = (i8*)argv[1];
mssg = (i8*)argv[2];
l = stoi((i8*)argv[3]);
}
else {usage(argv[0]);return -1;}
printf("Sending 5 packets of %d bytes ICMP echoes to %s | Timeout = %ds\n",l,dst,TIMEOUT);
i8 c = 0;
if (l > 225){printf("Mssg To Big!!\n");return -2;}
for (int i = 0 ; i < count; i++){
i8 ret = sendping(SRC_ADDR,dst,mssg,l);
if (!ret) {printf("!");c++;}
else printf(".%d",ret);
fflush(stdout);
}
if (!c) {fprintf(stderr,"\nError!\n");return -3;}
printf("\nSuccess Rate (%d/%d) : %.02f %%\n",c,seq,(float)(c/5) * 100);
return 0; 
}
*/


int main(int argc,char * argv[]){
Mac * s = mkmac((i8*)"12AF:461C:DDEF");
Mac * d = mkmac((i8*)"1ade:3832:def9");
Ethernet * ether = init_ether(s,d,e_ARP);
srand(getpid());
global_id = rand() % 50000;
seq = 0;
id = rand() % 50000;
Ping * str = init_ping((i8*)"oemaifnw",9,endian(id),endian(seq));
seq++;
if (!str) return 2;
Icmp *pkt = init_icmp(echo,(i8*)str,sizeof(Ping) + 9);
if (!pkt) return 3;
Ip* ip = init_ip(ICMP,(i8*)SRC_ADDR,(i8*)"1.1.1.1",0);
if (!ip) return 4;
ip->payload = pkt;
ether->payload = ip;
show(ether,1);

free(pkt);
free(ip);
free(s);
free(d);
free(ether);
return 0;
}

public i8 _sendping(i8* src,i8*dst,i8* mssg,i16 len){
if (!*src || !*dst || !*mssg) return 1;

Ping * str = init_ping((i8*)mssg,len+1,endian(id),endian(seq));
seq++;
if (!str) return 2;
Icmp *pkt = init_icmp(echo,(i8*)str,sizeof(Ping) + len+1);
if (!pkt) return 3;
Ip* ip = init_ip(ICMP,(i8*)src,(i8*)dst,0);
if (!ip) return 4;
ip->payload = pkt;
i32 sock = setup_ip_sock();
if (!sock) {close(sock);free(ip->payload);free(ip);return 5;}

int x = send_ip(sock,ip);
if (!x){close(sock);free(ip->payload);free(ip);return 6;}
Ip* reply = recv_ip(sock);
if (!reply){
    close(sock);free(ip->payload);free(ip);free(reply);return 7;}
close(sock);
free(ip->payload);
free(ip);
if (reply->payload && reply->payload->header)free(reply->payload);
if (reply->payload) free(reply);
return 0;
}


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

public Bytestr* eval_ip(Ip* ip){
if (!ip) return (Bytestr*)0;
Raw_ip raw;
raw.version = 4;
raw.ihl = (sizeof(Raw_ip))/4;
raw.dscp = 0;
raw.ecn = 0;
raw.len = (ip->payload)? endian(sizeof(Raw_ip) + ip->payload->size + sizeof(Raw_icmp)):endian(sizeof(Raw_ip));
raw.id = endian(ip->id);
raw.flags = 0;
raw.frag_offset= 0;
raw.ttl = 250;
raw.protocol = (ip->type == ICMP)?1:0;
raw.checksum = 0;
raw.srcaddr = ip->srcaddr;
raw.dstaddr = ip->dstaddr;
i8 * p = (i8*)malloc(raw.len);
if (!p) return (Bytestr*)0;
i8* k = p;
zero(p,raw.len);
memcopy(p,&raw,sizeof(Raw_ip));
p+=sizeof(Raw_ip);
if (ip->payload && ip->payload->size){
    Bytestr* bs = eval((Icmp*)ip->payload);
    i8* k = bs->data;
    i16 l = bs->len;
    if (k){copy(p,k,l);}
    free(bs);
    free(k);
}
Raw_ip * rawp;
rawp = (Raw_ip*)k;
rawp->checksum = endian(checksum(p,endian(raw.len)));
Bytestr* bs = init_bytestr(k,endian(raw.len));
return bs;
}


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
if (!n){ip->payload = (Icmp*)0;return ip;}

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
ip->payload = pv;

return ip;
}

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

public i8* mac2str(Mac * mac){
if (!mac) return (i8*)0;
i8 * ret = (i8*)malloc(20);
if (!ret) return (i8*)0;
zero(ret,20);
snprintf((char *)ret,19,"%.03hhu%.03hhu%.03hhu%.03hhu%.03hhu%.03hhu",mac->addr[0],mac->addr[1],mac->addr[2],mac->addr[3],mac->addr[4],mac->addr[5]);
return ret;
}

public Mac * to_mac(i64 arg){
Mac * mac = (Mac *)malloc(sizeof(Mac));
if (!mac) return (Mac*)0;
for (int i = 0 ; i < 6 ; i++) mac->addr[0] = arg & (0x00000000000000ff << i);
return mac;
}

public Mac* to_macs(i8* str){
if (!*str) return (Mac*)0;
Mac * mac = (Mac *)malloc(sizeof(Mac));
i8 k = 0,j = 0;
i8 buff[3] = {0};
if (!mac) return (Mac*)0;
for (int i = 0 ;str[i];i++){
if (str[i] == ':' || str[i] == '.') continue;
buff[j++] = str[i];
if (j == 2){
mac->addr[k++] = hex2ascii(buff);
j = buff[0] = buff[1] = buff[2] = 0;}
}
if (k != 6) {return (Mac*)0;}
return mac;
}

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

public void show_ether(Ethernet* e,i8 l){
printf("---Ethernet---\nPROTOCOL: %s\nSRC: %s\nDST: %s\n\n<PAYLOAD>\n",(e->protocol == 0)?"UNSET":(e->protocol == 0x08)?"IP":(e->protocol = 0x0806)?"ARP":"UNDEFINED",mac2strf(&e->src),mac2strf(&e->dst));
if(l){show(e->payload,1);}
printf("\n--------------\n");
}


public void show_bs(Bytestr* bs,i8 flag){
if (!bs) return;
if (flag) printf("[%d]-",bs->len);
printf("[%s]\n",bs->data);
}


public i32 setup_ether_sock(){
i32 s = socket(AF_PACKET,SOCK_PACKET,1);
if (s==-1) return 0;
}