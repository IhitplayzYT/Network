/* Networks.c */
#include "Networks.h"

i16 global_id;
i16 seq,id;

void init() {
srand(getpid());
global_id = rand() % 50000;
seq = 0;
id = rand() % 50000;
}

/*
int main(int argc,char * argv[]) { 
i16 count = 5,l;
i8* dst,*mssg;
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

boolean ping(char * message,char * src,char * dst,int npackets,int mssg_len){
if (!mssg_len) {
mssg_len = len(message);
if (!mssg_len) {return false;}
}
if (!npackets) {
    npackets = 5;
}
if (!src || !dst || !*src || !*dst) {return false;}
i8 c = 0;
for (int i = 0 ; i < npackets; i++){
i8 ret = sendping(SRC_ADDR,dst,message,mssg_len);
if (!ret) {printf("!");c++;}
else printf(".%d",ret);
fflush(stdout);
}
if (!c) {fprintf(stderr,"\nError!\n");return -3;}
printf("\nSuccess Rate (%d/%d) : %.02f %%\n",c,seq,(float)((float)c/5.0) * 100);
return true;
}




int main(int argc,char * argv[]){
init();
Mac * s = mkmac((i8*)"12AF:461C:DDEF");
Mac * d = mkmac((i8*)"1ade:3832:def9");
Ethernet * ether = init_ether(s,d,e_ARP);
Ping * str = init_ping((i8*)"helloworld",9,endian(id),endian(seq));
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





public i32 setup_ether_sock(){
i32 s = socket(AF_PACKET,SOCK_PACKET,1);
if (s==-1) return 0;

return s;
}