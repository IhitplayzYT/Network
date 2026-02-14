/* Networks.c */
#include "Networks.h"
#include <bits/types/struct_timeval.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdoslib/stdoslib.h>
#include <unistd.h>

i16 global_id;
i16 seq,id;

void init() {
if (getuid()) {fprintf(stdout,"Run with sudo");exit(-10);}
srand(getpid());
global_id = rand() % 50000;
seq = 0;
id = rand() % 50000;
}

/*
int main(int argc,char * argv[]) { 
i16 count = 5,l;
i8* dst,*mssg;
if (argc < 2) {usage_ip(argv[0]);return -1;}
else if (argc == 2) {
if (strcomp(argv[1],"-h")==0 || strcomp(argv[1],"-help")==0 ){usage_ip(argv[0]);return -1;}
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
else {usage_ip(argv[0]);return -1;}
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
if (argc < 6) {
    usage_ether((i8 *)argv[0]);
    return -1;
}
// "Usage : %s <SRC_MAC> <DST_MAC> <SRC_IP> <DST_IP> <MSSG> <MSSG_LEN>
Mac * src = mkmac((i8*)argv[1]),* dst = mkmac((i8*)argv[2]);
if (!src || !dst) return -2;
char * ip_src = argv[3],* ip_dst = argv[4];
if (!ip_src || !ip_dst) return -3;
char * mssg = argv[5];
i16 mssg_len = len(mssg);
if (argc > 6) mssg_len = stoi(argv[6]);
if (!mssg_len) return -4;
printf("1");
i32 sock = setup_ether_sock();
printf("2");
if (!sock) return -5;

int id = 0;

Ethernet * ether = init_ether(src,dst,e_IP);
if (!ether) return -6;
Ip * ip = init_ip(Raw, (i8 *)ip_src, (i8 *)ip_dst, id);
id++;
if (!ip) return -7;
ether->payload = ip;
ip->payload.raw_pkt = (i8* )mssg;
i8 ret = _sendether(sock, ether);
printf("Ok = %d\n",ret);

seq++;


close(sock);
FREE(ip,src,dst,ether);
return 0;
}






