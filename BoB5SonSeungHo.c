 #include <pcap/pcap.h>

#include <stdlib.h>

 

typedef struct mac_address {

u_char byte1;

u_char byte2;

u_char byte3;

u_char byte4;

u_char byte5;

u_char byte6;

}mac;

 

 

#define ETHER_ADDR_LEN 6

struct ether_header

{

u_char ether_dhost[ETHER_ADDR_LEN];

u_char ether_shost[ETHER_ADDR_LEN];

u_short ether_type;

}eth;

 

typedef struct ip_address

{

u_char byte1;

u_char byte2;

u_char byte3;

u_char byte4;

}ip_address;

 

typedef struct ip_header

{

u_char ip_leng:4; 

u_char  ip_version:4;

u_char tos; // Type of service 

u_short tlen; // Total length 

u_short identification; // Identification

u_short flags_fo; // Flags (3 bits) + Fragment offset (13 bits)

u_char ttl; // Time to live

u_char proto; // Protocol

u_short crc; // Header checksum

ip_address saddr; // Source address

ip_address daddr; // Destination address

u_int op_pad; // Option + Padding

}ip_header;

 

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

 

main()

{

pcap_if_t *alldevs;

pcap_if_t *d;

int inum;

int i=0;

pcap_t *adhandle;

char errbuf[PCAP_ERRBUF_SIZE];

u_int netmask;

char packet_filter[] = ""; // 사용자가 원하는 프로토콜 필터 정보를 넣을 수 있는 공간

struct bpf_program fcode; // 특정 프로토콜만을 캡쳐하기 위한 정책정보 저장

 


if(pcap_findalldevs(&alldevs, errbuf) == -1)

{

fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);

exit(1);

}

 


for(d=alldevs; d; d=d->next)

{

printf("%d. %s", ++i, d->name);

if (d->description)

printf(" (%s)\n", d->description);

else

printf(" (No description available)\n");

}

 

 

if(i==0)

{


printf("\nNo interfaces found! Make sure LiPcap is installed.\n");

return -1;

}

 


printf("Enter the interface number (1-%d):",i);

scanf("%d", &inum);


if(inum < 1 || inum > i)

{

printf("\nAdapter number out of range.\n");

 

pcap_freealldevs(alldevs);

return -1;

}

for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

 

if((adhandle= pcap_open_live(d->name, 65536, 1,  1000,  errbuf )) == NULL)

{

fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);

pcap_freealldevs(alldevs);

return -1;

}



if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0 )

{

fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");

pcap_freealldevs(alldevs);

return -1;

}


if (pcap_setfilter(adhandle, &fcode)<0)

{

fprintf(stderr,"\nError setting the filter.\n");

pcap_freealldevs(alldevs);

return -1;

}

 


printf("\nlistening on %s...\n", d->description);

 


pcap_freealldevs(alldevs);

 


pcap_loop(adhandle, 0, packet_handler, NULL);

 

return 0;

}


void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)

{


#define IP_HEADER 0x0800

#define ARP_HEADER 0x0806

#define REVERSE_ARP_HEADER 0x0835

 

unsigned int ptype;

 


mac* destmac;

mac* srcmac;

 

destmac = (mac*)pkt_data;

 
eth=(struct   ether_header*)pkt_data;   

ip_header *ih;
ih = (ip_header *)(pkt_data + 14);

printf("*************** Ethernet Frame Header *****************\n");

printf("\n");

printf("\n");

printf("Destination Mac Address : %02x.%02x.%02x.%02x.%02x.%02x \n",

destmac->byte1,

destmac->byte2,

destmac->byte3,

destmac->byte4,

destmac->byte5,

destmac->byte6 );       

printf("\n");


printf("Source Mac Address      : %02x.%02x.%02x.%02x.%02x.%02x \n",

srcmac->byte1,

srcmac->byte2,

srcmac->byte3,

srcmac->byte4,

srcmac->byte5,

srcmac->byte6 );

printf("\n");

 


if(ntohs(eth->ether_type) == IP_HEADER)

{

printf("Upper Protocol is IP HEADER(%04x)\n",ptype);

}

else if (ntohs(eth->ether_type) == ARP_HEADER)

{

printf("Upper Protocol is ARP HEADER(%04x)\n",ptype);

}

else if (ntohs(eth->ether_type) == REVERSE_ARP_HEADER)

{

printf("Upper Protocol is REVERSE ARP HEADER(%04x)\n",ptype);

}

else

{

printf("Upper Protocol is Unknown(%04x)\n",ptype);

}

 

 

printf("\n");

 


if(ntohs(eth->ether_type) == IP_HEADER)

{

 

printf("********************** IP Header ***********************\n");

printf("\n");

printf("\n");

printf("ip versioin is %d\n",ih->ip_version);

printf("\n");

printf("ip lengh is %d\n",(ih->ip_leng)*4);

printf("\n");


printf("Destination IP Address : %d.%d.%d.%d \n",

ih->daddr.byte1,

ih->daddr.byte2,

ih->daddr.byte3,

ih->daddr.byte4 );       

printf("\n");

printf("Source IP Address : %d.%d.%d.%d \n",

ih->saddr.byte1,

ih->saddr.byte2,

ih->saddr.byte3,

ih->saddr.byte4 );

printf("\n");


if(ih->proto == 0x06)

{

printf("Upper Protocol is TCP\n");

printf("\n");

}

else if(ih->proto == 0x11)

{

printf("Upper Protocol is UDP\n");

printf("\n");

}

else if(ih->proto == 0x01)

{

printf("Upper Protocol is ICMP\n");

printf("\n");

}

else 

{

printf("Upper Protocol is Unknown\n");

printf("\n");

}

}

else

{

printf("******************* NO IP Header *********************\n");

printf("\n");

printf("\n");

}

printf("*******************************************************\n");

printf("\n");

printf("\n");

printf("\n");

printf("\n");

printf("\n");

 

}
