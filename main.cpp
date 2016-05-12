#include <pcap.h>
#include<stdint.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <libnet.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <pthread.h>
int send_arp(pcap_t *h,const u_char *arp_packet, u_char *sum1);
void reply_arp(u_char *args, const struct pcap_pkthdr *header, const u_char *s);
static void *readingpacket(pcap_t *h);
void gateway_sendpacket(pcap_t h);
void host_sendpacket(pcap_t h);
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
ethernet_hdr e;
arp_hdr a,b1;
//my ethernet
uint8_t myethernet[6] = {0x0c,0x29,0xd6,0x34,0x32}; //ethernetmac address
uint8_t broadcastmac[6] = {0xff,0xff,0xff,0xff,0xff};
char my_ip[] = "192.168.17.133";
//know mac ip
u_char gateway_ip[4],host_ip[4];
u_char *gatewaymac, *hostmac;
u_char macaddress[6];
pthread_t tid;
 in_addr senderip, targetip , target_hostip; // targetip = gateway, targetip2 = hostip

 void *thread(void *unused);

int main(int args,char *argv[])

{





    sum *s,*s1;
    pcap_t *handle;            /* Session handle */

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
//ethernet_broadcast impormation
    memcpy(e.ether_shost,&myethernet,6);
    memcpy(e.ether_dhost,&broadcastmac,6);
    e.ether_type = htons(ETHERTYPE_ARP); //claer
    a.ar_hln = 6;//hawdware szie
    a.ar_pln = 4;//protocol size
    a.ar_hrd = htons(ARPHRD_ETHER);
    a.ar_pro = htons(ETHERTYPE_IP);
    a.ar_op = htons(ARPOP_REQUEST);

    memcpy(a.ar_sendermac,&myethernet,6);
    inet_aton(my_ip,&senderip); // device ip
    inet_aton(argv[2],&targetip);//gateway ip

    memcpy(a.ar_sendip, &senderip, sizeof(a.ar_sendip));
    memcpy(a.ar_targetip, &targetip, sizeof(a.ar_targetip));
    for(int i = 0; i<6 ; i++)
    a.ar_targetmac[i] = 0x00;


    s = (sum*)malloc(sizeof(ethernet_hdr) + sizeof(arp_hdr));
    s->a = e; //ethernet
    s->b = a; //arp
     const u_char *c = (u_char *)s;
    printf("gatewaypacket\nsource ip : %s\n",inet_ntoa(senderip));
    printf("destinaion ip ; %s\n",inet_ntoa(targetip));

    b1.ar_hln = 6;//hawdware szie
    b1.ar_pln = 4;//protocol size
    b1.ar_hrd = htons(ARPHRD_ETHER);
    b1.ar_pro = htons(ETHERTYPE_IP);
    b1.ar_op = htons(ARPOP_REQUEST);

    inet_aton(argv[1],&target_hostip); // the other ip
    memcpy(b1.ar_sendip, &senderip, sizeof(a.ar_sendip));
    memcpy(b1.ar_targetip, &target_hostip,sizeof(a.ar_targetip));
    s1 = (sum*)malloc(sizeof(ethernet_hdr) + sizeof(arp_hdr));
    s1->a =e;
    s1->b =b1;
    const u_char *c1 = (u_char *)s1;

    printf("hostpakcet\nsource ip : %s\n",inet_ntoa(senderip));
    printf("destinaion ip ; %s\n",inet_ntoa(targetip));
    if(pcap_sendpacket(handle,c,sizeof(*s)) == 0 && pcap_sendpacket(handle,c1,sizeof(*s1) == 0)) //block : host_pc is not reply
    {
        printf("packetsend!!\n ");
        pcap_loop(handle, -1, reply_arp, NULL);//thread

    }
    while(1)
    {


        pthread_create(&tid,NULL,&thread,NULL);
        printf("thread start :");
        sleep(2);
    }






    /* And close the session */

    pcap_close(handle);

    return(0);


}


void reply_arp(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    u_char h_ip[4], g_ip[4];
    memcpy(g_ip, &targetip, sizeof(a.ar_targetip));
    memcpy(h_ip, &target_hostip,sizeof(a.ar_targetip));
    ethernet_hdr *ethernet = (ethernet_hdr *) packet;
    printf("send mac : %s\n",ether_ntoa((ether_addr *)(ethernet->ether_shost)));
    printf("destination mac : %s\n",ether_ntoa((ether_addr *)(ethernet->ether_dhost)));
    if(ntohs(ethernet->ether_type) == ETHERTYPE_ARP)
    {
        arp_hdr *arp_packet = (arp_hdr *)(packet + sizeof(ethernet_hdr));
        printf("sendermac = %s\n",ether_ntoa((ether_addr*)(arp_packet->ar_sendermac)));

        if(ntohs(arp_packet->ar_pro) == ETHERTYPE_IP && ntohs(arp_packet->ar_op) == ARPOP_REPLY)
           {
                if(memcmp(arp_packet->ar_sendip,g_ip,sizeof(a.ar_sendip))==0)
                {
                    memcpy(macaddress,ethernet->ether_shost,6);
                    printf("gateway mac : %s\n",ether_ntoa((ether_addr *)(ethernet->ether_shost)));
                    gatewaymac = macaddress;

                }
                else if(memcmp(arp_packet->ar_sendip,h_ip,sizeof(a.ar_sendip))==0)
                {
                    memcpy(macaddress,ethernet->ether_shost,6);
                    printf("host mac : %s\n",ether_ntoa((ether_addr *)(ethernet->ether_shost)));
                    hostmac = macaddress;
                 }

          }

      }
}

// tring arp relay
void gateway_sendpacket(pcap_t *h)
{
    sum *g;
    g = (sum *) malloc(sizeof(ethernet_hdr) + sizeof(arphdr));
    u_char *c;
    ethernet_hdr gateway_ethernet;
    arp_hdr gateway_arp;
    memcpy(e.ether_shost,gateway_ethernet.ether_shost,6);
    memcpy(gatewaymac,gateway_ethernet.ether_dhost,6);
    gateway_ethernet.ether_type = htons(ETHERTYPE_ARP);
    gateway_arp.ar_hln = 6;
    gateway_arp.ar_pln = 4;
    gateway_arp.ar_hrd = htons(ARPHRD_ETHER);
    gateway_arp.ar_pro = htons(ETHERTYPE_IP);
    gateway_arp.ar_op = htons(ARPOP_REQUEST);
    memcpy(myethernet,gateway_arp.ar_sendermac,6);
    memcpy(host_ip,gateway_arp.ar_sendip,4);
    memcpy(gateway_ip,gateway_arp.ar_targetip,4);
    memcpy(gatewaymac,gateway_arp.ar_targetmac,6);
    g->a = gateway_ethernet;
    g->b = gateway_arp;
    c = (u_char *) g;
    pcap_sendpacket(h,c,sizeof(*g) == 0);
//after send

}

void host_sendpacket(pcap_t *h)
{
    sum *g;
    g = (sum *) malloc(sizeof(ethernet_hdr) + sizeof(arphdr));
    u_char *c;
    ethernet_hdr host_ethernet;
    arp_hdr host_arp;
    memcpy(e.ether_shost,host_ethernet.ether_shost,6);
    memcpy(hostmac,host_ethernet.ether_dhost,6);
    host_ethernet.ether_type = htons(ETHERTYPE_ARP);
    host_arp.ar_hln = 6;
    host_arp.ar_pln = 4;
    host_arp.ar_hrd = htons(ARPHRD_ETHER);
    host_arp.ar_pro = htons(ETHERTYPE_IP);
    host_arp.ar_op = htons(ARPOP_REQUEST);
    memcpy(myethernet,host_arp.ar_sendermac,6);
    memcpy(gateway_ip,host_arp.ar_sendip,4);
    memcpy(host_ip,host_arp.ar_targetip,4);
    memcpy(hostmac,host_arp.ar_targetmac,6);

 //after send
    g->a = host_ethernet;
    g->b = host_arp;
    c = (u_char *) g;
    pcap_sendpacket(h,c,sizeof(*g) == 0);
}


void *thread(void *unused)
{
    while(1)
    {
    void gateway_sendpacket();
    void host_sendpacket();
    }
}
