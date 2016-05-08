#include <pcap.h>
#include<stdint.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <libnet.h>
#include <arpa/inet.h>
#include <netinet/ether.h>


void reply_arp(u_char *args, const struct pcap_pkthdr *header, const u_char *s);
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
arp_hdr a;
u_char macaddress[6];
int main(int args,char *argv[])

{

    sum *s;
    s = (sum*)malloc(sizeof(ethernet_hdr) + sizeof(arp_hdr));
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


    for(int i = 0 ; i< 6 ; i++)
    e.ether_dhost[i] = 0xFF;
     //source mac
    e.ether_shost[1] = 0x0c;
    e.ether_shost[2] = 0x29;
    e.ether_shost[3] = 0xd6;
    e.ether_shost[4] = 0x34;
    e.ether_shost[5] = 0x32;
    e.ether_type = htons(ETHERTYPE_ARP); //claer
    a.ar_hln = 6;//hawdware szie
    a.ar_pln = 4;//protocol size
    a.ar_hrd = htons(ARPHRD_ETHER);
    a.ar_pro = htons(ETHERTYPE_IP);
    a.ar_op = htons(ARPOP_REQUEST);
    a.ar_sendermac[0] = 0x00;
    a.ar_sendermac[1] = 0x0c;
    a.ar_sendermac[2] = 0x29;
    a.ar_sendermac[3] = 0xd6;
    a.ar_sendermac[4] = 0x34;
    a.ar_sendermac[5] = 0x32;
    char my_ip[] = "192.168.7.131";
    in_addr senderip, targetip , targetip2;

    inet_aton(my_ip,&senderip); // device ip
    inet_aton(argv[1],&targetip2); // the other ip
    inet_aton(argv[2],&targetip);
    memcpy(a.ar_sendip, &senderip, sizeof(a.ar_sendip));
    memcpy(a.ar_targetip, &targetip, sizeof(a.ar_targetip));

    for(int i = 0; i<6 ; i++)
    a.ar_targetmac[i] = 0x00;
    s->a = e; //ethernet
    s->b = a; //arp

    const u_char *c = (u_char *)s;

    if(pcap_sendpacket(handle,c,sizeof(*s)) != 0)
        printf("packet send error!!!\n");
    else
    {

        printf("send packet!!\n");
        pcap_loop(handle, -1, reply_arp, NULL);
    }


    /* And close the session */


    pcap_close(handle);

    return(0);


}

void reply_arp(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

    ethernet_hdr *ethernet = (ethernet_hdr *) packet;
    if(ntohs(ethernet->ether_type) == ETHERTYPE_ARP)
    {  arp_hdr *arp_packet = (arp_hdr *)(packet + sizeof(ethernet_hdr));

        if(ntohs(arp_packet->ar_pro) == ETHERTYPE_IP && ntohs(arp_packet->ar_op) ==ARPOP_REPLY)
            if(memcmp(arp_packet->ar_sendip,a.ar_targetip,sizeof(a.ar_sendip))==0)
                memcpy(arp_packet->ar_sendermac,&macaddress,6);


    }


}

