#include <pcap.h>
#include<stdint.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <libnet.h>
#include <arpa/inet.h>
#include <netinet/ether.h>



struct sum //packging packet
{
    libnet_ethernet_hdr a;
    libnet_arp_hdr b;
};

int main(int args,char argv[])

{


    sum *s;

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


    libnet_ethernet_hdr ethernet_header;
    libnet_arp_hdr arp;

    ethernet_header.ether_dhost[0] = 0xFF;
    ethernet_header.ether_dhost[1] = 0xFF;//destination mac
    ethernet_header.ether_dhost[2] = 0xFF;
    ethernet_header.ether_dhost[3] = 0xFF;
    ethernet_header.ether_dhost[4] = 0xFF;
    ethernet_header.ether_dhost[5] = 0xFF;
    ethernet_header.ether_shost[0] = 0x00; //source mac
    ethernet_header.ether_shost[1] = 0x0c;
    ethernet_header.ether_shost[2] = 0x29;
    ethernet_header.ether_shost[3] = 0xd6;
    ethernet_header.ether_shost[4] = 0x34;
    ethernet_header.ether_shost[5] = 0x32;
    ethernet_header.ether_type = htons(ETHERTYPE_ARP);
    arp.ar_hln = 6;
    arp.ar_pln = 4;
    arp.ar_hrd = htons(ARPHRD_ETHER);
    arp.ar_pro = htons(0x0800);
    arp.ar_op = htons(ARPOP_REQUEST);
    arp.ar_sendermac[0] = 0x00;
    arp.ar_sendermac[1] = 0x0c;
    arp.ar_sendermac[2] = 0x29;
    arp.ar_sendermac[3] = 0xd6;
    arp.ar_sendermac[4] = 0x34;
    arp.ar_sendermac[5] = 0x32;

    char *sender_ip , *target_ip;

    sender_ip = strtok(&argv[0],".");
    target_ip = strtok(&argv[1],".");
    printf("%d",argv[0]);
    for(int i = 0 ; i < 4 ; i++)
    {
        arp.ar_senderip[i] = htons(sender_ip[i]);
        arp.ar_targetip[i] = htons(target_ip[i]);
    }
    for(int i = 0; i<6 ; i++)
        arp.ar_targetmac[i] = 0x00;





    s = (sum*)malloc(sizeof(ethernet_header) + sizeof(arp));
    s->a = ethernet_header;
    s->b = arp;
    const u_char *a = (u_char*)s;

    if(pcap_sendpacket(handle,a,sizeof(*s)) != 0)
        printf("packet send error!!!\n");
    else
        printf("send packet!!\n");



    /* And close the session */


    pcap_close(handle);

    return(0);

    // ..

}
