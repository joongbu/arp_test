#include <pcap.h>
#include<stdint.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <libnet.h>
#include <arpa/inet.h>
#include <netinet/ether.h>


int main()

{



    pcap_t *handle;            /* Session handle */
    char *dev;            /* The device to sniff on */

    char errbuf[PCAP_ERRBUF_SIZE];
    u_char arp_packet[100];


        /* Error string */
     dev  =  pcap_lookupdev(errbuf);

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





    // packet create
    for(int i = 0 ; i <= 5; i++)
    arp_packet[i]= 0xFF;
    //source mac
    arp_packet[6]= 0x00;
    arp_packet[7]= 0x50;
    arp_packet[8]= 0x56;
    arp_packet[9]= 0xe2;
    arp_packet[10]= 0x9F;
    arp_packet[11]= 0x40;
    //type;
    arp_packet[12]=0x08;
    arp_packet[13]=0x06;
    //ARP TYPE
    arp_packet[14]=0x00;
    arp_packet[15]=0x01;
    arp_packet[16]=0x08;
    arp_packet[17]=0x00;
    arp_packet[18]=0x06;
    arp_packet[19]=0x04;
    arp_packet[20]=0x00;
    arp_packet[21]=0x02;
    //sendermac
    arp_packet[22]=0x00;
    arp_packet[23]=0x50;
    arp_packet[24]=0x56;
    arp_packet[25]=0xE2;
    arp_packet[26]=0x9F;
    arp_packet[27]=0x40;
    //senderIP
    arp_packet[28]=0xc0;
    arp_packet[29]=0xa8;
    arp_packet[30]=0x11;
    arp_packet[31]=0x02;
    //taget mac
    for(int i = 32 ; i<=37; i++)
    arp_packet[i]=0x00;
    //taget ip
    arp_packet[38] = 0x0c;
    arp_packet[39] = 0xa8;
    arp_packet[40] = 0x11;
    arp_packet[41] = 0x83;
    if (pcap_sendpacket(handle,arp_packet,42) != 0)//sendpacket
    {
        fprintf(stderr, "couldn't send the packet : \n",pcap_geterr(handle));

    }


   // pcap_loop(handle, -1, got_packet, NULL);
    if (pcap_sendpacket(handle,arp_packet,42) != 0)//sendpacket
    {
        fprintf(stderr, "couldn't send the packet : \n",pcap_geterr(handle));

    }

    /* And close the session */

    pcap_close(handle);

    return(0);

}
/*
u_char *send_arp(u_char *args, const struct pcap_pkthdr *header,const u_char *packet) {
    libnet_ethernet_hdr *ethernet = (libnet_ethernet_hdr *) packet;

    libnet_arp_hdr *arp = (libnet_arp_hdr *) packet;


    for(int i = 0 ; i < 6 ; i++)
    ethernet->ether_dhost[i]= 0xFF;
    ethernet->ether_shost[0] = 0x00;
    ethernet->ether_shost[1] = 0x0C;
    ethernet->ether_shost[2] = 0x29;
    ethernet->ether_shost[3] = 0xD6;
    ethernet->ether_shost[4] = 0x34;
    ethernet->ether_shost[5] = 0x31;

    arp->ar_pro = ETHERTYPE_IP;
    arp->ar_op = htons(1);
    arp->ar_hrd = htons(1);
    arp->ar_pln = 4;
    arp->ar_hln = 6;
    //arp->ar_sender = ether_aton((ether_addr *)(ethernet->ether_shost));
    //arp->ar_sender_ip = inet_ntoa(ip_header->ip_src);
    //arp->ar_target = {0x00,0x00,0x00,0x00,0x00,0x00};
    //arp->ar_target_ip =;
}
*/
