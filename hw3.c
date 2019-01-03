#include <pcap.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include "protoheader.h"

int count,n,total;

void summary(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    static int count = 1;                   /* packet counter */

    /* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;            /* The TCP header */
    const struct sniff_udp *udp;
    const struct sniff_icmp *icmp;
    const struct sniff_arp *arp, *rarp;

    const char *payload;                    /* Packet payload */
    int i;
    int size_ip;
    int size_tcp;
    int size_payload;
    struct timeval tv;
    time_t nowtime;
    struct tm *nowtm;
    char tmbuf[64], buf[64],showbuf[64]="";

    bool tcp_packet = false, udp_packet = false, icmp_packet = false;



    sprintf(showbuf,"%s%d\t",showbuf,count);
//	printf("\nPacket length : %d\n", header->len);

    count++;
    total=count;

    tv = header->ts;
    nowtime = tv.tv_sec;
    nowtm = localtime(&nowtime);
    strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", nowtm);
    snprintf(buf, sizeof buf, "%s.%06ld", tmbuf, tv.tv_usec);
    sprintf(showbuf,"%s%s\t",showbuf,buf);
//	printf("%s\t", buf);

    /* define ethernet header */
    ethernet = (struct sniff_ethernet*)(packet);
    /*
    	printf("Source MAC Address : ");
    	for (i = 0; i < ETHER_ADDR_LEN; i++) {
    		printf("%02x", ethernet->ether_shost[i]);
    		if (i != (ETHER_ADDR_LEN-1))
    			printf(":");
    	}
    	printf("\n");
    	printf("Destination MAC Address : ");
    	for (i = 0; i<ETHER_ADDR_LEN; i++) {
                    printf("%02x", ethernet->ether_dhost[i]);
                    if (i != (ETHER_ADDR_LEN-1))
                            printf(":");
            }
            printf("\n");
    */
    if (ntohs(ethernet->ether_type) == ETHERTYPE_ARP)
    {
        arp = (struct sniff_arp *)(packet + SIZE_ETHERNET);
        if (ntohs(arp->htype) == 1 && ntohs(arp->ptype) == 0x0800)
        {
            for(i=0; i<3; i++)
                sprintf(showbuf,"%s%d.",showbuf,arp->spa[i]);
            sprintf(showbuf,"%s%d\t\t",showbuf,arp->spa[i]);

            for(i=0; i<3; i++)
                sprintf(showbuf,"%s%d.",showbuf,arp->tpa[i]);
            sprintf(showbuf,"%s%d\t\t",showbuf,arp->tpa[i]);
        }
        printf("\e[43m%sARP\t\t%-6d\e[49m\n",showbuf, header->len);
        return ;
    }
    /* define/compute ip header offset */
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20)
    {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    /* print source and destination IP addresses */


    /* determine protocol */
    switch(ip->ip_p)
    {
    case IPPROTO_TCP:
        tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp)*4;
        if (size_tcp < 20)
        {
            printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
            return;
        }
        sprintf(showbuf,"%s%s:%-5d\t",showbuf, inet_ntoa(ip->ip_src), ntohs(tcp->th_sport));
        sprintf(showbuf,"%s%s:%-5d\t",showbuf, inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
        printf("\e[42m%sTCP\t\t%-6d\e[49m\n",showbuf,header->len);
        break;

    case IPPROTO_UDP:
        udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
        sprintf(showbuf,"%s%s:%-5d\t",showbuf, inet_ntoa(ip->ip_src), ntohs(udp->uh_sport));
        sprintf(showbuf,"%s%s:%-5d\t",showbuf, inet_ntoa(ip->ip_dst), ntohs(udp->uh_dport));
        printf("\e[44m%sUDP\t\t%-6d\e[49m\n",showbuf,header->len);
        break;

    case IPPROTO_ICMP:

        icmp = (struct sniff_icmp*)(packet + SIZE_ETHERNET + size_ip);
        sprintf(showbuf,"%s%s\t\t",showbuf, inet_ntoa(ip->ip_src));
        sprintf(showbuf,"%s%s\t\t",showbuf, inet_ntoa(ip->ip_dst));
        printf("\e[101m%sICMP\t\t%-6d\e[49m\n",showbuf,header->len);
        break;
    case IPPROTO_IP:
        printf("   Protocol: IP\n");
        return;
    default:
        printf("   Protocol: unknown\n");
        return;
    }


//	printf("tcp_packet : %d, udp_packet : %d, icmp_packet : %d\n", tcp_packet, udp_packet, icmp_packet);
    /* define/compute tcp header offset */
    if (tcp_packet)
    {
        tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp)*4;
        if (size_tcp < 20)
        {
            printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
            return;
        }

        printf("   Src port: %d\n", ntohs(tcp->th_sport));
        printf("   Dst port: %d\n", ntohs(tcp->th_dport));

        /* define/compute tcp payload (segment) offset */
        payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
        /* compute tcp payload (segment) size */
        size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
    }
    else if (udp_packet)
    {
        /* define/compute udp header offset */
        udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);

        printf("   Src port: %d\n", ntohs(udp->uh_sport));
        printf("   Dst port: %d\n", ntohs(udp->uh_dport));

        /* define/compute udp payload (segment) offset */
        payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + SIZE_UDP);

        /* compute udp payload (segment) size */
        size_payload = ntohs(ip->ip_len) - (size_ip + SIZE_UDP);
        if (size_payload > ntohs(udp->uh_ulen))
            size_payload = ntohs(udp->uh_ulen);
    }
    else if (icmp_packet)
    {
        icmp = (struct sniff_icmp*)(packet + SIZE_ETHERNET + size_ip);
        printf("Type : %d", (unsigned int)(icmp->type));
        if ((unsigned int)(icmp->type) == 11)
            printf("   (TTL Expired)\n");
        else if ((unsigned int)(icmp->type) == ICMP_ECHO)
            printf("   (ICMP Echo Request)\n");
        else if ((unsigned int)(icmp->type) == ICMP_ECHOREPLY)
            printf("   (ICMP Echo Reply)\n");
        payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + sizeof(icmp));
        size_payload = ntohs(ip->ip_len) - (size_ip + sizeof(icmp));
    }

}

void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

    int i;
    int gap;
    const u_char *ch;
    /* offset */
//printf("%05d   ", offset);

    /* hex */
    ch = payload;
    for(i = 0; i < len; i++)
    {
        printf("%02x ", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i == 7)
            printf(" ");
    }
    /* print space to handle line less than 8 bytes */
    if (len < 8)
        printf(" ");

    /* fill hex gap with spaces if not full line */
    if (len < 16)
    {
        gap = 16 - len;
        for (i = 0; i < gap; i++)
        {
            printf("   ");
        }
    }
    printf("   ");

    /* ascii (if printable) */
    ch = payload;
    for(i = 0; i < len; i++)
    {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }

    printf("\n");

    return;
}


void print_payload(const u_char *payload, int len)
{

    int len_rem = len;
    int line_width = 16;			/* number of bytes per line */
    int line_len;
    int offset = 0;					/* zero-based offset counter */
    const u_char *ch = payload;


    if (len <= 0)
        return;

    /* data fits on one line */
    if (len <= line_width)
    {
        print_hex_ascii_line(ch, len, offset);
        return;
    }

    /* data spans multiple lines */
    for ( ;; )
    {
        /* compute current line length */
        line_len = line_width % len_rem;
        /* print line */
        print_hex_ascii_line(ch, line_len, offset);
        /* compute total remaining */
        len_rem = len_rem - line_len;
        /* shift pointer to remaining bytes to print */
        ch = ch + line_len;
        /* add offset */
        offset = offset + line_width;
        /* check if we have line width chars or less */
        if (len_rem <= line_width)
        {
            /* print last line and get out */
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }

    return;
}


void packet_detail(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

    if(count!=n)
    {
        count++;
        return;
    }
    //static int count = 1;                   /* packet counter */

    /* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;            /* The TCP header */
    const struct sniff_udp *udp;
    const struct sniff_icmp *icmp;
    const struct sniff_arp *arp, *rarp;
    const char *payload;                    /* Packet payload */
    int i;
    int size_ip;
    int size_tcp;
    int size_payload;
    struct timeval tv;
    time_t nowtime;
    struct tm *nowtm;
    char tmbuf[64], buf[64];
    bool tcp_packet = false, udp_packet = false, icmp_packet = false;

    printf("\nPacket length : %d\n", header->len);
    count++;

    tv = header->ts;
    nowtime = tv.tv_sec;
    nowtm = localtime(&nowtime);
    strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", nowtm);
    snprintf(buf, sizeof buf, "%s.%06ld", tmbuf, tv.tv_usec);
    printf("Time Stamp : %s\n", buf);

    /* define ethernet header */
    ethernet = (struct sniff_ethernet*)(packet);
    printf("Source MAC Address : ");
    for (i = 0; i < ETHER_ADDR_LEN; i++)
    {
        printf("%02x", ethernet->ether_shost[i]);
        if (i != (ETHER_ADDR_LEN-1))
            printf(":");
    }
    printf("\n");
    printf("Destination MAC Address : ");
    for (i = 0; i<ETHER_ADDR_LEN; i++)
    {
        printf("%02x", ethernet->ether_dhost[i]);
        if (i != (ETHER_ADDR_LEN-1))
            printf(":");
    }
    printf("\n");
    if (ntohs(ethernet->ether_type) == ETHERTYPE_IP)
        printf("Ethernet Type : IP\n");
    if (ntohs(ethernet->ether_type) == ETHERTYPE_ARP)
    {
        printf("Ethernet Type : ARP\n");
        arp = (struct sniff_arp *)(packet + SIZE_ETHERNET);
        printf("Hardware type: %s\n", (ntohs(arp->htype) == 1) ? "Ethernet" : "Unknown");
        printf("Protocol type: %s\n", (ntohs(arp->ptype) == 0x0800) ? "IPv4" : "Unknown");
        printf("Operation: %s\n", (ntohs(arp->oper) == ARP_REQUEST)? "ARP Request" : "ARP Reply");

        /* If is Ethernet and IPv4, print packet contents */
        if (ntohs(arp->htype) == 1 && ntohs(arp->ptype) == 0x0800)
        {
            printf("Sender MAC: ");

            for(i=0; i<6; i++)
                printf("%02X:", arp->sha[i]);

            printf("\nSender IP: ");

            for(i=0; i<4; i++)
                printf("%d.", arp->spa[i]);

            printf("\nTarget MAC: ");

            for(i=0; i<6; i++)
                printf("%02X:", arp->tha[i]);

            printf("\nTarget IP: ");

            for(i=0; i<4; i++)
                printf("%d.", arp->tpa[i]);

            printf("\n");
        }

        //return ;
    }
    else if (ntohs(ethernet->ether_type) == ETHERTYPE_REVARP)
    {
        printf("Ethernet Type : REVARP\n");
        arp = (struct sniff_arp *)(packet + SIZE_ETHERNET);
        printf("Hardware type: %s\n", (ntohs(arp->htype) == 1) ? "Ethernet" : "Unknown");
        printf("Protocol type: %s\n", (ntohs(arp->ptype) == 0x0800) ? "IPv4" : "Unknown");

        printf("Operation : ");
        if ((ntohs(arp->oper) == RARP_REQ_REV))
            printf("RARP Request Reverse\n");
        else if ((ntohs(arp->oper) == RARP_REPLY_REV))
            printf("RARP Reply Reverse\n");

        /* If is Ethernet and IPv4, print packet contents */
        if (ntohs(arp->htype) == 1 && ntohs(arp->ptype) == 0x0800)
        {
            printf("Sender MAC: ");

            for(i=0; i<5; i++)
				printf("%02X:", arp->sha[i]);                
			printf("%02X", arp->sha[i]);

            printf("\nSender IP: ");

            for(i=0; i<3; i++)
                printf("%d.", arp->spa[i]);
            printf("%d", arp->spa[i]);

            printf("\nTarget MAC: ");

            for(i=0; i<5; i++)
                printf("%02X:", arp->tha[i]);
            printf("%02X", arp->tha[i]);

            printf("\nTarget IP: ");

            for(i=0; i<3; i++)
                printf("%d.", arp->tpa[i]);
            printf("%d", arp->tpa[i]);

            printf("\n");
        }
        //return ;
    }
    else
    {

        /* define/compute ip header offset */
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;
        if (size_ip < 20)
        {
            printf("   * Invalid IP header length: %u bytes\n", size_ip);
            return;
        }

        /* print source and destination IP addresses */
        printf("       From: %s\n", inet_ntoa(ip->ip_src));
        printf("         To: %s\n", inet_ntoa(ip->ip_dst));

        /* determine protocol */
        switch(ip->ip_p)
        {
        case IPPROTO_TCP:
            tcp_packet = true;
            printf("   Protocol: TCP\n");
            break;
        case IPPROTO_UDP:
            udp_packet = true;
            printf("   Protocol: UDP\n");
            break;
        case IPPROTO_ICMP:
            icmp_packet = true;
            printf("   Protocol: ICMP\n");
            break;
        case IPPROTO_IP:
            printf("   Protocol: IP\n");
            return;
        default:
            printf("   Protocol: unknown\n");
            return;
        }

//	printf("tcp_packet : %d, udp_packet : %d, icmp_packet : %d\n", tcp_packet, udp_packet, icmp_packet);
        /* define/compute tcp header offset */
        if (tcp_packet)
        {
            tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
            size_tcp = TH_OFF(tcp)*4;
            if (size_tcp < 20)
            {
                printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
                return;
            }

            printf("   Src port: %d\n", ntohs(tcp->th_sport));
            printf("   Dst port: %d\n", ntohs(tcp->th_dport));

            /* define/compute tcp payload (segment) offset */
            payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
            /* compute tcp payload (segment) size */
            size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
        }
        else if (udp_packet)
        {
            /* define/compute udp header offset */
            udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);

            printf("   Src port: %d\n", ntohs(udp->uh_sport));
            printf("   Dst port: %d\n", ntohs(udp->uh_dport));

            /* define/compute udp payload (segment) offset */
            payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + SIZE_UDP);

            /* compute udp payload (segment) size */
            size_payload = ntohs(ip->ip_len) - (size_ip + SIZE_UDP);
            if (size_payload > ntohs(udp->uh_ulen))
                size_payload = ntohs(udp->uh_ulen);
        }
        else if (icmp_packet)
        {
            icmp = (struct sniff_icmp*)(packet + SIZE_ETHERNET + size_ip);
            printf("Type : %d\n", (unsigned int)(icmp->type));
            if ((unsigned int)(icmp->type) == 11)
                printf("   (TTL Expired)\n");
            else if ((unsigned int)(icmp->type) == ICMP_ECHO)
                printf("   (ICMP Echo Request)\n");
            else if ((unsigned int)(icmp->type) == ICMP_ECHOREPLY)
                printf("   (ICMP Echo Reply)\n");
            payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + sizeof(icmp));
            size_payload = ntohs(ip->ip_len) - (size_ip + sizeof(icmp));
        }
    }

    size_payload=header->len;	//*****************
    payload=(u_char *)(packet);	//*****************
    if (size_payload > 0)
    {
        //printf("   Payload (%d bytes):\n", size_payload);

        if (args)
        {
            const u_char *ch, *found = NULL;
            char tempbuf[size_payload];
            ch = payload;
            for(i = 0; i < size_payload; i++)
            {
                if (isprint(*ch))
                    tempbuf[i] = *ch;
                else
                    tempbuf[i] = '.';
                ch++;
            }
            found = strstr(tempbuf, (char *)args);
            if (found)
            {
                printf("FOUND\n");
                print_payload(payload, size_payload);
                return ;
            }
            else
            {
                printf("Not Found\n");
                return ;
            }
        }
        print_payload(payload, size_payload);
    }
}

int main(int argc, char** argv)
{
    pcap_t *handle;
    char error[100];

    struct pcap_pkthdr pack;
    const u_char *packet;
    struct pcap_pkthdr header;
    struct bpf_program filter;

    char file[]="./hart_ip.pcap";
    char expr[256];
    int i;

    printf("Please input filter expression:\n");
    gets(expr);

    if((handle=pcap_open_offline(file,error))==NULL)
    {
        printf("%s\n",error);
        return 0;
    }

    if(pcap_compile(handle,&filter,expr,1,0)<0)
    {
        printf("%s\n",pcap_geterr(handle));
        return 0;
    }
    printf("No.\tTime Stamp\t\t\tSrc IP:port\t\tDst IP:port\t\tProtocol\tLength\n");
    printf("--------------------------------------------------------------------------------------------------------------\n");
    if(pcap_setfilter(handle,&filter)==0)
        pcap_loop( handle, -1, summary, NULL);

    while(1)
    {
        count=1;
        printf("Input No.:");
        scanf("%d",&n);
        if(n>=total||n<=0)
        {
            printf("Out of range\n");
        }
        if((handle=pcap_open_offline(file,error))==NULL)
        {
            printf("%s\n",error);
            return 0;
        }
        if(pcap_compile(handle,&filter,expr,1,0)<0)
        {
            printf("%s\n",pcap_geterr(handle));
            return 0;
        }

        if(pcap_setfilter(handle,&filter)==0)
            pcap_loop( handle, -1, packet_detail, NULL);

    }
    /*

    	pcap_compile(handle,&filter,expr,1,0);
    	if(pcap_setfilter(handle,&filter)==0)
            pcap_loop( handle, -1, got_packet, NULL);
    	*/

    return 0;
}
