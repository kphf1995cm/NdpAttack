#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/in.h>
#include "packet_header.h"

#define MAXBYTE2CAPTURE 2048

int isprint(char c)
{
    return 0;
}

void print_buf(u_char* pBuf, u_int32 len)
{
    if (!pBuf)
    {
        return;
    }

    for(int i=0; i<len; i++)
    {
        printf("%02x ",  (u_char*)pBuf[i]);

        if ((i%16 == 0 && i!=0) || i == len-1)
        {
            printf("\r\n");
        }
    }
}

void parse_ethII(u_char* pData, u_int32 len)
{
    if (!pData || len <14)
    {
        return;
    }
    
    //printf("eth II frame: \r\n");
    //print_buf(pData, 14);

    //parse src mac and dst mac 
    /*EthHeader_t* pEth = (EthHeader_t*)pData;
    printf("destination: %02x:%02x:%02x:%02x:%02x:%02x ",
        pEth->dest_hwaddr[0],
        pEth->dest_hwaddr[1],
        pEth->dest_hwaddr[2],
        pEth->dest_hwaddr[3],
        pEth->dest_hwaddr[4],
        pEth->dest_hwaddr[5]);

    printf("source : %02x:%02x:%02x:%02x:%02x:%02x",
        pEth->source_hwaddr[0],
        pEth->source_hwaddr[1],
        pEth->source_hwaddr[2],
        pEth->source_hwaddr[3],
        pEth->source_hwaddr[4],
        pEth->source_hwaddr[5]);

    // parse frame type 
    printf("\r\nframe type: 0x%x\r\n", ntohs(pEth->frame_type));*/
    
}

void parse_ipheader(u_char* pData, u_int32 len)
{
    if (!pData || len <14)
    {
        return;
    }

    printf("ip header: \r\n");
    print_buf(pData, 20);

    /* parse ip header */
    IPHeader_t* pIpHeader = (IPHeader_t*)pData;
    printf("\tversion     : %02x\r\n"
           "\ttos         : %02x\r\n"
           "\ttotal length: %d(0x%02x)\r\n"
           "\tid          : %d(0x%02x)\r\n"
           "\tsegment flag: %d(0x%02x)\r\n"
           "\tttl         : %02x\r\n"
           "\tprotocol    : %02x\r\n"
           "\tchecksum    : %d(0x%02x)\r\n"
           "\tsrc ip      : %d.%d.%d.%d\r\n"
           "\tdst ip      : %d.%d.%d.%d\r\n",
        pIpHeader->Ver_HLen,
        pIpHeader->TOS,
        ntohs(pIpHeader->TotalLen), ntohs(pIpHeader->TotalLen),
        ntohs(pIpHeader->ID), ntohs(pIpHeader->ID),
        ntohs(pIpHeader->Flag_Segment), ntohs(pIpHeader->Flag_Segment),
        pIpHeader->TTL,
        pIpHeader->Protocol,
        ntohs(pIpHeader->Checksum), ntohs(pIpHeader->Checksum),
        pIpHeader->SrcIP[0],pIpHeader->SrcIP[1],pIpHeader->SrcIP[2],pIpHeader->SrcIP[3],
        pIpHeader->DstIP[0],pIpHeader->DstIP[1],pIpHeader->DstIP[2],pIpHeader->DstIP[3]);
}

u_int16 calculate_checksum(u_char* pData,IPv6Header_t* pIpv6Header,u_int16 icmpv6Bytes)
{
    u_int32 checksum=0;
    u_int16 icmpv6Len=icmpv6Bytes; //NA bytes is 24, NS bytes is 32
    u_int8* icmpv6Header=(u_int8*)pData;

    // ICMPv6 Header
    for(int i=0;i<icmpv6Len;i+=2){
        checksum += ((u_int16)icmpv6Header[i]<<8 & 0xff00) | ((u_int16)icmpv6Header[i+1] & 0x00ff);
    }

    // IPv6 Pseudo Header
    u_int8* ipv6Src = (u_int8*)pIpv6Header->ip6_src.addr8;
    u_int8* ipv6Dst = (u_int8*)pIpv6Header->ip6_dst.addr8;
    
    for(int i=0;i<16;i+=2){
        checksum += ((u_int16)ipv6Src[i]<<8 & 0xff00) | ((u_int16)ipv6Src[i+1] & 0x00ff);
    }

    for(int i=0;i<16;i+=2){
        checksum += ((u_int16)ipv6Dst[i]<<8 & 0xff00) | ((u_int16)ipv6Dst[i+1] & 0x00ff);
    }

    u_int8* ipv6PLen = (u_int8*)(&(pIpv6Header->ip6_plen));
    checksum += ((u_int16)ipv6PLen[0]<<8 & 0xff00) | ((u_int16)ipv6PLen[1] & 0x00ff);

    // for try
    checksum += (u_int16)(pIpv6Header->ip6_nxt) & 0x00ff;
    //checksum += (u_int16)(pIpv6Header->ip6_nxt<<8) & 0xffff;

    /*while(checksum>>16){
        checksum = (checksum & 0x0000ffff) + (checksum >> 16);
    }*/

    //checksum = (checksum & 0xffff) + (checksum >> 16);

    //checksum += checksum >> 16;

    //checksum = ~checksum;

    // checksum endian transform

    checksum = ((checksum >> 8) & 0xff) | (checksum << 8);

    printf("calculate checksum:%x\n",(u_int16)(checksum));
    return (u_int16)checksum;
}


/*typedef struct IPv6PseudoHeader_t{ // 16+16+4+2+1+1=40
    ipv6_addr ip6_src;
    ipv6_addr ip6_dst;
    u_int32 ip6_pkt_len;
    u_int16 zero16;
    u_int8 zero8;
    u_int8 ip6_nxt_header;
} IPv6PseudoHeader;*/

u_int16 calculate_checksum_with_option(u_char* pData,IPv6Header_t* pIpv6Header,u_int16 icmpv6Bytes)
{
    u_int32 checksum=0;
    u_int16 icmpv6Len=icmpv6Bytes/2; //NA bytes is 24, NS bytes is 32
    u_int16* icmpv6Header=(u_int16*)pData;

    printf("icmpv6 length:%d\n",icmpv6Bytes);

    // ICMPv6 Header
    for(int i=0;i<icmpv6Len;i++){
        checksum += icmpv6Header[i];
    }

    printf("checksum:%x\n",checksum);

    // IPv6 Pseudo Header
    /*IPv6PseudoHeader ipv6PseudoHeader;
    ipv6PseudoHeader.ip6_src = pIpv6Header->ip6_src;
    ipv6PseudoHeader.ip6_dst = pIpv6Header->ip6_dst;
    ipv6PseudoHeader.ip6_pkt_len = pIpv6Header->ip6_plen;
    ipv6PseudoHeader.ip6_nxt_header = pIpv6Header->ip6_nxt;
    ipv6PseudoHeader.zero16 = 0;
    ipv6PseudoHeader.zero8 = 0;
    printf("pseudo header size:%d\n",sizeof(ipv6PseudoHeader));
    u_int16 pseudoHeader[20];
    memset(pseudoHeader,&ipv6PseudoHeader,40);

    for(int i=0;i<20;i++){
        checksum += pseudoHeader[i];
    }*/

    
    u_int16* ipv6Src = (u_int16*)pIpv6Header->ip6_src.addr8;
    u_int16* ipv6Dst = (u_int16*)pIpv6Header->ip6_dst.addr8;
    
    for(int i=0;i<8;i++){
        checksum += ipv6Src[i];
    }

    for(int i=0;i<8;i++){
        checksum += ipv6Dst[i];
    }

    checksum += pIpv6Header->ip6_plen;

    checksum += (u_int16)(pIpv6Header->ip6_nxt); // single bytes problem

    

    printf("checksum:%x\n",checksum);

    while (checksum>>16){
        checksum = (checksum & 0xffff) + (checksum >> 16);
    }
    //checksum += checksum >> 16;
    printf("checksum:%x\n",checksum);

    checksum = ~checksum;

    // checksum endian transform
    printf("checksum:%x\n",checksum);

    checksum = ((checksum >> 8) & 0xff) | (checksum << 8);

    printf("calculate checksum:%x\n",(u_int16)(checksum));

    return (u_int16)checksum;
}

void set_ipv6_addr(ipv6_addr* ipv6,u_int8 destination[16])
{
    for(int i=0;i<16;i++){
        (*ipv6).addr8[i]=destination[i];
    }
}

void set_mac_addr(ipv6_addr* mac,u_int8 destination[6]){
    for(int i=0;i<6;i++){
        (*mac).addr8[i]=destination[i];
    }
}

void parse_icmpv6header(u_char* pData,u_int32 len)
{
    if(!pData||len<14)
    {
        return;
    }
    //printf("icmpv6 header: \r\n");
    //print_buf(pData,len);

    u_int16 length = len;

    /*parse icmpv6 header*/
    ICMPv6Header_t* pICMPv6Header = (ICMPv6Header_t*)pData;
    if (pICMPv6Header->type==135) //Neighbor Solicitation
    {
        u_char* pIpv6Start = (u_char*)pData-40;
        IPv6Header_t* pIpv6Header = (IPv6Header_t*)pIpv6Start;
        printf("ICMPv6 NS packet:\n");
        u_int16 tempCheckSum = pICMPv6Header->checksum;
        pICMPv6Header->checksum = 0;
        calculate_checksum_with_option(pData,pIpv6Header,32);// add ipv6 header
        printf(
            "\ttype :%d\r\n"
            "\tcode :%x\r\n"
            "\tchecksum :%x\r\n"
            "\treserved :%x\r\n",
            //"\ttarget address :%x\r\n",
            pICMPv6Header->type,
            pICMPv6Header->code,
            tempCheckSum,
            pICMPv6Header->reserved
            //pICMPv6Header->target_address
        );
        printf("\ttarget_address :");
        print_ipv6_address(pICMPv6Header->target_address);
        u_char* pEtherStart = (u_char*)pData - 54;
        len=len+54;

        // forge source mac (checksum has no way to mac addr)
        EthHeader_t* pEth = (EthHeader_t*)pEtherStart;
        u_int8 mac[6]={0x8c,0xec,0x4b,0x73,0x25,0x8d};
        set_mac_addr(&(pEth->source_hwaddr),mac);

        
        // forge src and dst ipv6,for NA packet (checksum has way to ipv6 addr)
        u_int8 src[16]={0xfe,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x43,0x7f,0x21,0x37,0x3e,0x16,0xb6,0xea};
        u_int8 dst[16]={0xff,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
        set_ipv6_addr(&(pIpv6Header->ip6_src),src);
        set_ipv6_addr(&(pIpv6Header->ip6_dst),dst);
        

        // Make some change
        pICMPv6Header->type=136; // NA
        //pICMPv6Header->code=0;
        //pICMPv6Header->reserved=1234;
        pICMPv6Header->checksum = calculate_checksum_with_option(pData,pIpv6Header,24);
        u_char* pForgePkt = (char*)malloc(len+1);
        memcpy(pForgePkt,pEtherStart,len);
        forge_packet((u_char*)pForgePkt,len);
    }
}

void print_ipv6_address(ipv6_addr ipv6){
    for(int i=0;i<16;i++){
        uint8_t value=ipv6.addr8[i];
        printf("%x",value/16);
        printf("%x",value%16);
    }
    printf("\r\n");
}

void parse_ip6header(u_char* pData, u_int32 len)
{
    if (!pData || len <14)
    {
        return;
    }
    //uint8_t	__u6_addr8[16];

    //printf("ipv6 header: \r\n");
    //print_buf(pData, 40);

    /* parse ipv6 header */
    IPv6Header_t* pIpv6Header = (IPv6Header_t*)pData;
    if(pIpv6Header->ip6_ctlun.ip6_unl.ip6_unl_nxt==58){ // ICMPv6
        printf("IPv6 packet:\n");
        printf("\tversion           : %x\r\n"
           "\ttraffic class     : %x\r\n"
           "\tflow label        : %x\r\n"
           "\tpayload length    : %d\r\n"
           "\tnext header       : %d\r\n"
           "\thop limit         : %d\r\n",
           //"\tsource            : %x\r\n"
           //"\tdestination       : %x\r\n",
           pIpv6Header->ip6_ctlun.ip6_un2_vfc,
           pIpv6Header->ip6_ctlun.ip6_unl.ip6_unl_flow,
           pIpv6Header->ip6_ctlun.ip6_unl.ip6_unl_flow,
           pIpv6Header->ip6_ctlun.ip6_unl.ip6_unl_plen,
           pIpv6Header->ip6_ctlun.ip6_unl.ip6_unl_nxt,
           pIpv6Header->ip6_ctlun.ip6_unl.ip6_unl_hlim);
           //pIpv6Header->ip6_src,
           //pIpv6Header->ip6_dst);
        printf("\tsource        :");
        print_ipv6_address(pIpv6Header->ip6_src);
        printf("\tdestination   :");
        print_ipv6_address(pIpv6Header->ip6_dst);
        u_char* pMbuf = (u_char*)pData;
        pMbuf = (u_char*)pData + 40;
        parse_icmpv6header(pMbuf,len-40);
        //u_char* pDst = (char*)malloc(len+1);
        //memcpy(pDst,pSrc,len);
        //forge_packet((u_char*)pDst - 54,len+54);
    }
}

void parse_packet(const u_char* packet, u_int32 len)
{
    u_short ftype = 0;

    if (!packet)
    {
        return ;
    }

    u_char* pMbuf = (u_char*)packet;
    parse_ethII(pMbuf, len);

    ftype = ntohs(((EthHeader_t*)pMbuf)->frame_type);
    switch(ftype)
    {
        case 0x0800:  /* ipv4 */
            pMbuf = (u_char*)packet + 14;
            //parse_ipheader(pMbuf, len-14);
            break;
        case 0x86dd: /* ipv6 */
            pMbuf = (u_char*)packet + 14;
            parse_ip6header(pMbuf, len-14);
            break;
        default:
            //printf("frame type : 0x%x\r\n", ftype);
            break;
    }
    //printf("\r\n");
}

void forge_packet(const u_char* packet,size_t size){
    pcap_t *descr = NULL;
    char *device = "enp0s31f6";
    char errbuf[PCAP_ERRBUF_SIZE];
     /* Open device in promiscuous mode */
    descr = pcap_open_live(device, MAXBYTE2CAPTURE, 1, 512, errbuf);
    int bytes_written = pcap_inject(descr,packet,size);
}


void processPacket(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    int i = 0, *counter = (int *)arg;

    //printf("--------------------------------------------\r\n");
    //printf("Packet Count: %d\n", ++(*counter));
    //printf("Received Packet Size: %d\n", pkthdr->len);
    //printf("Payload:\n");
/*
#if 1
    for (i = 0; i < pkthdr->len; i++)
    {
        if (isprint(packet[i]))
        {
            printf("%02d ", packet[i]);
        }
        else
        {
            printf("%02x ", packet[i]);
        }

        if ((i % 16 == 0 && i != 0) || i == pkthdr->len-1)
        {
            printf("\n");
        }

    }
#endif
*/
    parse_packet(packet, pkthdr->len);

    // Send NA packet

    return;
}

int main()
{
    int i = 0, count = 0;
    pcap_t *descr = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);
    char *device = "enp0s31f6";

    /* Get the name of the first device suitable for capture */
    /*device = pcap_lookupdev(errbuf);
    if (!device)
    {
        printf("Open device failed.");
        return -1;
    }

    printf("Opening device %s\n", device);*/

    /* Open device in promiscuous mode */
    descr = pcap_open_live(device, MAXBYTE2CAPTURE, 1, 512, errbuf);

    /* Loop forever & call processPacket() for every received packet */
    pcap_loop(descr, -1, processPacket, (u_char *)&count);

    return 0;
}