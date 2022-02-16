#ifndef ANALYZE_H
#define ANALYZE_H

#include <windef.h>
#include <winsock2.h>
#include <string.h>

typedef struct FrameHeader_t  {   // 帧首部
    BYTE	DesMAC[6];	        // 目的地址
    BYTE    SrcMAC[6];	        // 源地址
    WORD    FrameType;	        // 帧类型
} FrameHeader_t;
typedef struct IPHeader_t {          // IP首部
    //unsigned int head_Len:4;//注意主机序和网络序的顺序区别
    //unsigned int Ver_HLen:4;
    BYTE    Ver_HLen;
    BYTE	TOS;
    WORD	TotalLen;
    WORD	ID;
    WORD	Flag_Segment;
    BYTE	TTL;
    BYTE	Protocol;
    WORD	Checksum;
    ULONG	SrcIP;
    ULONG	DstIP;
} IPHeader_t;
typedef struct Data_t {	//包含帧首部和IP首部的数据包
    FrameHeader_t	FrameHeader;
    IPHeader_t	IPHeader;
} Data_t;
/* 4字节的IP地址 */
typedef struct ip_address {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPv4 首部 */
typedef struct ip_header {
    u_char  ver_ihl;        // 版本 (4 bits) + 首部长度 (4 bits)
    u_char  tos;            // 服务类型(Type of service)
    u_short tlen;           // 总长(Total length)
    u_short identification; // 标识(Identification)
    u_short flags_fo;       // 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
    u_char  ttl;            // 存活时间(Time to live)
    u_char  proto;          // 协议(Protocol)
    u_short crc;            // 首部校验和(Header checksum)
    ip_address  saddr;      // 源地址(Source address)
    ip_address  daddr;      // 目的地址(Destination address)
    u_int   op_pad;         // 选项与填充(Option + Padding)
}ip_header;

/* TCP 首部*/
typedef struct tcphdr
{
    u_short th_sport;
    u_short th_dport;
    u_long th_seq;
    u_long th_ack;
    u_int th_off:4;
    u_int th_x2:4;
    u_char th_flags;
    u_short th_win;
    u_short th_sum;
    u_short th_urp;
}TCP_HEADER;

/* UDP 首部*/
typedef struct udp_header {
    u_short sport;          // 源端口(Source port)
    u_short dport;          // 目的端口(Destination port)
    u_short len;            // UDP数据包长度(Datagram length)
    u_short crc;            // 校验和(Checksum)
}udp_header;

typedef struct arphdr
{
    u_short ar_hrd;
    u_short ar_pro;
    u_char ar_hln;
    u_char ar_pln;
    u_short ar_op;
    BYTE SrcMAC[6];	        // 源地址
    BYTE SrcIP[4];	        
    BYTE DesMAC[6];	        // 目的地址
    BYTE DesIP[4];
}ARP_HEADER;

//ICMP头部，总长度4字节
typedef struct _icmp_hdr
{
    u_char icmp_type;   //类型
    u_char code;        //代码
    u_short chk_sum;    //16位检验和
    u_short flags;      //16位标志符
    u_short sen;    //16位序列号
}icmp_hdr;
#endif // ANALYZE_H
