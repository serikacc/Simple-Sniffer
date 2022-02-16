#include "mythread.h"
#include "mainwindow.h"
#include "ui_mainwindow.h"

extern QList<QString> timestamp; //捕获时间
extern QList<QString> sip; //源IP地址
extern QList<QString> dip; //目的IP地址
extern QList<QString> smac; //源mac地址
extern QList<QString> dmac; //目的mac地址
extern QList<QString> lenth; //长度
extern QList<QString> frame; //帧类型
extern QList<QString> protocol; //协议类型
QList<QString> tmp;
extern int dev_num;//当前监控的设备
extern pcap_if_t *alldevs;
int num_packet = 0;//数据包总数
int type_packet=0;//数据包类型
extern QString packet_filter;
struct bpf_program fcode;
extern int endm;

BYTE DesMAC[6];
BYTE SrcMAC[6];
WORD FrameType;
BYTE NetType;
BYTE SrcIP[4];
BYTE DesIP[4];

extern MainWindow w;

mythread::mythread()
{

}

void mythread::run()
{
    pcap_if_t *d;
    int inum;
    int i=0;
    pcap_t *adhandle;
    int res;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct tm *ltime;
    char timestr[16];
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    time_t local_tv_sec;
    u_int netmask;

    /* 获取本机设备列表 */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        qDebug(errbuf);
        exit(1);
    }

    /* 打印列表 */
    for(d=alldevs; d; d=d->next)
    {
        qDebug("%d. %s", ++i, d->name);
        if (d->description)
            qDebug(" (%s)\n", d->description);
        else
            qDebug(" (No description available)\n");
    }

    if(i==0)
    {
        qDebug("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return ;
    }

    inum=dev_num;

    if(inum < 1 || inum > i)
    {
        qDebug("\nInterface number out of range.\n");
        /* 释放设备列表 */
        pcap_freealldevs(alldevs);
        return ;
    }

    /* 跳转到已选中的适配器 */
    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

    /* 打开设备 */
    if ( (adhandle= pcap_open(d->name,          // 设备名
                              65536,            // 要捕捉的数据包的部分
                                                // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
                              PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
                              1000,             // 读取超时时间
                              NULL,             // 远程机器验证
                              errbuf            // 错误缓冲池
                              ) ) == NULL)
    {
        qDebug("\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
        /* 释放设列表 */
        pcap_freealldevs(alldevs);
        return ;
    }

    /* 检查数据链路层，为了简单，我们只考虑以太网 */
    if(pcap_datalink(adhandle) != DLT_EN10MB)
    {
        qDebug("\nThis program works only on Ethernet networks.\n");
        /* 释放设备列表 */
        pcap_freealldevs(alldevs);
        return ;
    }

    if(d->addresses != NULL)
        /* 获得接口第一个地址的掩码 */
        netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        /* 如果接口没有地址，那么我们假设一个C类的掩码 */
        netmask=0xffffff;
/*
    char* str_filter;
    QByteArray ba = packet_filter.toLatin1(); // must
    str_filter=ba.data();
*/
    //编译过滤器
    if (pcap_compile(adhandle, &fcode, packet_filter.toStdString().c_str(), 1, netmask) <0 )
    {
         qDebug("Unable to compile the packet filter. Check the syntax.");
         emit sendData2();
        /* 释放设备列表 */
        pcap_freealldevs(alldevs);
        return ;
    }

    //设置过滤器
    if (pcap_setfilter(adhandle, &fcode)<0)
    {
        qDebug("Error setting the filter.");
        /* 释放设备列表 */
        pcap_freealldevs(alldevs);
        return ;
    }

    qDebug("\nlistening on %s...\n", d->description);

    /* 释放设备列表 */
    pcap_freealldevs(alldevs);

    /* 获取数据包 */
    while((res = pcap_next_ex( adhandle, &header, &pkt_data)) >= 0){

        if(res == 0){
            /* 超时时间到 */
            qDebug(".");
            continue;
        }
        /* 将时间戳转换成可识别的格式 */
        local_tv_sec = header->ts.tv_sec;
        ltime=localtime(&local_tv_sec);
        strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

        qDebug("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);

        memcpy(DesMAC, pkt_data, 6);
        memcpy(SrcMAC, pkt_data+6, 6);
        memcpy(&FrameType, pkt_data+12, 2);
        FrameType = ntohs(FrameType);//网络序转主机序

        char cDesMAC[20];
        char cSrcMAC[20];
        char cDesIP[20];
        char cSrcIP[20];
        sprintf(cDesMAC,"%02x:%02x:%02x:%02x:%02x:%02x",DesMAC[0],DesMAC[1],DesMAC[2],DesMAC[3],DesMAC[4],DesMAC[5]);
        sprintf(cSrcMAC,"%02x:%02x:%02x:%02x:%02x:%02x",SrcMAC[0],SrcMAC[1],SrcMAC[2],SrcMAC[3],SrcMAC[4],SrcMAC[5]);
        //qDebug("MAC : %s -> %s",cSrcMAC, cDesMAC);
        //qDebug("frame : %04x",FrameType);
        timestamp.append(QString(timestr)+"."+QString::number(header->ts.tv_usec));
        lenth.append(QString::number(header->len));
        dmac.append(QString(cDesMAC));
        smac.append(QString(cSrcMAC));
        switch(FrameType)
        {
            case 0x0800:frame.append("IP");break;
            case 0x0806:frame.append("ARP");type_packet=1;break;
            case 0x8035:frame.append("RARP");break;
            default: frame.append("?");
        }
        switch(FrameType)
        {
            case 0x0800:
                memcpy(&SrcIP, pkt_data+14+12, 4);
                memcpy(&DesIP, pkt_data+14+12+4, 4);
                memcpy(&NetType, pkt_data+14+9, 1);
                //NetType = ntohs(NetType);
                sprintf(cDesIP,"%d.%d.%d.%d",DesIP[0],DesIP[1],DesIP[2],DesIP[3]);
                sprintf(cSrcIP,"%d.%d.%d.%d",SrcIP[0],SrcIP[1],SrcIP[2],SrcIP[3]);
                sip.append(QString(cSrcIP));
                dip.append(QString(cDesIP));
                switch(NetType)
                {
                    case 1: protocol.append("ICMP");type_packet=4;break;
                    case 6: protocol.append("TCP");type_packet=2;break;
                    case 17: protocol.append("UDP");type_packet=3;break;
                    default: protocol.append("?");
                }


                break;
            case 0x0806: protocol.append("");sip.append("");dip.append("");break;
            case 0x8035: protocol.append("");sip.append("");dip.append("");break;
            default: protocol.append("");sip.append("");dip.append("");
        }
        emit sendData(type_packet);
        /*将数据包内容存储在文件系统中*/
        FILE * fout = NULL;//向文件系统中保存数据包内容
        char name_packet[10];
        sprintf(name_packet, "%d", num_packet);
        strcat(name_packet,".pkt");
        fout = fopen(name_packet,"wb");
        for(int j=0; j< header->len ; j++)
            fprintf(fout,"%02x ", pkt_data[j]);
        fclose(fout);
        num_packet++;
        type_packet=0;
        if(endm){
            endm = 0;
            return;
        }
    }

    if(res == -1){
        qDebug("Error reading the packets: %s\n", pcap_geterr(adhandle));
        return ;
    }

    return ;
}
