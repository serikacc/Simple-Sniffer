#ifndef ATTACK_H
#define ATTACK_H

#include "pcap.h"
#include <iostream>
#include <winsock2.h>
#include <QDebug>
#include <QList>
#include <QString>
#include <QByteArray>
#include <QCoreApplication>
#include <QWidget>
#include <QThread>

#define PADDING_LEN			18		// ARP 数据包的有效载荷长度

//以太网 14字节
typedef struct enthernet{
    u_char d_mac[6];
    u_char s_mac[6];
    qint16 type;
}enthernet;

//arp
typedef struct arphdr0
{
    u_short ar_hrd;
    u_short ar_pro;
    u_char ar_hln;
    u_char ar_pln;
    u_short ar_op;
}arp_header0;

/*ARP与生成的报头*/
typedef struct ether_arp
{
    arp_header0 ea_hdr;
    u_char arp_sha[6];
    u_char arp_spa[4];
    u_char arp_tha[6];
    u_char arp_tpa[4];
}eth_arp;

typedef struct arp_packet {
    enthernet eh;				// 以太网首部
    ether_arp ah;					// ARP 首部
    u_char padding[PADDING_LEN];
} arp_packet;

namespace Ui {
class Attack;
}

class Attack : public QWidget
{
    Q_OBJECT

public:
    explicit Attack(QWidget *parent = 0);
    char * get_mac_ip(int a);
    ~Attack();

private slots:
    void on_pushButton_clicked();

private:
    Ui::Attack *ui;
    void get_mac(QString mac,unsigned char *MAC);
};

class cheating:public QThread
{
      Q_OBJECT
public:
    void bf_run(char *sip,char *smac,char *dip,char *dmac);

protected:
    void run();
   
private:
   arp_packet * arpreply1=new arp_packet();     //受害主机
   arp_packet * arpreply=new arp_packet();     //网关
};

#endif // ATTACK_H
