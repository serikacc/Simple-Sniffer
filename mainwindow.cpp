#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "select.h"
#include "ui_select.h"
#include "filter.h"
#include "ui_filter.h"
#include "attack.h"
#include "ui_attack.h"
#include "mythread.h"
#include "analyze.h"
#include "pcap.h"
#include <time.h>
#include<stdio.h>

extern mythread *dlg;
extern int dev_num;
extern int num_packet;
pcap_if_t *alldevs;
int num=0;
int endm = 0;


QList<QString> timestamp; //捕获时间
QList<QString> sip; //源IP地址
QList<QString> dip; //目的IP地址
QList<QString> smac; //源mac地址
QList<QString> dmac; //目的mac地址
QList<QString> lenth; //长度
QList<QString> frame; //帧类型
QList<QString> protocol; //协议类型

int num_ARP=0;
int num_TCP=0;
int num_UDP=0;
int num_ICMP=0;
int num_TOTAL=0;

bool isASCII(char c);

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    dlg = new mythread;
    ui->tableWidget->setRowCount(0);
    ui->tableWidget->setColumnCount(9);
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);//设置每次点击选中一行
    ui->tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);//设置每行不可编辑
    ui->action_3->setEnabled(false);//设置“终止监听”按钮不可用
    ui->treeWidget->setHeaderLabel("数据包内容分析");
    ui->lineEdit->setEnabled(false);
    ui->lineEdit_2->setEnabled(false);
    ui->lineEdit_3->setEnabled(false);
    ui->lineEdit_4->setEnabled(false);
    ui->lineEdit_5->setEnabled(false);
    ui->lineEdit->setText(QString::number(num_ARP));
    ui->lineEdit_2->setText(QString::number(num_TCP));
    ui->lineEdit_3->setText(QString::number(num_UDP));
    ui->lineEdit_4->setText(QString::number(num_ICMP));
    ui->lineEdit_5->setText(QString::number(num_TOTAL));
    QStringList headers;
    headers<<"捕获时间"<<"源IP地址"<<"目的IP地址"<<"源MAC地址"<<"目的MAC地址"<<"长度"<<"帧类型"<<"协议类型"<<"其他";
    ui->tableWidget->setHorizontalHeaderLabels(headers);
    ui->tableWidget->horizontalHeader()->setStretchLastSection(true); //列填充
    connect(dlg,SIGNAL(sendData(int )),this,SLOT(receiveData(int )));
    connect(dlg,SIGNAL(sendData2()),this,SLOT(receiveData2()));
}

MainWindow::~MainWindow()
{
    delete ui; 
}

void MainWindow::on_action_6_triggered()
{
    if(dev_num==0)
        QMessageBox::warning(NULL,"warning","请先选择网卡！\n",QMessageBox::Yes);
    else{
        Attack *s2 = new Attack();
        s2->show();
    }
}

void MainWindow::on_action_1_triggered()
{
    Select *s0 = new Select();
    s0->show();
}

void MainWindow::on_action_2_triggered()
{
    if(dev_num==0)
        QMessageBox::warning(NULL,"warning","请先选择网卡！\n",QMessageBox::Yes);
    else{
        dlg->start();
        ui->action_2->setEnabled(false);
        ui->action_3->setEnabled(true);

    }
}

void MainWindow::on_action_3_triggered()
{
    //dlg->terminate();
    endm = 1;
    ui->action_2->setEnabled(true);
    ui->action_3->setEnabled(false);
    timestamp.clear();
    sip.clear();
    dip.clear();
    smac.clear();
    dmac.clear();
    lenth.clear();
    frame.clear();
    protocol.clear();
}

void MainWindow::on_action_4_triggered()
{
    if(dev_num==0)
        QMessageBox::warning(NULL,"warning","请先选择网卡！\n",QMessageBox::Yes);
    else{
        filter *s1 = new filter();
        s1->show();
    }
}

void MainWindow::on_action_5_triggered()
{
    system("del *.pkt");
    ui->tableWidget->clearContents();
    ui->treeWidget->clear();
    ui->textBrowser->clear();
    num=0;
    num_ARP=0;
    num_TCP=0;
    num_UDP=0;
    num_ICMP=0;
    num_TOTAL=0;
    num_packet=0;
    ui->lineEdit->setText(QString::number(num_ARP));
    ui->lineEdit_2->setText(QString::number(num_TCP));
    ui->lineEdit_3->setText(QString::number(num_UDP));
    ui->lineEdit_4->setText(QString::number(num_ICMP));
    ui->lineEdit_5->setText(QString::number(num_TOTAL));
}

void MainWindow::receiveData(int data)
{
    ui->tableWidget->setRowCount(num+1);
    ui->tableWidget->setItem(num,0,new QTableWidgetItem(timestamp.at(0)));
    ui->tableWidget->setItem(num,1,new QTableWidgetItem(sip.at(0)));
    ui->tableWidget->setItem(num,2,new QTableWidgetItem(dip.at(0)));
    ui->tableWidget->setItem(num,3,new QTableWidgetItem(smac.at(0)));
    ui->tableWidget->setItem(num,4,new QTableWidgetItem(dmac.at(0)));
    ui->tableWidget->setItem(num,5,new QTableWidgetItem(lenth.at(0)));
    ui->tableWidget->setItem(num,6,new QTableWidgetItem(frame.at(0)));
    ui->tableWidget->setItem(num,7,new QTableWidgetItem(protocol.at(0)));
    timestamp.removeFirst();
    sip.removeFirst();
    dip.removeFirst();
    smac.removeFirst();
    dmac.removeFirst();
    lenth.removeFirst();
    frame.removeFirst();
    protocol.removeFirst();
    switch (data) {
    case 0: break;
    case 1: num_ARP++;ui->lineEdit->setText(QString::number(num_ARP));break;
    case 2: num_TCP++;ui->lineEdit_2->setText(QString::number(num_TCP));break;
    case 3: num_UDP++;ui->lineEdit_3->setText(QString::number(num_UDP));break;
    case 4: num_ICMP++;ui->lineEdit_4->setText(QString::number(num_ICMP));break;
    default:
        break;
    }
    num_TOTAL++;
    ui->lineEdit_5->setText(QString::number(num_TOTAL));
    num++;
}

void MainWindow::receiveData2()
{
    QMessageBox::warning(NULL,"warning","无法编译过滤器，请重新设置！\n",QMessageBox::Yes);
    ui->action_2->setEnabled(true);
    ui->action_3->setEnabled(false);
}

void MainWindow::on_tableWidget_cellClicked(int row, int column)//选中一行报文，则在另外两个表格中加载报文的具体信息
{
    QString output;
    ui->textBrowser->clear();
    FILE * fin = NULL;
    u_char num_in[65536];
    char infile[20];
    sprintf(infile, "%d", row);
    strcat(infile,".pkt");
    fin = fopen(infile,"rb");



    /*向textBrowser中插入信息*/
    int index = 0;
    while(fscanf(fin,"%x",&num_in[index]) != EOF)
        index++;
    fclose(fin);
    char trans[9];
    trans[8]='\0';
    for(int i=0 ; i<index ; i++)
    {
        if( i%8 == 0 && i!=0 )//每行显示8个字节
        {
            ui->textBrowser->append(output+"    "+QString(trans));
            for(int j=0;j<8;j++)
                trans[j] = '\0';
            output = QString::number(i)+"\t";
        }
        else if(i==0)
        {
            output = QString::number(0)+"\t";
        }
        else
        {
            ;
        }
        long temp;

        temp = num_in[i];
        if(!isASCII(temp))
            trans[i%8]='.';
        else
            trans[i%8]=temp;
        if(temp<16)//空位补0
            output+="0";
        output+=QString::number(temp,16);
        output+=" ";

    }
    ui->textBrowser->append(output+"    "+QString(trans));

    /*向treeView中插入信息*/
    ui->treeWidget->clear();

    /*数据链路层*/
    QTreeWidgetItem *items1 = new QTreeWidgetItem(ui->treeWidget, QStringList(QString("数据链路层：以太网")));
    items1->addChild(new QTreeWidgetItem(QStringList(QString("目的MAC地址："+ui->tableWidget->item(row,4)->text()))));
    items1->addChild(new QTreeWidgetItem(QStringList(QString("源MAC地址："+ui->tableWidget->item(row,3)->text()))));
    items1->addChild(new QTreeWidgetItem(QStringList(QString("帧长度："+ui->tableWidget->item(row,5)->text()+" 字节"))));

    /*网络层*/
    if(ui->tableWidget->item(row,6)->text()=="IP")
    {
        QTreeWidgetItem *items2 = new QTreeWidgetItem(ui->treeWidget, QStringList(QString("网络层：IP")));
        IPHeader_t ip_head;
        memcpy(&ip_head, num_in+14, 20);
        long TOS = ip_head.TOS;
        long TotalLen = ntohs(ip_head.TotalLen);
        long ID = ntohs(ip_head.ID);
        long Flag_Segment = ntohs(ip_head.Flag_Segment);
        long TTL = ip_head.TTL;
        if(ntohs(ip_head.Ver_HLen) & 0xf0 == 0x40)
            items2->addChild(new QTreeWidgetItem(QStringList(QString("协议类型：IPv4"))));
        else
            items2->addChild(new QTreeWidgetItem(QStringList(QString("协议类型：IPv"+QString::number(ip_head.Ver_HLen & 0xf0 /4)))));
        items2->addChild(new QTreeWidgetItem(QStringList(QString("头部长度："+QString::number((ip_head.Ver_HLen & 0x0f) *4)+"字节"))));
        items2->addChild(new QTreeWidgetItem(QStringList(QString("服务类型（十六进制）："+QString::number(TOS,16)))));
        items2->addChild(new QTreeWidgetItem(QStringList(QString("报文总长："+QString::number(TotalLen,10)+"字节"))));
        items2->addChild(new QTreeWidgetItem(QStringList(QString("标识（十六进制）："+QString::number(ID,16)))));
        items2->addChild(new QTreeWidgetItem(QStringList(QString("标记+片偏移（十六进制）："+QString::number(Flag_Segment,16)))));/////??
        items2->addChild(new QTreeWidgetItem(QStringList(QString("生存周期："+QString::number(TTL,10)))));
        items2->addChild(new QTreeWidgetItem(QStringList(QString("目的IP地址："+ui->tableWidget->item(row,2)->text()))));
        items2->addChild(new QTreeWidgetItem(QStringList(QString("源IP地址："+ui->tableWidget->item(row,1)->text()))));

        if(ui->tableWidget->item(row,7)->text()=="TCP")
        {
            QTreeWidgetItem *items3 = new QTreeWidgetItem(ui->treeWidget, QStringList(QString("传输层：TCP")));
            TCP_HEADER tcp_head;
            memcpy(&tcp_head, num_in+14+(ip_head.Ver_HLen & 0x0f) *4, 24);
            u_short th_sport = ntohs(tcp_head.th_sport);
            u_short th_dport = ntohs(tcp_head.th_dport);
            u_long th_seq = ntohl(tcp_head.th_seq);
            u_long th_ack = ntohl(tcp_head.th_ack);
            u_char th_flags = tcp_head.th_flags;
            char th[20];
            itoa(th_flags, th, 2);
            u_short th_win = ntohs(tcp_head.th_win);
            u_short th_sum = ntohs(tcp_head.th_sum);
            u_short th_urp = ntohs(tcp_head.th_urp);
            items3->addChild(new QTreeWidgetItem(QStringList(QString("源端口："+QString::number(th_sport,10)))));
            items3->addChild(new QTreeWidgetItem(QStringList(QString("目的端口："+QString::number(th_dport,10)))));
            items3->addChild(new QTreeWidgetItem(QStringList(QString("序列号："+QString::number(th_seq,10)))));
            items3->addChild(new QTreeWidgetItem(QStringList(QString("确认号："+QString::number(th_ack,10)))));
            items3->addChild(new QTreeWidgetItem(QStringList(QString("各标志位："+QString(th)))));
            items3->addChild(new QTreeWidgetItem(QStringList(QString("窗口大小："+QString::number(th_win,10)))));
            items3->addChild(new QTreeWidgetItem(QStringList(QString("校验和（十六进制）："+QString::number(th_sum,16)))));
            items3->addChild(new QTreeWidgetItem(QStringList(QString("紧急状态指针（十六进制）："+QString::number(th_urp,16)))));
            if(th_sport==80 || th_sport==8080 || th_sport== 443)
            {
                QTreeWidgetItem *items4 = new QTreeWidgetItem(ui->treeWidget, QStringList(QString("应用层：HTTP   服务器响应报文")));
                char out[65535];
                memcpy(&out, num_in+14+(ip_head.Ver_HLen & 0x0f) *4 + 24, TotalLen-24);
                for(int i=0;i<65535;i++)
                    items4->addChild(new QTreeWidgetItem(QStringList(QString("报文内容："+QString(out)))));
            }
            else if(th_dport==80 || th_dport==8080 || th_dport== 443)
            {
                QTreeWidgetItem *items4 = new QTreeWidgetItem(ui->treeWidget, QStringList(QString("应用层：HTTP   服务器响应报文")));
                char out[65535];
                memcpy(&out, num_in+14+(ip_head.Ver_HLen & 0x0f) *4 + 24, TotalLen-24);
                for(int i=0;i<TotalLen-24;i++)
                    if((!isASCII(out[i])) && out[i]!='\n')
                        out[i]='.';
                out[TotalLen-24] = '\0';
                items4->addChild(new QTreeWidgetItem(QStringList(QString("报文内容："+QString(out)))));
            }
        }
        else if(ui->tableWidget->item(row,7)->text()=="UDP")
        {
            QTreeWidgetItem *items3 = new QTreeWidgetItem(ui->treeWidget, QStringList(QString("传输层：UDP")));
            udp_header udp_head;
            memcpy(&udp_head, num_in+14+(ip_head.Ver_HLen & 0x0f) *4, 8);
            u_short sport = ntohs(udp_head.sport);          // 源端口(Source port)
            u_short dport = ntohs(udp_head.dport);          // 目的端口(Destination port)
            u_short len = ntohs(udp_head.len);            // UDP数据包长度(Datagram length)
            u_short crc = ntohs(udp_head.crc);            // 校验和(Checksum)
            items3->addChild(new QTreeWidgetItem(QStringList(QString("源端口："+QString::number(sport,10)))));
            items3->addChild(new QTreeWidgetItem(QStringList(QString("目的端口："+QString::number(dport,10)))));
            items3->addChild(new QTreeWidgetItem(QStringList(QString("UDP数据包长度："+QString::number(len,10)))));
            items3->addChild(new QTreeWidgetItem(QStringList(QString("校验和（十六进制）："+QString::number(crc,16)))));
        }
        else if(ui->tableWidget->item(row,7)->text()=="ICMP")
        {
            QTreeWidgetItem *items3 = new QTreeWidgetItem(ui->treeWidget, QStringList(QString("IP上层：ICMP")));
            icmp_hdr icmp_head;
            memcpy(&icmp_head, num_in+14+(ip_head.Ver_HLen & 0x0f) *4, 8);
            unsigned char icmp_type = icmp_head.icmp_type;   //类型
            unsigned char code = icmp_head.code;        //代码
            unsigned short chk_sum = icmp_head.chk_sum;    //16位检验和
            unsigned short flags = icmp_head.flags;    //16位标识符
            unsigned short sen = icmp_head.sen;    //序列号
            switch(icmp_type)
            {
                case 8: items3->addChild(new QTreeWidgetItem(QStringList(QString("类型："+QString::number(icmp_type,10)+" echo请求"))));break;
                case 0: items3->addChild(new QTreeWidgetItem(QStringList(QString("类型："+QString::number(icmp_type,10)+" echo应答"))));break;
                case 13: items3->addChild(new QTreeWidgetItem(QStringList(QString("类型："+QString::number(icmp_type,10)+" 时间戳请求"))));break;
                case 14: items3->addChild(new QTreeWidgetItem(QStringList(QString("类型："+QString::number(icmp_type,10)+" 时间戳应答"))));break;
                case 3: items3->addChild(new QTreeWidgetItem(QStringList(QString("类型："+QString::number(icmp_type,10)+" 目的不可达"))));break;
                case 11: items3->addChild(new QTreeWidgetItem(QStringList(QString("类型："+QString::number(icmp_type,10)+" 超时"))));break;
                default: items3->addChild(new QTreeWidgetItem(QStringList(QString("类型："+QString::number(icmp_type,10)))));break;
            }
            items3->addChild(new QTreeWidgetItem(QStringList(QString("代码："+QString::number(code,16)))));
            items3->addChild(new QTreeWidgetItem(QStringList(QString("检验和："+QString::number(chk_sum,16)))));
            items3->addChild(new QTreeWidgetItem(QStringList(QString("标识符："+QString::number(flags,16)))));
            items3->addChild(new QTreeWidgetItem(QStringList(QString("序列号："+QString::number(sen,10)))));
        }
    }
    else if(ui->tableWidget->item(row,6)->text()=="ARP")
    {
        QTreeWidgetItem *items2 = new QTreeWidgetItem(ui->treeWidget, QStringList(QString("网络层：ARP")));
        ARP_HEADER arp_head;
        memcpy(&arp_head, num_in+14, 28);
        short ar_hrd = ntohs(arp_head.ar_hrd);
        short ar_pro = ntohs(arp_head.ar_pro);
        char ar_hln = arp_head.ar_hln;
        char ar_pln = arp_head.ar_pln;
        items2->addChild(new QTreeWidgetItem(QStringList(QString("硬件类型（十六进制）："+QString::number(ar_hrd,16)))));
        items2->addChild(new QTreeWidgetItem(QStringList(QString("协议类型（十六进制）："+QString::number(ar_pro,16)+" 0x0800为IP"))));
        items2->addChild(new QTreeWidgetItem(QStringList(QString("硬件地址长度："+QString::number(ar_hln,10)))));
        items2->addChild(new QTreeWidgetItem(QStringList(QString("协议地址长度："+QString::number(ar_pln,10)))));
        char csrcmac[20];
        char csrcip[20];
        char cdesmac[20];
        char cdesip[20];

        sprintf(csrcmac,"%02x:%02x:%02x:%02x:%02x:%02x",arp_head.SrcMAC[0],arp_head.SrcMAC[1],arp_head.SrcMAC[2],arp_head.SrcMAC[3],arp_head.SrcMAC[4],arp_head.SrcMAC[5]);
        sprintf(cdesmac,"%02x:%02x:%02x:%02x:%02x:%02x",arp_head.DesMAC[0],arp_head.DesMAC[1],arp_head.DesMAC[2],arp_head.DesMAC[3],arp_head.DesMAC[4],arp_head.DesMAC[5]);
        sprintf(cdesip,"%d.%d.%d.%d",arp_head.DesIP[0],arp_head.DesIP[1],arp_head.DesIP[2],arp_head.DesIP[3]);
        sprintf(csrcip,"%d.%d.%d.%d",arp_head.SrcIP[0],arp_head.SrcIP[1],arp_head.SrcIP[2],arp_head.SrcIP[3]);

        items2->addChild(new QTreeWidgetItem(QStringList(QString("发送者硬件地址："+QString(csrcmac)))));
        items2->addChild(new QTreeWidgetItem(QStringList(QString("发送者IP地址："+QString(csrcip)))));
        items2->addChild(new QTreeWidgetItem(QStringList(QString("接收者硬件地址："+QString(cdesmac)))));
        items2->addChild(new QTreeWidgetItem(QStringList(QString("接收者IP地址："+QString(cdesip)))));

    }
    else if(ui->tableWidget->item(row,6)->text()=="RARP")
    {
        ;
    }
}

bool isASCII(char c)
{
    char q[] = "1234567890-=qwertyuiop[]\\asdfghjkl;'zxcvbnm,./!@#$%^&*()_+QWERTYUIOP{}|ASDFGHJKL:\"ZXCVBNM<>?~`";
    for(int i=0;i<strlen(q);i++)
        if(c==q[i])
            return true;
    return false;
}

