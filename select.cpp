#include "select.h"
#include "ui_select.h"
#include "pcap.h"
#include <QDebug>

extern pcap_if_t *alldevs;
int dev_num=0;

Select::Select(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Select)
{
    ui->setupUi(this);
    ui->tableWidget->setRowCount(0);
    ui->tableWidget->setColumnCount(2);
    ui->tableWidget->clearContents();//清空原有数据
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);//设置每次点击选中一行
    ui->tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);//设置每行不可编辑
    QStringList headers;
    headers<<"设备名"<<"描述";
    ui->tableWidget->setHorizontalHeaderLabels(headers);
    ui->tableWidget->horizontalHeader()->setStretchLastSection(true); //列填充

    pcap_if_t *d;
    int i=0;
    char errbuf[PCAP_ERRBUF_SIZE];

    /* 获取本地机器设备列表 */
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        qDebug() << errbuf;
        exit(1);
    }

    /* 打印列表 */
    for(d= alldevs; d != NULL; d= d->next)
    {
        qDebug()<<++i<<". "<<d->name;
        ui->tableWidget->setRowCount(i);
        ui->tableWidget->setItem(i-1,0,new QTableWidgetItem(QString(d->name)));
        if (d->description){
            qDebug()<<" ("<<d->description<<")\n";
            ui->tableWidget->setItem(i-1,1,new QTableWidgetItem(QString(d->description)));
        }
        else{
            qDebug()<<" (No description available)\n";
        }
    }

    if (i == 0)
    {
        qDebug()<<"\nNo interfaces found! Make sure WinPcap is installed.\n";
        ui->tableWidget->setRowCount(1);
        ui->tableWidget->setItem(0,0,new QTableWidgetItem("No interfaces found! Make sure WinPcap is installed."));
        return;
    }

    /* 不再需要设备列表了，释放它 */
    pcap_freealldevs(alldevs);

}

Select::~Select()
{
    delete ui;
}

void Select::on_tableWidget_cellDoubleClicked(int row)//双击选择网卡
{
    dev_num = row+1;
    qDebug("%d", dev_num);
    close();
}
