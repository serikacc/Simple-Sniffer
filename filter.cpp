#include "filter.h"
#include "ui_filter.h"
#include <QDebug>

QString packet_filter="";
extern int dev_num;

filter::filter(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::filter)
{
    ui->setupUi(this);

}

filter::~filter()
{
    delete ui;
}

void filter::on_pushButton_clicked()
{
    packet_filter = ui->lineEdit->text();
    qDebug()<<packet_filter;
    close();
}
