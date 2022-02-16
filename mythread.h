#ifndef MYTHREAD_H
#define MYTHREAD_H
#include "select.h"
#include "ui_select.h"
#include "analyze.h"
#include "pcap.h"
#include <winsock2.h>
#include <QDebug>
#include <QCoreApplication>
#include <QThread>

class mythread : public QThread
{
    Q_OBJECT
public:
    mythread();
    //MainWindow *w;
    void run();
signals:
    void  sendData(int);
    void  sendData2();
};

#endif // MYTHREAD_H
