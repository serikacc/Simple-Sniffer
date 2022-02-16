#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTextStream>
#include <QMessageBox>
#include <QDebug>
#include <winsock2.h>
#include <QCoreApplication>
#include "mythread.h"
#include "pcap.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    QWidget *s0;
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

 private slots:
    void on_menu_2_triggered();
    void on_action_1_triggered();
    void on_action_2_triggered();
    void on_action_3_triggered();
    void on_action_4_triggered();
    void on_action_5_triggered();
    void on_action_6_triggered();
    void receiveData(int);
    void receiveData2();
    void on_tableWidget_cellClicked(int row, int column);

private:
    Ui::MainWindow *ui;
    mythread *dlg;
};

#endif // MAINWINDOW_H
