#ifndef SELECT_H
#define SELECT_H

#include <QWidget>
#include <QMainWindow>

namespace Ui {
class Select;
}

class Select : public QWidget
{
    Q_OBJECT

public:
    explicit Select(QWidget *parent = 0);
    ~Select();

private slots:
    void on_tableWidget_cellDoubleClicked(int row);

private:
    Ui::Select *ui;
};

#endif // SELECT_H
