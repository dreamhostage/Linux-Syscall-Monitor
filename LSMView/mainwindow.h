#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QFileDialog>
#include <QInputDialog>
#include <QCheckBox>
#include "procfsmodel.h"
#include "procfiltermodel.h"
namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private:
    Ui::MainWindow *ui;
    ProcfsModel *procModel;
    ProcFSFilterModel *procFilterModel;
};

#endif // MAINWINDOW_H
