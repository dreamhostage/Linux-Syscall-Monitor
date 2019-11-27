#include "mainwindow.h"
#include "ui_mainwindow.h"


MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    procModel = new ProcfsModel(this);
    procFilterModel = new ProcFSFilterModel;
    procFilterModel->setSourceModel(procModel);
    ui->tblLog->setModel(procFilterModel);
    connect(ui->btnRefresh,&QPushButton::clicked,procModel,&ProcfsModel::refreshData);
    connect(ui->chkDmesg,&QCheckBox::clicked,procModel,&ProcfsModel::readFromDMESG);
    connect(ui->chkX86,&QCheckBox::clicked,[&](bool isChecked){
        if (isChecked)
        {
            procModel->setLoggingEnable(false);
            procModel->setLogLevel(3);
            procModel->allowX86(true);
        }
        else {
           procModel->allowX86(false);
        }
    });
    ui->tblLog->setColumnWidth(0,100);
    ui->tblLog->setColumnWidth(1,200);
    ui->tblLog->horizontalHeader()->setStretchLastSection(true);
    connect(ui->btnSetLvl1,&QPushButton::clicked,[&](){
      procModel->setLogLevel(1);
    });
    connect(ui->btnSetLvl2,&QPushButton::clicked,[&](){
      procModel->setLogLevel(2);
    });
    connect(ui->btnSetLvl3,&QPushButton::clicked,[&](){
      procModel->setLogLevel(3);
    });
    connect(ui->btnBlockFile,&QPushButton::clicked,[&](){
      procModel->setBlockFile(QFileDialog::getOpenFileName(this,"Select file"));
    });
    connect(ui->btnUnblockFile,&QPushButton::clicked,[&](){
      procModel->setBlockFile("");
    });
    connect(ui->btnStopLogging,&QPushButton::clicked,[&](){
      procModel->setLoggingEnable(false);
    });
    connect(ui->btnStartLogging,&QPushButton::clicked,[&](){
      procModel->setLoggingEnable(true);
    });
    connect(ui->btnAllowUnload,&QPushButton::clicked,[&](){
      procModel->alloUnload(false);
    });
    connect(ui->btnBlockUnload,&QPushButton::clicked,[&](){
      procModel->alloUnload(true);
    });
    connect(ui->btnFilter,&QPushButton::clicked,[this]()
    {
        bool ok;
        QString text=QInputDialog::getText(this,"Enter filter","Enter text for filtering:",QLineEdit::Normal,"",&ok);
        if (ok)
        {
            this->procFilterModel->setFilterStr(text);
            this->procModel->setDMESGFilter(text);
        }
    });

}

MainWindow::~MainWindow()
{
    delete ui;
}
