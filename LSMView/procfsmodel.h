#ifndef PROCFSMODEL_H
#define PROCFSMODEL_H

#include <QDebug>
#include <QObject>
#include <QAbstractTableModel>
#include <QList>
#include <QTextStream>
#include <QFuture>
#include <QtConcurrent/QtConcurrent>
#include <QProcess>
#include <QTimer>
#include <QFile>
struct oneLogRecord{
    QString type;
    QString command;
    QString msg;
};
class ProcfsModel : public QAbstractTableModel
{
    Q_OBJECT
public:
    explicit ProcfsModel(QObject *parent = nullptr);
signals:

public slots:
    void refreshData();
    void setLogLevel(int lvl);
    void setBlockFile(QString path);
    void setLoggingEnable(bool isLogEnable);
    void alloUnload(bool isAllowUnload);
    void readFromDMESG(bool enable);
    void allowX86(bool isAllowUnload);
    void setDMESGFilter(QString filterStr);
    // QAbstractItemModel interface
public:
    int rowCount(const QModelIndex &parent) const {return m_records.count();}
    int columnCount(const QModelIndex &parent) const {return  m_colCount;}
    QVariant data(const QModelIndex &index, int role) const;
private:
    QHash<QString,oneLogRecord> m_records_dmesg;
    oneLogRecord parseStr(QString str);
    const QString m_procPath="/proc/ActMon";
    QVector<oneLogRecord> m_records;
    void writeCommandToFile(QString cmd);
    QProcess *m_procDmesg;
    int m_colCount=3;
    bool m_DMESGEnable=false;
    const QString m_fileLogPath="event.log";
    QStringList m_args;
private slots:
    void onDmesgReadyRead();
    // QAbstractItemModel interface
public:
    QVariant headerData(int section, Qt::Orientation orientation, int role) const;
};

#endif // PROCFSMODEL_H
