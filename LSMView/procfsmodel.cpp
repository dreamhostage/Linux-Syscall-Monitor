#include "procfsmodel.h"
ProcfsModel::ProcfsModel(QObject *parent) : QAbstractTableModel(parent)
{
        m_args<<"-c"<<"dmesg --follow | grep \"<LSM>\"";
        QString program = "/bin/";
        m_procDmesg = new QProcess(parent);
        m_procDmesg->setProgram("bash");
        m_procDmesg->setArguments((m_args));
        m_procDmesg->setReadChannel(QProcess::StandardOutput);
        //procDmesg->setReadChannelMode()
        connect(m_procDmesg,&QProcess::readyReadStandardOutput,this,&ProcfsModel::onDmesgReadyRead);
        QFile logFile(m_fileLogPath);
        logFile.resize(0);

}



void ProcfsModel::setLogLevel(int lvl)
{
    writeCommandToFile("setlogginglevel "+QString::number(lvl));
}

void ProcfsModel::setBlockFile(QString path)
{
    if (path=="")
        writeCommandToFile("unblock");
    else
        writeCommandToFile("block "+path);
}

void ProcfsModel::setLoggingEnable(bool isLogEnable)
{
    if (isLogEnable)
       writeCommandToFile("startlogging");
    else
       writeCommandToFile("stoplogging");
}

void ProcfsModel::alloUnload(bool isAllowUnload)
{
    if (isAllowUnload)
        writeCommandToFile("allowunload 1");
    else
        writeCommandToFile("allowunload 0");

}
void ProcfsModel::allowX86(bool is32bitEnable)
{
    if (is32bitEnable)
        writeCommandToFile("startlogging32");
    else
        writeCommandToFile("stoplogging32");

}

void ProcfsModel::setDMESGFilter(QString filterStr)
{
    if (m_DMESGEnable) m_procDmesg->terminate();
    if (filterStr!="")
    {
        QStringList argsWithFilter=m_args;
        argsWithFilter.last().append(filterStr);
        m_procDmesg->setArguments(argsWithFilter);
    }
    else {
        m_procDmesg->setArguments(m_args);
    }
    if (m_DMESGEnable) m_procDmesg->start();
}

void ProcfsModel::readFromDMESG(bool enable)
{
    m_DMESGEnable=enable;
    if (enable)
       // tmrForReadDMESG->start();
        m_procDmesg->start();
    else
        //tmrForReadDMESG->stop();
        m_procDmesg->terminate();
}
oneLogRecord ProcfsModel::parseStr(QString str)
{
    oneLogRecord rcd;
    int indexOfLsm=str.indexOf("<LSM>");
    if (indexOfLsm==-1)
    {
        rcd.msg=str;
        return rcd;
    }
    str=str.remove(0,indexOfLsm+5);
    int indexOfSep=str.indexOf('>');
    if (indexOfSep==-1)
    {
        rcd.msg=str;
        return rcd;
    }
    rcd.type=str.left(indexOfSep);
    rcd.type.remove(0,1);
    str=str.remove(0,indexOfSep+1);
    indexOfSep=str.indexOf('>');
    if (indexOfSep==-1)
    {
        rcd.msg=str;
        return rcd;
    }
    rcd.command=str.left(indexOfSep+1);
    rcd.command.remove(0,1);
    rcd.command.remove(rcd.command.length()-1,1);
    str=str.remove(0,indexOfSep+1);
    rcd.msg=str;
    return rcd;
}
void ProcfsModel::refreshData()
{
    if (m_DMESGEnable) return;
    beginResetModel();
    QFile proc(m_procPath);
    m_records.clear();
    if (!proc.open(QIODevice::ReadOnly))
    {
        qWarning()<<"Cant open file";
        return;
    }
    if (!proc.isReadable()){
        qWarning()<<"Cant read file";
        return;
    }

    QByteArray contents = proc.readAll();
    QTextStream in(&contents);
    QString line;
    line=in.readLine();
    while (!line.isNull()) {
        m_records.insert(0,parseStr(line));
        line = in.readLine();
    }
    proc.close();
    endResetModel();
}
void ProcfsModel::writeCommandToFile(QString cmd)
{
    QFile proc(m_procPath);
    if (!proc.open(QIODevice::WriteOnly))
    {
        qWarning()<<"Cant open file";
        return;
    }
    QTextStream procText(&proc);
    procText<<cmd<<"\n\0";
    procText.seek(0);
    proc.close();
}

void ProcfsModel::onDmesgReadyRead()
{
    //QByteArray contents=procDmesg->readAll();
    //QTextStream in(&contents);
    beginResetModel();
    /*QString line;
    line=in.readLine();
    while (!line.isNull()) {
        m_records.insert(0,parseStr(line));
        line = in.readLine();
    }*/
    QFile logFile(m_fileLogPath);
    bool IsOpened =logFile.open(QIODevice::Append);
    QString oneLine;
    while (m_procDmesg->canReadLine())
    {
        oneLine=QString(m_procDmesg->readLine());
        m_records.insert(0,parseStr(oneLine));
        if (IsOpened) logFile.write(oneLine.toUtf8());
    }
    if (IsOpened) logFile.close();
    if (m_records.size()>1000)
        m_records.resize(1000);
    endResetModel();
    //emit dataChanged(index(0,0),index(999,2));
}

QVariant ProcfsModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (role==Qt::DisplayRole&&orientation==Qt::Horizontal)
        switch (section) {
        case 0:
            return "Type";
        case 1:
            return "Command";
        case 2:
            return "Message";
        default:
            return QVariant();
        }
    return QVariant();
}
QVariant ProcfsModel::data(const QModelIndex &index, int role) const
{
    if (index.isValid()&&role==Qt::DisplayRole)
    {
        if (index.row()<m_records.count())
        {
            switch (index.column()) {
                case 0:
                return m_records.at(index.row()).type;
            case 1:
                return m_records.at(index.row()).command;
            case 2:
                return m_records.at(index.row()).msg;
            default:
                return QVariant();
            }
        }

    }
    return QVariant();
}
