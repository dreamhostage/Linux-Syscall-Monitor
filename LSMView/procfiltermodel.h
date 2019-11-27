#ifndef PROCFILTERMODEL_H
#define PROCFILTERMODEL_H

#include <QObject>
#include <QSortFilterProxyModel>
class ProcFSFilterModel : public QSortFilterProxyModel
{
public:
    ProcFSFilterModel(QObject *parent = nullptr);

    // QSortFilterProxyModel interface
public slots:
    void setFilterStr(const QString &value);

protected:
    bool filterAcceptsRow(int source_row, const QModelIndex &source_parent) const;
private:
    QString m_filterStr="";
};

#endif // PROCFILTERMODEL_H
