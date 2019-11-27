#include "procfiltermodel.h"

ProcFSFilterModel::ProcFSFilterModel(QObject *parent) : QSortFilterProxyModel(parent)
{

}

bool ProcFSFilterModel::filterAcceptsRow(int source_row, const QModelIndex &source_parent) const
{
    if (m_filterStr=="") return true;
    if ((sourceModel()->index(source_row,1,source_parent).data().toString().contains(m_filterStr,Qt::CaseInsensitive))
            ||(sourceModel()->index(source_row,2,source_parent).data().toString().contains(m_filterStr,Qt::CaseInsensitive))
            ||(sourceModel()->index(source_row,2,source_parent).data().toString().contains(m_filterStr,Qt::CaseInsensitive)))
         return true;
    return false;
}

void ProcFSFilterModel::setFilterStr(const QString &value)
{
    m_filterStr = value;
    invalidateFilter();
}
