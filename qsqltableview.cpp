#include "qsqltableview.h"
#include "qsqlquerymodel.h"
#include <QSqlTableModel>

QSqlTableView::QSqlTableView(QSqlQueryModel *sqlQueryModel, QWidget* parent): QTableView(parent), sqlModel(sqlQueryModel), model(new QStandardItemModel(this))
{
    updateStandardItemModel(sqlModel->index(0, 0), sqlModel->index(sqlModel->rowCount()-1, sqlModel->columnCount()-1));
}

QSqlTableView::~QSqlTableView()
{
}

QStandardItemModel *QSqlTableView::getModel()
{
    return model;
}

void QSqlTableView::setSqlQueryModel(QSqlQueryModel *sqlQueryModel)
{
    delete sqlModel;
    sqlModel = sqlQueryModel;
    updateStandardItemModel(sqlModel->index(0, 0), sqlModel->index(sqlModel->rowCount()-1, sqlModel->columnCount()-1));
}

QSqlQueryModel *QSqlTableView::getSqlQueryModel()
{
    return sqlModel;
}

void QSqlTableView::updateStandardItemModel(const QModelIndex &topLeft, const QModelIndex &bottomRight, const QList<int> &roles)
{
    delete model;
    model = new QStandardItemModel(bottomRight.row()- topLeft.row(), bottomRight.column() - topLeft.column());
    for (int i=0; i< sqlModel->columnCount(); ++i)
    {
        model->setHorizontalHeaderItem(i, new QStandardItem(sqlModel->headerData(i, Qt::Horizontal).toString()));
    }

    for (int i=0; i< sqlModel->columnCount(); ++i)
    {
        for (int j=0; j< sqlModel->rowCount(); ++j)
        {
            QStandardItem *item = new QStandardItem(j, i);
            item->setText(sqlModel->index(j,i).data().toString());
            item->setTextAlignment(Qt::AlignCenter);
            model->setItem(j, i, item);
        }
    }
    setModel(model);
}

