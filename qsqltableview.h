#ifndef QSQLTABLEVIEW_H
#define QSQLTABLEVIEW_H

#include "qsqlquerymodel.h"
#include "qstandarditemmodel.h"
#include <QTableView>

class QSqlTableView : public QTableView
{
public:
    explicit QSqlTableView(QSqlQueryModel *model, QWidget *parent = nullptr);

    ~QSqlTableView() override;

    QStandardItemModel* getModel();
    void setSqlQueryModel(QSqlQueryModel* sqlQueryModel);
    QSqlQueryModel* getSqlQueryModel();

protected:
    QSqlQueryModel* sqlModel;
    QStandardItemModel* model;

public  slots:
    void updateStandardItemModel(const QModelIndex &topLeft, const QModelIndex &bottomRight, const QList<int> &roles = QList<int>());

};

#endif // QSQLTABLEVIEW_H
