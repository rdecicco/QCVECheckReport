/*!
   QCVECheckReport project

   @file: qsqltableview.cpp

   @author: Raffaele de Cicco <decicco.raffaele@gmail.com>

   @abstract:
   This tool is able to create a report to analyze CVE of a yocto build image using CVECheck json report and
   NVD CVE DB of NIST created by the same tool retriving information by https://www.nist.gov/

   @copyright: Copyright 2024 Raffaele de Cicco <decicco.raffaele@gmail.com>

   @legalese:
   Licensed under the General Public License, Version 3.0 (the "License");
   you may not use this file except in compliance with the License.
   See file gnu-gpl-v3.0.md or obtain a copy of the License at

       https://www.gnu.org/licenses/gpl-3.0.html

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */

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

