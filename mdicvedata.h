/*!
   QCVECheckReport project

   @file: mdicvedata.h

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

#ifndef MDICVEDATA_H
#define MDICVEDATA_H

#include "qsqltableview.h"
#include "qsqlitemanager.h"
#include <QMdiSubWindow>
#include <QSharedPointer>
#include <QtCharts/QtCharts>

namespace Ui {
class MdiCVEData;
}

class MdiCVEData : public QMdiSubWindow
{
    Q_OBJECT

public:

    enum class GroupBoxEnum {
        NVDs,
        Products,
    };

    explicit MdiCVEData(QSQLiteManager *sqlManager = nullptr, QWidget *parent = nullptr);
    ~MdiCVEData();

    void reloadData();

    void scrollToGroupBox(GroupBoxEnum groupBox);

protected:
    Ui::MdiCVEData *ui;
    QSQLiteManager* sqliteManager = nullptr;
    QSqlTableView* nvdsTableView = nullptr;
    QSqlTableView* productsTableView = nullptr;
    QMutex* nvdsTableMutex = nullptr;
    QMutex* productsTableMutex = nullptr;
    QThread* execSelectNVDs = nullptr;
    QThread* execSelectProducts = nullptr;

    static bool productsKeysComparison(const QString &product1, const QString &product2);

    void resizeEvent(QResizeEvent *ev) override;
    void resizeNVDsTableView();
    void resizeProductsTableView();

    void setComboBoxNVDsProducts();

    QString selectedProductID;

    void executeSelectNVDs(bool search = true);
    static void selectNVDs(QMutex *nvdsTableMutex, Ui::MdiCVEData *ui, QSQLiteManager *sqliteManager, QSqlTableView* nvdsTableView, bool search = true);

    void executeSelectProducts(const QString &productID = QString(""), bool search = true);
    static void selectProducts(QMutex *productsTableMutex, Ui::MdiCVEData *ui, QSQLiteManager *sqliteManager, QSqlTableView* productsTableView, const QString &productID = QString(""), bool search = true);

signals:
    void nvdsTableViewDataUpdated(const QModelIndex &indexA, const QModelIndex &indexB);
    void productsTableViewDataUpdated(const QModelIndex &indexA, const QModelIndex &indexB);

protected slots:
    void refreshNVDsTableView(const QModelIndex &indexA, const QModelIndex &indexB);
    void refreshProductsTableView(const QModelIndex &indexA, const QModelIndex &indexB);
    void nvdsTableViewClicked(const QModelIndex &index);
    void executeSelectNVDsFinished();
    void executeSelectProductsFinished();

private slots:
    void on_comboBoxNVDsAttackVector_currentIndexChanged(int index);
    void on_comboBoxNVDsMinimumCVSS_currentIndexChanged(int index);
    void on_comboBoxShowNs_currentIndexChanged(int index);
    void on_pushButtonSearchNVDs_clicked();
    void on_pushButtonClearSearchNVDs_clicked();
    void on_spinBoxNVDsPage_valueChanged(int value);
    void on_comboBoxShowProducts_currentIndexChanged(int index);
    void on_pushButtonSearchProducts_clicked();
    void on_pushButtonClearSearchProducts_clicked();
    void on_spinBoxProductsPage_valueChanged(int value);
    void on_comboBoxNVDsProducts_currentIndexChanged(int index);
};

#endif // MDICVEDATA_H
