/*!
   QCVECheckReport project

   @file: mdisubwindow.h

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

#ifndef MDISUBWINDOW_H
#define MDISUBWINDOW_H

#include "qsqltableview.h"
#include "reportdata.h"
#include <QMdiSubWindow>
#include <QSharedPointer>
#include <QtCharts/QtCharts>

namespace Ui {
class MdiSubWindow;
}

class MdiSubWindow : public QMdiSubWindow
{
    Q_OBJECT

public:

    enum class GroupBoxEnum {
        General,
        Summary,
        Packages,
        CVEs,
        IgnoredCVEs
    };

    explicit MdiSubWindow(const QString& fileName = QString(), QSQLiteManager *sqlManager = nullptr, QWidget *parent = nullptr);
    ~MdiSubWindow();

    void LoadReportData();

    void scrollToGroupBox(GroupBoxEnum groupBox);

private:
    Ui::MdiSubWindow *ui;
    QString reportFile;
    QSQLiteManager* sqliteManager = nullptr;
    QSharedPointer<ReportData> reportData;
    QPieSeries* unpatchedCVEBySeveritySeries = nullptr;
    QChartView* unpatchedCVEBySeverityChart = nullptr;
    QPieSeries* packagesWithKnowenCVEsSeries = nullptr;
    QChartView* packagesWithKnowenCVEsChart = nullptr;
    QSqlTableView* packagesTableView = nullptr;
    QSqlTableView* cvesTableView = nullptr;
    QSqlTableView* ignoredCVEsTableView = nullptr;

    QMutex* packagesTableMutex = nullptr;
    QMutex* cvesTableMutex = nullptr;
    QMutex* ignoredCVEsTableMutex = nullptr;

    QThread* execSelectPackages = nullptr;
    QThread* execSelectCVEs = nullptr;
    QThread* execSelectIgnoreCVEs = nullptr;

    static bool packagesKeysComparison(const AbstractDTO::SharedDTO &package1, const AbstractDTO::SharedDTO &package2);
    void setComboBoxCVEPackages();

protected:
    void resizeEvent(QResizeEvent *ev) override;
    void resizePackagesTableView();
    void resizeCVEsTableView();
    void resizeIgnoredCVEsTableView();
    void resizeAllTables();

    void executeSelectPackages(bool search = true);
    void executeSelectCVEs(bool search = true);
    void executeSelectIgnoredCVEs(bool search = true);

signals:
    void packagesTableViewDataUpdated(const QModelIndex &indexA, const QModelIndex &indexB);
    void cvesTableViewDataUpdated(const QModelIndex &indexA, const QModelIndex &indexB);
    void ignoredCVEsTableViewDataUpdated(const QModelIndex &indexA, const QModelIndex &indexB);

protected slots:
    static void selectPackages(QMutex* packagesTableMutex, ReportData* reportData, Ui::MdiSubWindow* ui, QSqlTableView* packagesTableView, bool search = true);
    static void selectCVEs(QMutex* cvesTableMutex, ReportData* reportData, Ui::MdiSubWindow* ui, QSqlTableView* cvesTableView, bool search = true);
    static void selectIgnoredCVEs(QMutex* ignoredCVEsTableMutex, ReportData* reportData, Ui::MdiSubWindow* ui, QSqlTableView* ignoredCVEsTableView, bool search = true);

    void refreshPackagesTableView(const QModelIndex &indexA, const QModelIndex &indexB);
    void refreshCVEsTableView(const QModelIndex &indexA, const QModelIndex &indexB);
    void refreshIgnoredCVEsTableView(const QModelIndex &indexA, const QModelIndex &indexB);

    void cvesTableViewClicked(const QModelIndex &index);
    void ignoredCVEsTableViewClicked(const QModelIndex &index);

    void executeSelectPackagesFinished();
    void executeSelectCVEsFinished();
    void executeSelectIgnoredCVEsFinished();

private slots:
    void on_checkBoxOnlyUnfixedPackages_stateChanged(int state);
    void on_comboBoxShowPackages_currentIndexChanged(int index);
    void on_pushButtonSearchPackages_clicked();
    void on_spinBoxPackagesPage_valueChanged(int value);
    void on_pushButtonClearSearchPackages_clicked();
    void on_comboBoxCVEsPackages_currentIndexChanged(int index);
    void on_comboBoxCVEsStatus_currentIndexChanged(int index);
    void on_comboBoxCVEsAttackVector_currentIndexChanged(int index);
    void on_comboBoxCVEsMinimumCVSS_currentIndexChanged(int index);
    void on_comboBoxShowCVEs_currentIndexChanged(int index);
    void on_pushButtonSearchCVEs_clicked();
    void on_pushButtonClearSearchCVEs_clicked();
    void on_comboBoxShowIgnoredCVEs_currentIndexChanged(int index);
    void on_pushButtonSearchIgnoredCVEs_clicked();
    void on_pushButtonClearSearchIgnoredCVEe_clicked();
    void on_spinBoxIgnoredCVEsPage_valueChanged(int index);
    void on_spinBoxCVEsPage_valueChanged(int index);
};

#endif // MDISUBWINDOW_H
