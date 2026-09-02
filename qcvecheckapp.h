/*!
   QCVECheckReport project

   @file: qcvecheckapp.h

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

#ifndef QCVECHECKAPP_H
#define QCVECHECKAPP_H

#include <QMainWindow>
#include <QResizeEvent>
#include <dialogimportcvereport.h>
#include <dialogimportsbomcvereport.h>
#include "dialogimportnvddb.h"
#include "dialogimportnvdjsonrepo.h"
#include "dialogimportcvejsonrepo.h"
#include "mdicvedata.h"
#include "mdipdfreport.h"
#include "mdireport.h"
#include "qsqlitemanager.h"
#include "jsoncvecheckreportmanager.h"

QT_BEGIN_NAMESPACE
namespace Ui { class QCVECheckApp; }
QT_END_NAMESPACE

class QCVECheckApp : public QMainWindow
{
    Q_OBJECT

public:
    QCVECheckApp(QWidget *parent = nullptr);
    ~QCVECheckApp();

signals:
    void importJsonCVEReportFinished(const QString& jsonReportFileName);
    void importNVDDBFinished();
    void importNVDJsonRepoFinished();
    void importCVEJsonRepoFinished();

private slots:
    void on_action_Import_CVE_Check_Report_triggered();
    void on_action_Import_SBOM_CVE_Check_Report_triggered();
    void on_action_Import_NVD_DB_triggered();
    void on_action_Import_NVD_Json_Repo_triggered();
    void on_action_Import_CVE_Json_Repo_triggered();

    void on_action_Exit_triggered();
    void on_action_About_QCVECheckReport_triggered();

    void on_comboBoxReports_currentIndexChanged(int index);
    void on_pushButtonOpen_clicked();
    void on_pushButtonGeneral_clicked();

    void on_pushButtonSummary_clicked();

    void on_pushButtonPackages_clicked();

    void on_pushButtonCVEs_clicked();

    void on_pushButtonIgnoredCVEs_clicked();    

    void on_pushButtonCVEData_clicked();

    void on_pushButtonExportReport_clicked();

    static void importCVECheckReport(QCVECheckApp* parent, const QString& jsonReportFileName, const QString& NVDDBFileName);
    static void importSBOMCVECheckReport(QCVECheckApp* parent, const QString& jsonReportFileName, const QString& NVDJsonRepoPath,  const QString& CVEJsonRepoPath);

    static void importNVDDB(QCVECheckApp *parent, const QString& NVDDBFileName);
    static void importNVDJsonRepo(QCVECheckApp *parent, const QString& NVDJsonRepoPath);
    static void importCVEJsonRepo(QCVECheckApp *parent, const QString& CVEJsonRepoPath);

    void jsonCVEReportImported(const QString& jsonReportFileName);

    void NVDDBImported();
    void NVDJsonRepoImported();
    void CVEJsonRepoImported();

    void UpdateCVEReportsComboBox();

private:
    Ui::QCVECheckApp *ui = nullptr;
    DialogImportCVEReport *dialogImportCVEReport = nullptr;
    DialogImportSBOMCVEReport *dialogImportSBOMCVEReport= nullptr;
    DialogImportNVDDB *dialogImportNVDDB= nullptr;
    DialogImportNVDJsonRepo *dialogImportNVDJsonRepo= nullptr;
    DialogImportCVEJsonRepo *dialogImportCVEJsonRepo= nullptr;
    QSQLiteManager* sqliteDBManager= nullptr;
    JsonCVECheckReportManager jsonCVEReportManager;
    QStringList jsonCVEReportsList;

    QMap<QString, MdiPDFReport*> pdfReportsMap;
    QMap<QString, MdiReport*> reportMap;
    MdiCVEData* mdiCVEData = nullptr;

    void OpenCVEReportWindow(const QString &reportName);
    void OpenPDFReportWindow(const QString &reportName);

    QThread* importCVEReportThread = nullptr;
    QThread* importNVDDbThread = nullptr;

    QThread* importSBOMCVEReportThread = nullptr;
    QThread* importNVDJsonRepoThread = nullptr;
    QThread* importCVEJsonRepoThread = nullptr;

    QMutex* subWindowMapMutex = nullptr;
    QMutex* mdiCVEDataMutex = nullptr;

protected:
    void resizeEvent(QResizeEvent *ev) override;

};
#endif // QCVECHECKAPP_H
