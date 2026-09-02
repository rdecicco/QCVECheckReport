/*!
   QCVECheckReport project

   @file: qcvecheckapp.cpp

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

#include "qcvecheckapp.h"
#include "ui_qcvecheckapp.h"
#include "dialogimportnvddb.h"
#include "mdicvedata.h"
#include "mdireport.h"
#include "ui_qcvecheckapp.h"
#include <QFileDialog>
#include <QJsonDocument>
#include <QJsonObject>
#include <QException>
#include <QtSql/QSql>
#include <QDockWidget>
#include <QMdiSubWindow>
#include <QMessageBox>
#include <QResizeEvent>
#include <QWindow>
#include <ui_dialogimportcvereport.h>

QCVECheckApp::QCVECheckApp(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::QCVECheckApp), sqliteDBManager(new QSQLiteManager(this)), mdiCVEDataMutex(new QMutex()), subWindowMapMutex(new QMutex())
{
    ui->setupUi(this);
    UpdateCVEReportsComboBox();
    connect(this, SIGNAL(importJsonCVEReportFinished(QString)), this, SLOT(jsonCVEReportImported(QString)), Qt::QueuedConnection);
    connect(this, SIGNAL(importNVDDBFinished()), this, SLOT(NVDDBImported()), Qt::QueuedConnection);
    connect(this, SIGNAL(importNVDJsonRepoFinished()), this, SLOT(NVDJsonRepoImported()), Qt::QueuedConnection);
    connect(this, SIGNAL(importCVEJsonRepoFinished()), this, SLOT(CVEJsonRepoImported()), Qt::QueuedConnection);
}

QCVECheckApp::~QCVECheckApp()
{
    disconnect(this, SIGNAL(importJsonCVEReportFinished(QString)), this, SLOT(jsonCVEReportImported(QString)));
    disconnect(this, SIGNAL(importNVDDBFinished()), this, SLOT(NVDDBImported()));
    disconnect(this, SIGNAL(importNVDJsonRepoFinished()), this, SLOT(NVDJsonRepoImported()));
    disconnect(this, SIGNAL(importCVEJsonRepoFinished()), this, SLOT(CVEJsonRepoImported()));
    delete sqliteDBManager;
    delete ui;
    delete mdiCVEDataMutex;
    delete subWindowMapMutex;
}

void QCVECheckApp::resizeEvent(QResizeEvent *ev)
{
    ui->centralwidget->resize(ev->size() - QSize(ui->dockWidgetMenu->size().width() + 6, 0));
    ui->mdiArea->resize(ui->centralwidget->size() - QSize(0, ui->menubar->height() + ui->toolBar->height() + ui->statusbar->height()));
    ui->dockWidgetMenu->resize(200, ev->size().height() - ui->menubar->height() - ui->toolBar->height() - ui->statusbar->height());
    ui->dockWidgetMenuContents->resize(ui->dockWidgetMenu->size());
    ui->dockWidgetVerticalToolBox->resize(ui->dockWidgetMenuContents->size());
    ui->dockWidgetVerticalToolBoxPage1->resize(ui->dockWidgetVerticalToolBox->size());
    ui->groupBoxMain->resize(ui->dockWidgetVerticalToolBoxPage1->size().width(), 100);
    ui->groupBoxCVEReport->resize(ui->dockWidgetVerticalToolBoxPage1->size().width(), 100);
    ui->groupBoxCVEData->resize(ui->dockWidgetVerticalToolBoxPage1->size().width(), 100);
}

void QCVECheckApp::UpdateCVEReportsComboBox()
{
    jsonCVEReportsList = sqliteDBManager->getCVEReportsList();
    ui->comboBoxReports->clear();
    ui->comboBoxReports->addItems(jsonCVEReportsList);
}

void QCVECheckApp::importCVECheckReport(QCVECheckApp* parent, const QString& jsonReportFileName, const QString& NVDDBFileName)
{
    try
    {
        parent->setCursor(Qt::CursorShape::WaitCursor);

        if (!QFile::exists(NVDDBFileName) || !QFile::exists(jsonReportFileName))
        {
            QMessageBox::critical(nullptr, tr("Open CVE Json Report Error"), tr("Not valid file name"));
            parent->setCursor(Qt::CursorShape::ArrowCursor);
            return;
        }

        if (!parent->sqliteDBManager->isNewReport(jsonReportFileName))
        {
            QMessageBox::critical(nullptr, tr("Import CVE Json Report Error"), tr("Report already imported"));
            parent->setCursor(Qt::CursorShape::ArrowCursor);
            return;
        }

        if (!parent->sqliteDBManager->importNVDDb(NVDDBFileName))
        {
            QMessageBox::critical(nullptr, tr("Import NVD DB Error"), tr("Import of NVD DB Failed"));
            parent->setCursor(Qt::CursorShape::ArrowCursor);
            return;
        }

        if (!parent->jsonCVEReportManager.open(jsonReportFileName))
        {
            QMessageBox::critical(nullptr, tr("Open CVE Json Report Error"), tr("Not valid CVE Report"));
            parent->setCursor(Qt::CursorShape::ArrowCursor);
            return;
        }

        if (!parent->sqliteDBManager->importCVEJsonReport(jsonReportFileName, parent->jsonCVEReportManager.getJsonDocument()))
        {
            parent->setCursor(Qt::CursorShape::ArrowCursor);
            return;
        }

        emit parent->importJsonCVEReportFinished(jsonReportFileName);
        QMessageBox::information(nullptr, tr("Import CVE Json Report"), tr("Import of CVE Report Successfully Executed"));
        parent->setCursor(Qt::CursorShape::ArrowCursor);
    }
    catch (QException ex)
    {
        QMessageBox::critical(nullptr, tr("Error"), ex.what());
        parent->setCursor(Qt::CursorShape::ArrowCursor);
    }
}

void QCVECheckApp::jsonCVEReportImported(const QString &jsonReportFileName)
{
    try
    {
        UpdateCVEReportsComboBox();
        ui->comboBoxReports->setCurrentIndex(jsonCVEReportsList.indexOf(QFileInfo(jsonReportFileName).fileName()));

        {
            QMutexLocker locker(subWindowMapMutex);
            for (auto& mdiReportWindow : reportMap)
            {
                mdiReportWindow->LoadReportData();
            }
        }

        {
            QMutexLocker locker(mdiCVEDataMutex);
            if (mdiCVEData)
            {
                mdiCVEData->reloadData();
            }
        }
    }
    catch (QException ex)
    {
        QMessageBox::critical(this, tr("Error"), ex.what());
    }
}

void QCVECheckApp::on_action_Import_CVE_Check_Report_triggered()
{
    try
    {
        dialogImportCVEReport = new DialogImportCVEReport(this);
        QDialog::DialogCode returnValue = (QDialog::DialogCode)dialogImportCVEReport->exec();
        if (returnValue == QDialog::DialogCode::Accepted)
        {
            QString NVDDBFileName = dialogImportCVEReport->getNVDDbFileName();
            QString jsonReportFileName = dialogImportCVEReport->getJsonReportFileName();

            if (importCVEReportThread != nullptr)
            {
                importCVEReportThread->exit();
                delete importCVEReportThread;
                importCVEReportThread = nullptr;
            }

            importCVEReportThread = QThread::create(importCVECheckReport, this, jsonReportFileName, NVDDBFileName);
            importCVEReportThread->start();
        }
    }
    catch (QException ex)
    {
        QMessageBox::critical(this, tr("Error"), ex.what());
    }

    if (dialogImportCVEReport != nullptr)
    {
        dialogImportCVEReport->close();
    }
}

void QCVECheckApp::importSBOMCVECheckReport(QCVECheckApp* parent, const QString& jsonReportFileName, const QString& NVDJsonRepoPath,  const QString& CVEJsonRepoPath)
{
    try
    {
        parent->setCursor(Qt::CursorShape::WaitCursor);

        if (!QFile::exists(jsonReportFileName) || (!QFile::exists(NVDJsonRepoPath) && !QFile::exists(CVEJsonRepoPath)))
        {
            QMessageBox::critical(nullptr, tr("Open SBOM CVE Json Report Error"), tr("Not valid file name or path"));
            parent->setCursor(Qt::CursorShape::ArrowCursor);
            return;
        }

        if (!parent->sqliteDBManager->isNewReport(jsonReportFileName))
        {
            QMessageBox::critical(nullptr, tr("Import SBOM CVE Json Report Error"), tr("Report already imported"));
            parent->setCursor(Qt::CursorShape::ArrowCursor);
            return;
        }

        if (!NVDJsonRepoPath.isEmpty() && !parent->sqliteDBManager->importNVDJsonRepo(NVDJsonRepoPath))
        {
            QMessageBox::critical(nullptr, tr("Import NVD Json Repository Error"), tr("Import of NVD Json Repository Failed"));
            parent->setCursor(Qt::CursorShape::ArrowCursor);
            return;
        }

        if (!CVEJsonRepoPath.isEmpty() && !parent->sqliteDBManager->importCVEJsonRepo(CVEJsonRepoPath))
        {
            QMessageBox::critical(nullptr, tr("Import CVE Json Repository Error"), tr("Import of CVE Json Repository Failed"));
            parent->setCursor(Qt::CursorShape::ArrowCursor);
            return;
        }

        if (!parent->jsonCVEReportManager.open(jsonReportFileName))
        {
            QMessageBox::critical(nullptr, tr("Open CVE Json Report Error"), tr("Not valid CVE Report"));
            parent->setCursor(Qt::CursorShape::ArrowCursor);
            return;
        }

        if (!parent->sqliteDBManager->importSBOMCVEJsonReport(jsonReportFileName, parent->jsonCVEReportManager.getJsonDocument()))
        {
            parent->setCursor(Qt::CursorShape::ArrowCursor);
            return;
        }

        emit parent->importJsonCVEReportFinished(jsonReportFileName);
        QMessageBox::information(nullptr, tr("Import Json Report"), tr("Import of CSV Report Successfully Executed"));
        parent->setCursor(Qt::CursorShape::ArrowCursor);
    }
    catch (QException ex)
    {
        QMessageBox::critical(nullptr, tr("Error"), ex.what());
        parent->setCursor(Qt::CursorShape::ArrowCursor);
    }
}

void QCVECheckApp::on_action_Import_SBOM_CVE_Check_Report_triggered()
{
    try
    {
        dialogImportSBOMCVEReport = new DialogImportSBOMCVEReport(this);
        QDialog::DialogCode returnValue = (QDialog::DialogCode)dialogImportSBOMCVEReport->exec();
        if (returnValue == QDialog::DialogCode::Accepted)
        {
            QString jsonReportFileName = dialogImportSBOMCVEReport->getJsonReportFileName();
            QString NVDJsonRepoPath = dialogImportSBOMCVEReport->getNVDJsonRepoPath();
            QString CVEJsonRepoPath = dialogImportSBOMCVEReport->getCVEJsonRepoPath();

            if (importSBOMCVEReportThread != nullptr)
            {
                importSBOMCVEReportThread->exit();
                delete importSBOMCVEReportThread;
                importSBOMCVEReportThread = nullptr;
            }

            importSBOMCVEReportThread = QThread::create(importSBOMCVECheckReport, this, jsonReportFileName, NVDJsonRepoPath, CVEJsonRepoPath);
            importSBOMCVEReportThread->start();
        }
    }
    catch (QException ex)
    {
        QMessageBox::critical(this, tr("Error"), ex.what());
    }

    if (dialogImportSBOMCVEReport != nullptr)
    {
        dialogImportSBOMCVEReport->close();
    }
}

void QCVECheckApp::importNVDDB(QCVECheckApp *parent, const QString& NVDDBFileName)
{
    try
    {
        parent->setCursor(Qt::CursorShape::WaitCursor);

        if (!QFile::exists(NVDDBFileName))
        {
            QMessageBox::critical(nullptr, tr("Import NVD DB Error"), tr("Not valid file name"));
            parent->setCursor(Qt::CursorShape::ArrowCursor);
            return;
        }

        if (parent->sqliteDBManager->importNVDDb(NVDDBFileName))
        {
            emit parent->importNVDDBFinished();
            QMessageBox::information(nullptr, tr("Import NVD DB"), tr("Import of NVD DB Successfully Executed"));
        }
        else
        {
            QMessageBox::critical(nullptr, tr("Import NVD DB Error"), tr("Import of NVD DB Failed"));
        }
        parent->setCursor(Qt::CursorShape::ArrowCursor);
    }
    catch (QException ex)
    {
        QMessageBox::critical(nullptr, tr("Error"), ex.what());
        parent->setCursor(Qt::CursorShape::ArrowCursor);
    }
}

void QCVECheckApp::NVDDBImported()
{
    try
    {
        if (importNVDDbThread != nullptr)
        {
            importNVDDbThread->exit();
            delete importNVDDbThread;
            importNVDDbThread = nullptr;
        }

        {
            QMutexLocker locker(subWindowMapMutex);
            for (auto& mdiReportWindow : reportMap)
            {
                mdiReportWindow->LoadReportData();
            }
        }

        {
            QMutexLocker locker(mdiCVEDataMutex);
            if (mdiCVEData)
            {
                mdiCVEData->reloadData();
            }
        }
    }
    catch (QException ex)
    {
        QMessageBox::critical(this, tr("Error"), ex.what());
    }
}

void QCVECheckApp::on_action_Import_NVD_DB_triggered()
{
    try
    {
        dialogImportNVDDB = new DialogImportNVDDB(this);
        QDialog::DialogCode returnValue = (QDialog::DialogCode)dialogImportNVDDB->exec();
        if (returnValue == QDialog::DialogCode::Accepted)
        {
            QString NVDDBFileName = dialogImportNVDDB->getNVDDbFileName();

            if (importNVDDbThread != nullptr)
            {
                importNVDDbThread->exit();
                delete importNVDDbThread;
                importNVDDbThread = nullptr;
            }

            importNVDDbThread = QThread::create(importNVDDB, this, NVDDBFileName);
            importNVDDbThread->start();
        }
    }
    catch (QException ex)
    {
        QMessageBox::critical(this, tr("Error"), ex.what());
    }

    if (dialogImportNVDDB != nullptr)
    {
        dialogImportNVDDB->close();
    }
}

void QCVECheckApp::importNVDJsonRepo(QCVECheckApp *parent, const QString& NVDJsonRepoPath)
{
    try
    {
        parent->setCursor(Qt::CursorShape::WaitCursor);

        if (!QFile::exists(NVDJsonRepoPath))
        {
            QMessageBox::critical(nullptr, tr("Import NVD Json Repository Error"), tr("Not valid NVD Json Repository Path"));
            parent->setCursor(Qt::CursorShape::ArrowCursor);
            return;
        }

        if (parent->sqliteDBManager->importNVDJsonRepo(NVDJsonRepoPath))
        {
            emit parent->importNVDJsonRepoFinished();
            QMessageBox::information(nullptr, tr("Import NVD DB"), tr("Import of NVD Json Repository Successfully Executed"));
        }
        else
        {
            QMessageBox::critical(nullptr, tr("Import NVD DB Error"), tr("Import of NVD Json Repository Failed"));
        }
        parent->setCursor(Qt::CursorShape::ArrowCursor);
    }
    catch (QException ex)
    {
        QMessageBox::critical(nullptr, tr("Error"), ex.what());
        parent->setCursor(Qt::CursorShape::ArrowCursor);
    }
}

void QCVECheckApp::NVDJsonRepoImported()
{
    try
    {
        if (importNVDJsonRepoThread != nullptr)
        {
            importNVDJsonRepoThread->exit();
            delete importNVDJsonRepoThread;
            importNVDJsonRepoThread = nullptr;
        }

        {
            QMutexLocker locker(subWindowMapMutex);
            for (auto& mdiReportWindow : reportMap)
            {
                mdiReportWindow->LoadReportData();
            }
        }

        {
            QMutexLocker locker(mdiCVEDataMutex);
            if (mdiCVEData)
            {
                mdiCVEData->reloadData();
            }
        }
    }
    catch (QException ex)
    {
        QMessageBox::critical(this, tr("Error"), ex.what());
    }
}

void QCVECheckApp::on_action_Import_NVD_Json_Repo_triggered()
{
    try
    {
        dialogImportNVDJsonRepo = new DialogImportNVDJsonRepo(this);
        QDialog::DialogCode returnValue = (QDialog::DialogCode)dialogImportNVDJsonRepo->exec();
        if (returnValue == QDialog::DialogCode::Accepted)
        {
            QString NVDJsonRepoPath = dialogImportNVDJsonRepo->getNVDJsonRepoPath();

            if (importNVDJsonRepoThread != nullptr)
            {
                importNVDJsonRepoThread->exit();
                delete importNVDJsonRepoThread;
                importNVDJsonRepoThread = nullptr;
            }

            importNVDJsonRepoThread = QThread::create(importNVDJsonRepo, this, NVDJsonRepoPath);
            importNVDJsonRepoThread->start();
        }
    }
    catch (QException ex)
    {
        QMessageBox::critical(this, tr("Error"), ex.what());
    }

    if (dialogImportNVDJsonRepo != nullptr)
    {
        dialogImportNVDJsonRepo->close();
    }
}

void QCVECheckApp::importCVEJsonRepo(QCVECheckApp *parent, const QString& CVEJsonRepoPath)
{
    try
    {
        parent->setCursor(Qt::CursorShape::WaitCursor);

        if (!QFile::exists(CVEJsonRepoPath))
        {
            QMessageBox::critical(nullptr, tr("Import NVD Json Repository Error"), tr("Not valid NVD Json Repository Path"));
            parent->setCursor(Qt::CursorShape::ArrowCursor);
            return;
        }

        if (parent->sqliteDBManager->importCVEJsonRepo(CVEJsonRepoPath))
        {
            emit parent->importNVDJsonRepoFinished();
            QMessageBox::information(nullptr, tr("Import NVD DB"), tr("Import of NVD Json Repository Successfully Executed"));
        }
        else
        {
            QMessageBox::critical(nullptr, tr("Import NVD DB Error"), tr("Import of NVD Json Repository Failed"));
        }
        parent->setCursor(Qt::CursorShape::ArrowCursor);
    }
    catch (QException ex)
    {
        QMessageBox::critical(nullptr, tr("Error"), ex.what());
        parent->setCursor(Qt::CursorShape::ArrowCursor);
    }
}

void QCVECheckApp::CVEJsonRepoImported()
{
    try
    {
        if (importCVEJsonRepoThread != nullptr)
        {
            importCVEJsonRepoThread->exit();
            delete importCVEJsonRepoThread;
            importCVEJsonRepoThread = nullptr;
        }

        {
            QMutexLocker locker(subWindowMapMutex);
            for (auto& mdiReportWindow : reportMap)
            {
                mdiReportWindow->LoadReportData();
            }
        }

        {
            QMutexLocker locker(mdiCVEDataMutex);
            if (mdiCVEData)
            {
                mdiCVEData->reloadData();
            }
        }
    }
    catch (QException ex)
    {
        QMessageBox::critical(this, tr("Error"), ex.what());
    }
}
void QCVECheckApp::on_action_Import_CVE_Json_Repo_triggered()
{
    try
    {
        dialogImportCVEJsonRepo = new DialogImportCVEJsonRepo(this);
        QDialog::DialogCode returnValue = (QDialog::DialogCode)dialogImportCVEJsonRepo->exec();
        if (returnValue == QDialog::DialogCode::Accepted)
        {
            QString CVEJsonRepoPath = dialogImportCVEJsonRepo->getCVEJsonRepoPath();

            if (importCVEJsonRepoThread != nullptr)
            {
                importCVEJsonRepoThread->exit();
                delete importCVEJsonRepoThread;
                importCVEJsonRepoThread = nullptr;
            }

            importCVEJsonRepoThread = QThread::create(importCVEJsonRepo, this, CVEJsonRepoPath);
            importCVEJsonRepoThread->start();
        }
    }
    catch (QException ex)
    {
        QMessageBox::critical(this, tr("Error"), ex.what());
    }

    if (dialogImportCVEJsonRepo != nullptr)
    {
        dialogImportCVEJsonRepo->close();
    }
}

void QCVECheckApp::on_action_Exit_triggered()
{
    QApplication::exit();
}

void QCVECheckApp::OpenCVEReportWindow(const QString& reportName)
{
    QMutexLocker locker(subWindowMapMutex);
    if (!reportName.isNull() && !reportName.isEmpty())
    {
        if (reportMap.contains(reportName))
        {
            MdiReport* mdiReportWindow = (MdiReport*) reportMap.value(reportName);
            if (ui->mdiArea->subWindowList().contains(mdiReportWindow))
            {
                mdiReportWindow->show();
            }
            else
            {
                ui->mdiArea->addSubWindow(mdiReportWindow);
                mdiReportWindow->show();
            }
        }
        else
        {
            MdiReport* mdiReportWindow = new MdiReport(reportName, sqliteDBManager, this);
            reportMap.insert(reportName, mdiReportWindow);
            ui->mdiArea->addSubWindow(mdiReportWindow);
            mdiReportWindow->show();
        }
    }
}

void QCVECheckApp::on_comboBoxReports_currentIndexChanged(int index)
{
    QString reportName = ui->comboBoxReports->itemText(index);
    OpenCVEReportWindow(reportName);
}

void QCVECheckApp::on_pushButtonOpen_clicked()
{
    QString reportName = ui->comboBoxReports->currentText();
    OpenCVEReportWindow(reportName);
}


void QCVECheckApp::on_pushButtonGeneral_clicked()
{
    QMutexLocker locker(subWindowMapMutex);
    if (reportMap.contains(ui->comboBoxReports->currentText()))
        reportMap.value(ui->comboBoxReports->currentText())->scrollToGroupBox(MdiReport::GroupBoxEnum::General);
}


void QCVECheckApp::on_pushButtonSummary_clicked()
{
    QMutexLocker locker(subWindowMapMutex);
    if (reportMap.contains(ui->comboBoxReports->currentText()))
        reportMap.value(ui->comboBoxReports->currentText())->scrollToGroupBox(MdiReport::GroupBoxEnum::Summary);
}


void QCVECheckApp::on_pushButtonPackages_clicked()
{
    QMutexLocker locker(subWindowMapMutex);
    if (reportMap.contains(ui->comboBoxReports->currentText()))
        reportMap.value(ui->comboBoxReports->currentText())->scrollToGroupBox(MdiReport::GroupBoxEnum::Packages);
}


void QCVECheckApp::on_pushButtonCVEs_clicked()
{
    QMutexLocker locker(subWindowMapMutex);
    if (reportMap.contains(ui->comboBoxReports->currentText()))
        reportMap.value(ui->comboBoxReports->currentText())->scrollToGroupBox(MdiReport::GroupBoxEnum::CVEs);
}


void QCVECheckApp::on_pushButtonIgnoredCVEs_clicked()
{
    QMutexLocker locker(subWindowMapMutex);
    if (reportMap.contains(ui->comboBoxReports->currentText()))
        reportMap.value(ui->comboBoxReports->currentText())->scrollToGroupBox(MdiReport::GroupBoxEnum::IgnoredCVEs);
}

void QCVECheckApp::on_pushButtonCVEData_clicked()
{
    QMutexLocker locker(mdiCVEDataMutex);
    if (!mdiCVEData)
    {
        mdiCVEData = new MdiCVEData(sqliteDBManager, this);
        ui->mdiArea->addSubWindow(mdiCVEData);
        mdiCVEData->show();
    }
    else
    {
        mdiCVEData->reloadData();
    }
    mdiCVEData->show();
}

void QCVECheckApp::on_pushButtonExportReport_clicked()
{
    QMutexLocker locker(subWindowMapMutex);
    QString reportName = ui->comboBoxReports->currentText();
    if (!reportName.isNull() && !reportName.isEmpty())
    {
        MdiPDFReport* mdiPdfReport;
        if (pdfReportsMap.contains(reportName))
        {
            mdiPdfReport = (MdiPDFReport*) pdfReportsMap.value(reportName);
            if (ui->mdiArea->subWindowList().contains(mdiPdfReport))
            {
                mdiPdfReport->show();
            }
            else
            {
                ui->mdiArea->addSubWindow(mdiPdfReport);
                mdiPdfReport->show();
            }
        }
        else
        {
            mdiPdfReport = new MdiPDFReport(reportName, sqliteDBManager, this);
            pdfReportsMap.insert(reportName, mdiPdfReport);
            ui->mdiArea->addSubWindow(mdiPdfReport);
            mdiPdfReport->show();
        }
        mdiPdfReport->LoadReportData();
    }
}


void QCVECheckApp::on_action_About_QCVECheckReport_triggered()
{
    QMessageBox::aboutQt(this);
}

