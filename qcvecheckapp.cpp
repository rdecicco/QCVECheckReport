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
#include "./ui_qcvecheckapp.h"
#include "dialogimportcvedb.h"
#include "mdicvedata.h"
#include "mdisubwindow.h"
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
#include <PDFWriter.h>

QCVECheckApp::QCVECheckApp(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::QCVECheckApp), sqliteDBManager(new QSQLiteManager(this)), mdiCVEDataMutex(new QMutex()), subWindowMapMutex(new QMutex())
{
    ui->setupUi(this);
    UpdateCVEReportsComboBox();
    connect(this, SIGNAL(importJsonCVEReportFinished(QString)), this, SLOT(jsonCVEReportImported(QString)), Qt::QueuedConnection);
    connect(this, SIGNAL(importCVEDBFinished()), this, SLOT(CVEDBImported()), Qt::QueuedConnection);
}

QCVECheckApp::~QCVECheckApp()
{
    disconnect(this, SIGNAL(importJsonCVEReportFinished(QString)), this, SLOT(jsonCVEReportImported(QString)));
    disconnect(this, SIGNAL(importCVEDBFinished()), this, SLOT(CVEDBImported()));
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

void QCVECheckApp::importCVEReport(QCVECheckApp* parent, const QString& jsonReportFileName, const QString& CVEDBFileName)
{
    try
    {
        parent->setCursor(Qt::CursorShape::WaitCursor);

        if (!QFile::exists(CVEDBFileName) || !QFile::exists(jsonReportFileName))
        {
            QMessageBox::critical(nullptr, tr("Open Json Report Error"), tr("Not valid file name"));
            return;
        }

        if (!parent->sqliteDBManager->isNewReport(jsonReportFileName))
        {
            QMessageBox::critical(nullptr, tr("Import Json Report Error"), tr("Report already imported"));
            return;
        }

        if (!parent->sqliteDBManager->importCVEDb(CVEDBFileName))
        {
            QMessageBox::critical(nullptr, tr("Import CVE DB Error"), tr("Import of CVE DB Failed"));
            return;
        }

        if (!parent->jsonCVEReportManager.open(jsonReportFileName))
        {
            QMessageBox::critical(nullptr, tr("Open Json Report Error"), tr("Not valid CVE Report"));
            return;
        }

        if (!parent->sqliteDBManager->importJson(jsonReportFileName, parent->jsonCVEReportManager.getJsonDocument()))
        {
            QMessageBox::critical(nullptr, tr("Import Json Report Error"), tr("Import of CSV Report Failed"));
            return;
        }

        emit parent->importJsonCVEReportFinished(jsonReportFileName);
        QMessageBox::information(nullptr, tr("Import Json Report"), tr("Import of CSV Report Successfully Executed"));
    }
    catch (QException ex)
    {
        QMessageBox::critical(nullptr, tr("Error"), ex.what());
    }
}

void QCVECheckApp::jsonCVEReportImported(const QString &jsonReportFileName)
{
    try
    {
        setCursor(Qt::CursorShape::ArrowCursor);

        UpdateCVEReportsComboBox();
        ui->comboBoxReports->setCurrentIndex(jsonCVEReportsList.indexOf(QFileInfo(jsonReportFileName).fileName()));

        {
            QMutexLocker locker(subWindowMapMutex);
            for (auto& mdiWindow : subWindowsMap)
            {
                mdiWindow->LoadReportData();
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

void QCVECheckApp::on_action_Open_triggered()
{
    try
    {
        dialogImportCVEReport = new DialogImportCVEReport(this);
        QDialog::DialogCode returnValue = (QDialog::DialogCode)dialogImportCVEReport->exec();
        if (returnValue == QDialog::DialogCode::Accepted)
        {
            QString CVEDBFileName = dialogImportCVEReport->getCVEDbFileName();
            QString jsonReportFileName = dialogImportCVEReport->getJsonReportFileName();

            if (importCVEReportThread != nullptr)
            {
                importCVEReportThread->exit();
                delete importCVEReportThread;
                importCVEReportThread = nullptr;
            }

            importCVEReportThread = QThread::create(importCVEReport, this, jsonReportFileName, CVEDBFileName);
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

void QCVECheckApp::importCVEDB(QCVECheckApp *parent, const QString& CVEDBFileName)
{
    try
    {
        parent->setCursor(Qt::CursorShape::WaitCursor);

        if (!QFile::exists(CVEDBFileName))
        {
            QMessageBox::critical(nullptr, tr("Import CVE DB Error"), tr("Not valid file name"));
            return;
        }

        if (parent->sqliteDBManager->importCVEDb(CVEDBFileName))
        {
            emit parent->importCVEDBFinished();
            QMessageBox::information(nullptr, tr("Import CVE DB"), tr("Import of CVE DB Successfully Executed"));
        }
        else
        {
            QMessageBox::critical(nullptr, tr("Import CVE DB Error"), tr("Import of CVE DB Failed"));
        }        
    }
    catch (QException ex)
    {
        QMessageBox::critical(nullptr, tr("Error"), ex.what());
    }
}

void QCVECheckApp::CVEDBImported()
{
    try
    {
        setCursor(Qt::CursorShape::ArrowCursor);

        if (importCVEDbThread != nullptr)
        {
            importCVEDbThread->exit();
            delete importCVEDbThread;
            importCVEDbThread = nullptr;
        }

        {
            QMutexLocker locker(subWindowMapMutex);
            for (auto& mdiWindow : subWindowsMap)
            {
                mdiWindow->LoadReportData();
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

void QCVECheckApp::on_actionImport_CVE_DB_triggered()
{
    try
    {
        dialogImportCVEDB = new DialogImportCVEDB(this);
        QDialog::DialogCode returnValue = (QDialog::DialogCode)dialogImportCVEDB->exec();
        if (returnValue == QDialog::DialogCode::Accepted)
        {
            QString CVEDBFileName = dialogImportCVEDB->getCVEDbFileName();

            if (importCVEDbThread != nullptr)
            {
                importCVEDbThread->exit();
                delete importCVEDbThread;
                importCVEDbThread = nullptr;
            }

            importCVEDbThread = QThread::create(importCVEDB, this, CVEDBFileName);
            importCVEDbThread->start();
        }
    }
    catch (QException ex)
    {
        QMessageBox::critical(this, tr("Error"), ex.what());
    }

    if (dialogImportCVEDB != nullptr)
    {
        dialogImportCVEDB->close();
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
        if (subWindowsMap.contains(reportName))
        {
            MdiSubWindow* mdiSubWindow = (MdiSubWindow*) subWindowsMap.value(reportName);
            if (ui->mdiArea->subWindowList().contains(mdiSubWindow))
            {
                mdiSubWindow->show();
            }
            else
            {
                ui->mdiArea->addSubWindow(mdiSubWindow);
                mdiSubWindow->show();
            }
        }
        else
        {
            MdiSubWindow* mdiSubWindow = new MdiSubWindow(reportName, sqliteDBManager, this);
            subWindowsMap.insert(reportName, mdiSubWindow);
            ui->mdiArea->addSubWindow(mdiSubWindow);
            mdiSubWindow->show();
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
    if (subWindowsMap.contains(ui->comboBoxReports->currentText()))
        subWindowsMap.value(ui->comboBoxReports->currentText())->scrollToGroupBox(MdiSubWindow::GroupBoxEnum::General);
}


void QCVECheckApp::on_pushButtonSummary_clicked()
{
    QMutexLocker locker(subWindowMapMutex);
    if (subWindowsMap.contains(ui->comboBoxReports->currentText()))
        subWindowsMap.value(ui->comboBoxReports->currentText())->scrollToGroupBox(MdiSubWindow::GroupBoxEnum::Summary);
}


void QCVECheckApp::on_pushButtonPackages_clicked()
{
    QMutexLocker locker(subWindowMapMutex);
    if (subWindowsMap.contains(ui->comboBoxReports->currentText()))
        subWindowsMap.value(ui->comboBoxReports->currentText())->scrollToGroupBox(MdiSubWindow::GroupBoxEnum::Packages);
}


void QCVECheckApp::on_pushButtonCVEs_clicked()
{
    QMutexLocker locker(subWindowMapMutex);
    if (subWindowsMap.contains(ui->comboBoxReports->currentText()))
        subWindowsMap.value(ui->comboBoxReports->currentText())->scrollToGroupBox(MdiSubWindow::GroupBoxEnum::CVEs);
}


void QCVECheckApp::on_pushButtonIgnoredCVEs_clicked()
{
    QMutexLocker locker(subWindowMapMutex);
    if (subWindowsMap.contains(ui->comboBoxReports->currentText()))
        subWindowsMap.value(ui->comboBoxReports->currentText())->scrollToGroupBox(MdiSubWindow::GroupBoxEnum::IgnoredCVEs);
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


void QCVECheckApp::on_actionAbout_QCVECheckReport_triggered()
{
    QMessageBox::aboutQt(this);
}

