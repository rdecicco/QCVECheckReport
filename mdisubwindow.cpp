/*!
   QCVECheckReport project

   @file: mdisubwindow.cpp

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

#include "mdisubwindow.h"
#include "ui_mdisubwindow.h"
#include <QResizeEvent>
#include <QScrollBar>
#include <QThread>

#define PackagesPackageIDColumnIndex 0
#define PackagesPackageNameColumnIndex 1
#define PackagesPackageLayerColumnIndex 2
#define PackagesPackageVersionColumnIndex 3
#define PacakgesPackageCVEReportIDColumnIndex 4
#define PackagesCriticalColumnIndex 5
#define PackagesHighColumnIndex 6
#define PackagesMediumColumnIndex 7
#define PackagesLowColumnIndex 8
#define PackagesUnpatchedColumnIndex 9
#define PackagesPatchedColumnIndex 10
#define PackagesIgnoredColumnIndex 11
#define CVEsPackageIDColumnIndex 0
#define CVEsPackageNameColumnIndex 1
#define CVEsPackageLayerColumnIndex 2
#define CVEsPackageVersionColumnIndex 3
#define CVEsIssueIDColumnIndex 4
#define CVEsIssueStatusColumnIndex 5
#define CVEsIssueNVDIDColumnIndex 6
#define CVEsNVDCVSS3ScoreColumnIndex 7
#define CVEsNVDVectorColumnIndex 8
#define CVEsLinkColumnIndex 9
#define IgnoredCVEsPackageIDColumnIndex 0
#define IgnoredCVEsPackageNameColumnIndex 1
#define IgnoredCVEsPackageLayerColumnIndex 2
#define IgnoredCVEsPackageVersionColumnIndex 3
#define IgnoredCVEsIssueIDColumnIndex 4
#define IgnoredCVEsIssueStatusColumnIndex 5
#define IgnoredCVEsIssueNVDIDColumnIndex 6
#define IgnoredCVEsNVDCVSS3ScoreColumnIndex 7
#define IgnoredCVEsNVDVectorColumnIndex 8
#define IgnoredCVEsLinkColumnIndex 9

#define NameWidth 180
#define LayerWidth 180
#define VersionWidth 220
#define StatusWidth 120
#define NVDIDWidth 150
#define CVSS3ScoreWidth 100
#define VectorWidth 180

MdiSubWindow::MdiSubWindow(const QString &fileName, QSQLiteManager* sqlManager, QWidget *parent):
    QMdiSubWindow(parent), reportFile(fileName), sqliteManager(sqlManager),
    packagesTableMutex(new QMutex()), cvesTableMutex(new QMutex()), ignoredCVEsTableMutex(new QMutex()),
    ui(new Ui::MdiSubWindow)
{
    ui->setupUi(this);

    ui->spinBoxPackagesPage->setMinimum(1);
    ui->comboBoxShowPackages->addItem(tr("10"), 10);
    ui->comboBoxShowPackages->addItem(tr("20"), 20);
    ui->comboBoxShowPackages->addItem(tr("50"), 50);
    ui->comboBoxShowPackages->addItem(tr("100"), 100);
    ui->comboBoxShowPackages->addItem(tr("250"), 250);
    ui->comboBoxShowPackages->setCurrentIndex(4);

    ui->spinBoxCVEsPage->setMinimum(1);
    ui->comboBoxShowCVEs->addItem(tr("10"), 10);
    ui->comboBoxShowCVEs->addItem(tr("20"), 20);
    ui->comboBoxShowCVEs->addItem(tr("50"), 50);
    ui->comboBoxShowCVEs->addItem(tr("100"), 100);
    ui->comboBoxShowCVEs->addItem(tr("250"), 250);
    ui->comboBoxShowCVEs->setCurrentIndex(4);

    ui->comboBoxCVEsStatus->addItem(tr("All"), "");
    ui->comboBoxCVEsStatus->addItem(tr("Patched"), "Patched");
    ui->comboBoxCVEsStatus->addItem(tr("Unpatched"), "Unpatched");
    ui->comboBoxCVEsStatus->addItem(tr("Ignored"), "Ignored");

    ui->comboBoxCVEsAttackVector->addItem(tr("All"), "");
    ui->comboBoxCVEsAttackVector->addItem(tr("Unknown"), "UNKNOWN");
    ui->comboBoxCVEsAttackVector->addItem(tr("Local"), "LOCAL");
    ui->comboBoxCVEsAttackVector->addItem(tr("Network"), "NETWORK");
    ui->comboBoxCVEsAttackVector->addItem(tr("Adjacent Network"), "ADJACENT_NETWORK");
    ui->comboBoxCVEsAttackVector->addItem(tr("Physical"), "PHYSICAL");

    ui->comboBoxCVEsMinimumCVSS->addItem(tr("None"), 0.0);
    ui->comboBoxCVEsMinimumCVSS->addItem(tr("Low"), 0.1);
    ui->comboBoxCVEsMinimumCVSS->addItem(tr("Medium"), 4.0);
    ui->comboBoxCVEsMinimumCVSS->addItem(tr("High"), 7.0);
    ui->comboBoxCVEsMinimumCVSS->addItem(tr("Critical"), 9.0);

    ui->spinBoxIgnoredCVEsPage->setMinimum(1);
    ui->comboBoxShowIgnoredCVEs->addItem(tr("10"), 10);
    ui->comboBoxShowIgnoredCVEs->addItem(tr("20"), 20);
    ui->comboBoxShowIgnoredCVEs->addItem(tr("50"), 50);
    ui->comboBoxShowIgnoredCVEs->addItem(tr("100"), 100);
    ui->comboBoxShowIgnoredCVEs->addItem(tr("250"), 250);
    ui->comboBoxShowIgnoredCVEs->setCurrentIndex(4);

    LoadReportData();
    setComboBoxCVEPackages();
}

MdiSubWindow::~MdiSubWindow()
{
    disconnect(SIGNAL(packagesTableViewDataUpdated(QModelIndex,QModelIndex)), this, SLOT(refreshPackagesTableView(QModelIndex,QModelIndex)));
    disconnect(SIGNAL(cvesTableViewDataUpdated(QModelIndex,QModelIndex)), this, SLOT(refreshCVEsTableView(QModelIndex,QModelIndex)));
    disconnect(cvesTableView, SIGNAL(clicked(QModelIndex)), this, SLOT(cvesTableViewClicked(QModelIndex)));
    disconnect(this, SIGNAL(ignoredCVEsTableViewDataUpdated(QModelIndex,QModelIndex)), this, SLOT(refreshIgnoredCVEsTableView(QModelIndex,QModelIndex)));
    disconnect(ignoredCVEsTableView, SIGNAL(clicked(QModelIndex)), this, SLOT(ignoredCVEsTableViewClicked(QModelIndex)));
    delete ui;
    delete packagesTableMutex;
    delete cvesTableMutex;
    delete ignoredCVEsTableMutex;
}

void MdiSubWindow::scrollToGroupBox(GroupBoxEnum groupBox)
{
    switch (groupBox)
    {
    case GroupBoxEnum::General:
        ui->scrollArea->verticalScrollBar()->setValue(ui->groupBoxGeneralInformation->y());
        break;
    case GroupBoxEnum::Summary:
        ui->scrollArea->verticalScrollBar()->setValue(ui->groupBoxSummary->y());
        break;
    case GroupBoxEnum::Packages:
        ui->scrollArea->verticalScrollBar()->setValue(ui->groupBoxPackages->y());
        break;
    case GroupBoxEnum::CVEs:
        ui->scrollArea->verticalScrollBar()->setValue(ui->groupBoxCVEs->y());
        break;
    case GroupBoxEnum::IgnoredCVEs:
        ui->scrollArea->verticalScrollBar()->setValue(ui->groupBoxIgnoredCVEs->y());
        break;
    }
}

void MdiSubWindow::resizeEvent(QResizeEvent *ev)
{
    ui->scrollArea->move(10,40);
    ui->scrollArea->resize(ev->size() - QSize(20, 60));
    if (ui->tableWidgetPackages->model() && ui->tableWidgetPackages->model()->columnCount())
    {
        ui->tableWidgetPackages->horizontalHeader()->setDefaultSectionSize(ui->tableWidgetPackages->width()  / ui->tableWidgetPackages->model()->columnCount() - 2);
    }
    if (ui->tableWidgetCVEs->model() && ui->tableWidgetCVEs->model()->columnCount())
    {
        ui->tableWidgetCVEs->horizontalHeader()->setDefaultSectionSize(ui->tableWidgetCVEs->width()  / ui->tableWidgetCVEs->model()->columnCount());
    }
    if (ui->tableWidgetIgnoredCVEs->model() && ui->tableWidgetIgnoredCVEs->model()->columnCount())
    {
        ui->tableWidgetIgnoredCVEs->horizontalHeader()->setDefaultSectionSize(ui->tableWidgetIgnoredCVEs->width()  / ui->tableWidgetIgnoredCVEs->model()->columnCount());
    }
    resizeAllTables();
}

void MdiSubWindow::resizeAllTables()
{
    resizePackagesTableView();
    resizeCVEsTableView();
    resizeIgnoredCVEsTableView();
}

void MdiSubWindow::resizePackagesTableView()
{
    if (packagesTableView && packagesTableView->getModel() && packagesTableView->getModel()->columnCount())
    {
        int columnCount = packagesTableView->getModel()->columnCount();
        packagesTableView->horizontalHeader()->setDefaultSectionSize(packagesTableView->width()  / (columnCount - 2) - 2);
        packagesTableView->horizontalHeader()->setDefaultAlignment(Qt::AlignCenter);
        int widths[PackagesCriticalColumnIndex] = { 0, NameWidth, LayerWidth, VersionWidth, 0 };
        for (int i = PackagesPackageIDColumnIndex; i < PackagesCriticalColumnIndex; i++)
        {
            packagesTableView->horizontalHeader()->setSectionResizeMode(i, QHeaderView::ResizeToContents);
        }
        for (int i = PackagesCriticalColumnIndex; i < columnCount; i++)
        {
            packagesTableView->horizontalHeader()->setSectionResizeMode(i, QHeaderView::Stretch);
        }
    }
}

void MdiSubWindow::resizeCVEsTableView()
{
    if (cvesTableView && cvesTableView->getModel() && cvesTableView->getModel()->columnCount())
    {
        int columnCount = cvesTableView->getModel()->columnCount();
        cvesTableView->horizontalHeader()->setDefaultSectionSize(cvesTableView->width() / (columnCount - 2) - 2);
        cvesTableView->horizontalHeader()->setDefaultAlignment(Qt::AlignCenter);
        int widths[CVEsLinkColumnIndex] = { 0, NameWidth, LayerWidth, VersionWidth, 0, StatusWidth, NVDIDWidth, CVSS3ScoreWidth, VectorWidth};
        for (int i = 0; i < CVEsLinkColumnIndex; i++)
        {
            cvesTableView->setColumnWidth(i, widths[i]);
        }
        cvesTableView->horizontalHeader()->setStretchLastSection(true);
    }
}

void MdiSubWindow::resizeIgnoredCVEsTableView()
{
    if (ignoredCVEsTableView && ignoredCVEsTableView->getModel() && ignoredCVEsTableView->getModel()->columnCount())
    {
        int columnCount = ignoredCVEsTableView->getModel()->columnCount();
        ignoredCVEsTableView->horizontalHeader()->setDefaultSectionSize(ignoredCVEsTableView->width()  / (columnCount - 2) - 2);
        ignoredCVEsTableView->horizontalHeader()->setDefaultAlignment(Qt::AlignCenter);
        int widths[IgnoredCVEsLinkColumnIndex] = { 0, NameWidth, LayerWidth, VersionWidth, 0, StatusWidth, NVDIDWidth, CVSS3ScoreWidth, VectorWidth};
        for (int i = 0; i < IgnoredCVEsLinkColumnIndex; i++)
        {
            ignoredCVEsTableView->setColumnWidth(i, widths[i]);
        }
        ignoredCVEsTableView->horizontalHeader()->setStretchLastSection(true);
    }
}

bool MdiSubWindow::packagesKeysComparison(const AbstractDTO::SharedDTO &package1, const AbstractDTO::SharedDTO &package2)
{
    const PackageDTO* packageDTO1 = static_cast<const PackageDTO*>(package1.get());
    const PackageDTO* packageDTO2 = static_cast<const PackageDTO*>(package2.get());
    if (packageDTO1 && packageDTO2)
    {
        return packageDTO1->getName() < packageDTO2->getName();
    }
    else if (packageDTO1)
    {
        return false;
    }
    else if (packageDTO2)
    {
        return true;
    }

    return false;
}

void MdiSubWindow::setComboBoxCVEPackages()
{
    ui->comboBoxCVEsPackages->addItem("All", 0);
    const CVEReportDTO& reportDTO = reportData->getFullCVEReport();
    auto packages = reportDTO.getPackages().values();
    std::sort(packages.begin(), packages.end(), packagesKeysComparison);
    for (auto& package : packages)
    {
        const PackageDTO* packageDTO = static_cast<const PackageDTO*>(package.get());
        if (packageDTO)
        {
            const PackageDTO::PackageKey* key = static_cast<const PackageDTO::PackageKey*>(packageDTO->getKey().get());
            if (key)
                ui->comboBoxCVEsPackages->addItem(packageDTO->getName(), key->getID());
        }
    }
}

void MdiSubWindow::LoadReportData()
{
    try
    {
        reportData = QSharedPointer<ReportData>::create(reportFile, sqliteManager, this);
        if (!reportData.isNull())
        {
            const CVEReportDTO& reportDTO = reportData->getFullCVEReport();
            setWindowTitle(reportDTO.getFileName());
            ui->fileNameLineEdit->setText(reportDTO.getFileName());
            ui->dateLineEdit->setText(reportDTO.getDate().toString());
            ui->ownerLineEdit->setText(reportDTO.getOwner());

            ReportData::Summary summary = reportData->getSummary();
            ui->patchedLineEdit->setText(QString("%1").arg(summary.packagesWithKnowenCVS.Patched));
            ui->unpatchedLineEdit->setText(QString("%1").arg(summary.packagesWithKnowenCVS.Unpatched));
            ui->ignoredLineEdit->setText(QString("%1").arg(summary.packagesWithKnowenCVS.Ignored));
            ui->highCriticalLineEdit->setText(QString("%1").arg((summary.unpatchedCVEBySeverity.High + summary.unpatchedCVEBySeverity.Critical)));

            if (unpatchedCVEBySeveritySeries && unpatchedCVEBySeverityChart) {
                ui->groupBoxUnpatchedCVEsBySeverity->layout()->removeWidget(unpatchedCVEBySeverityChart);
                unpatchedCVEBySeverityChart->chart()->removeAllSeries();
            }

            unpatchedCVEBySeveritySeries = new QPieSeries(this);
            unpatchedCVEBySeveritySeries->setHoleSize(0.35);
            unpatchedCVEBySeveritySeries->append(QString("None (%1)").arg(summary.unpatchedCVEBySeverity.None), summary.unpatchedCVEBySeverity.None);
            unpatchedCVEBySeveritySeries->append(QString("Low (%1)").arg(summary.unpatchedCVEBySeverity.Low), summary.unpatchedCVEBySeverity.Low);
            unpatchedCVEBySeveritySeries->append(QString("Medium (%1)").arg(summary.unpatchedCVEBySeverity.Medium), summary.unpatchedCVEBySeverity.Medium);
            unpatchedCVEBySeveritySeries->append(QString("High (%1)").arg(summary.unpatchedCVEBySeverity.High), summary.unpatchedCVEBySeverity.High);
            unpatchedCVEBySeveritySeries->append(QString("Critical (%1)").arg(summary.unpatchedCVEBySeverity.Critical), summary.unpatchedCVEBySeverity.Critical);
            unpatchedCVEBySeveritySeries->setLabelsPosition(QPieSlice::LabelOutside);
            unpatchedCVEBySeveritySeries->setLabelsVisible(false);

            unpatchedCVEBySeverityChart = new QChartView(this);
            unpatchedCVEBySeverityChart->setRenderHint(QPainter::Antialiasing);
            unpatchedCVEBySeverityChart->chart()->addSeries(unpatchedCVEBySeveritySeries);
            unpatchedCVEBySeverityChart->chart()->legend()->setAlignment(Qt::AlignRight);
            unpatchedCVEBySeverityChart->chart()->setTheme(QChart::ChartThemeDark);
            unpatchedCVEBySeverityChart->chart()->legend()->setFont(QFont("Arial", 10));
            unpatchedCVEBySeverityChart->chart()->legend()->setVisible(true);

            ui->groupBoxUnpatchedCVEsBySeverity->layout()->addWidget(unpatchedCVEBySeverityChart);
            unpatchedCVEBySeverityChart->show();

            if (packagesWithKnowenCVEsSeries && packagesWithKnowenCVEsChart) {
                ui->groupBoxPackagesWithKnowenCVE->layout()->removeWidget(packagesWithKnowenCVEsChart);
                packagesWithKnowenCVEsChart->chart()->removeAllSeries();
            }

            packagesWithKnowenCVEsSeries = new QPieSeries(this);
            packagesWithKnowenCVEsSeries->setHoleSize(0.35);
            packagesWithKnowenCVEsSeries->append(QString("Patched (%1)").arg(summary.packagesWithKnowenCVS.Patched), summary.packagesWithKnowenCVS.Patched);
            packagesWithKnowenCVEsSeries->append(QString("Unpatched (%1)").arg(summary.packagesWithKnowenCVS.Unpatched), summary.packagesWithKnowenCVS.Unpatched);
            packagesWithKnowenCVEsSeries->append(QString("Ignored (%1)").arg(summary.packagesWithKnowenCVS.Ignored), summary.packagesWithKnowenCVS.Ignored);
            packagesWithKnowenCVEsSeries->setLabelsPosition(QPieSlice::LabelOutside);
            packagesWithKnowenCVEsSeries->setLabelsVisible(false);

            packagesWithKnowenCVEsChart = new QChartView(this);
            packagesWithKnowenCVEsChart->setRenderHint(QPainter::Antialiasing);
            packagesWithKnowenCVEsChart->chart()->addSeries(packagesWithKnowenCVEsSeries);
            packagesWithKnowenCVEsChart->chart()->legend()->setAlignment(Qt::AlignRight);
            packagesWithKnowenCVEsChart->chart()->setTheme(QChart::ChartThemeDark);
            packagesWithKnowenCVEsChart->chart()->legend()->setFont(QFont("Arial", 10));
            packagesWithKnowenCVEsChart->chart()->legend()->setVisible(true);

            ui->groupBoxPackagesWithKnowenCVE->layout()->addWidget(packagesWithKnowenCVEsChart);
            packagesWithKnowenCVEsChart->show();

            {
                QMutexLocker locker(packagesTableMutex);
                if (!packagesTableView)
                {
                    packagesTableView = new QSqlTableView(reportData->getPackages(), this);
                    connect(this, SIGNAL(packagesTableViewDataUpdated(QModelIndex,QModelIndex)), this, SLOT(refreshPackagesTableView(QModelIndex,QModelIndex)));
                    packagesTableView->setFocusPolicy(Qt::NoFocus);
                    packagesTableView->setSelectionBehavior(QTableView::SelectionBehavior::SelectRows);
                    packagesTableView->setSelectionMode(QTableView::NoSelection);
                    ui->groupBoxPackages->layout()->replaceWidget(ui->tableWidgetPackages, packagesTableView);
                    packagesTableView->verticalHeader()->show();
                    ui->tableWidgetPackages->hide();
                    packagesTableView->show();
                }
            }

            executeSelectPackages();

            {
                QMutexLocker locker(cvesTableMutex);
                if (!cvesTableView)
                {
                    cvesTableView = new QSqlTableView(reportData->getCVEs(), this);
                    connect(this, SIGNAL(cvesTableViewDataUpdated(QModelIndex,QModelIndex)), this, SLOT(refreshCVEsTableView(QModelIndex,QModelIndex)));
                    connect(cvesTableView, SIGNAL(clicked(QModelIndex)), this, SLOT(cvesTableViewClicked(QModelIndex)));
                    cvesTableView->setFocusPolicy(Qt::NoFocus);
                    cvesTableView->setSelectionBehavior(QTableView::SelectionBehavior::SelectRows);
                    cvesTableView->setSelectionMode(QTableView::NoSelection);
                    ui->groupBoxCVEs->layout()->replaceWidget(ui->tableWidgetCVEs, cvesTableView);
                    cvesTableView->verticalHeader()->show();
                    ui->tableWidgetCVEs->hide();
                    cvesTableView->show();
                }
            }

            executeSelectCVEs();

            {
                QMutexLocker locker(ignoredCVEsTableMutex);
                if (!ignoredCVEsTableView)
                {
                    ignoredCVEsTableView = new QSqlTableView(reportData->getIgnoredCVEs(), this);
                    connect(this, SIGNAL(ignoredCVEsTableViewDataUpdated(QModelIndex,QModelIndex)), this, SLOT(refreshIgnoredCVEsTableView(QModelIndex,QModelIndex)));
                    connect(ignoredCVEsTableView, SIGNAL(clicked(QModelIndex)), this, SLOT(ignoredCVEsTableViewClicked(QModelIndex)));
                    ignoredCVEsTableView->setFocusPolicy(Qt::NoFocus);
                    ignoredCVEsTableView->setSelectionBehavior(QTableView::SelectionBehavior::SelectRows);
                    ignoredCVEsTableView->setSelectionMode(QTableView::NoSelection);
                    ui->groupBoxIgnoredCVEs->layout()->replaceWidget(ui->tableWidgetIgnoredCVEs, ignoredCVEsTableView);
                    ignoredCVEsTableView->verticalHeader()->show();
                    ui->tableWidgetIgnoredCVEs->hide();
                    ignoredCVEsTableView->show();
                }
            }

            executeSelectIgnoredCVEs();
        }
    }
    catch (...)
    {

    }
}

void MdiSubWindow::executeSelectPackages(bool search)
{
    static QMutex m;

    if (execSelectPackages && execSelectPackages->isRunning())
    {
        execSelectPackages->moveToThread(QThread::currentThread());
        execSelectPackages->quit();
        disconnect(execSelectPackages, SIGNAL(finished()), this, SLOT(executeSelectPackagesFinished()));
        delete execSelectPackages;
        execSelectPackages = nullptr;
    }

    QMutexLocker locker(&m);

    try
    {
        if (!execSelectPackages)
        {
            if (!reportData.isNull())
            {
                execSelectPackages = QThread::create(selectPackages, packagesTableMutex, reportData.get(), ui, packagesTableView, search);
                connect(execSelectPackages, SIGNAL(finished()), this, SLOT(executeSelectPackagesFinished()));
                execSelectPackages->start();
            }
        }
    }
    catch (...)
    {
        if (execSelectPackages)
        {
            execSelectPackages->moveToThread(QThread::currentThread());
            execSelectPackages->quit();
            disconnect(execSelectPackages, SIGNAL(finished()), this, SLOT(executeSelectPackagesFinished()));
            delete execSelectPackages;
            execSelectPackages = nullptr;
        }
    }
}

void MdiSubWindow::executeSelectPackagesFinished()
{
    execSelectPackages->moveToThread(QThread::currentThread());
    disconnect(execSelectPackages, SIGNAL(finished()), this, SLOT(executeSelectPackagesFinished()));
    delete execSelectPackages;
    execSelectPackages = nullptr;
    QMutexLocker locker(packagesTableMutex);
    QModelIndex startIndexCell = packagesTableView->getSqlQueryModel()->index(0, 0);
    QModelIndex endIndexCell = packagesTableView->getSqlQueryModel()->index(packagesTableView->getSqlQueryModel()->rowCount() - 1, packagesTableView->getSqlQueryModel()->columnCount() - 1);
    emit packagesTableViewDataUpdated(startIndexCell, endIndexCell);
}

void MdiSubWindow::selectPackages(QMutex* packagesTableMutex, ReportData* reportData, Ui::MdiSubWindow* ui, QSqlTableView* packagesTableView, bool search)
{
    QMutexLocker locker(packagesTableMutex);
    if (reportData)
    {
        int numOfPackagesToShow = ui->comboBoxShowPackages->currentData().toInt();
        bool onlyUnfixedPackages = ui->checkBoxOnlyUnfixedPackages->isChecked();
        int page = ui->spinBoxPackagesPage->value();
        QString filter = search ? ui->lineEditSearchPackages->text() : QString("");
        qint64 totalNumOfpackages = reportData->selectPackagesRowCount(ui->checkBoxOnlyUnfixedPackages->isChecked(), search ? ui->lineEditSearchPackages->text() : QString(""));
        ui->spinBoxPackagesPage->setMinimum(1);
        int pages = numOfPackagesToShow ? totalNumOfpackages / numOfPackagesToShow + (totalNumOfpackages % numOfPackagesToShow ? 1 : 0) : 1;
        reportData->selectPackages(onlyUnfixedPackages, numOfPackagesToShow, page, filter);
        if (reportData->getPackages())
        {
            int startingRow = ui->comboBoxShowPackages->currentData().toInt() * (ui->spinBoxPackagesPage->value() - 1) + 1;
            int numOfPackages = reportData->getPackages()->rowCount();
            int endingRow = numOfPackagesToShow ? std::min(numOfPackagesToShow * page, numOfPackagesToShow * (page - 1) + numOfPackages) : totalNumOfpackages;
            ui->labelPackagesItems->setText(QString("Showing %1 to %2 of %3 items").arg(startingRow).arg(endingRow).arg(totalNumOfpackages));
            ui->spinBoxPackagesPage->setMaximum( pages ? pages : 1);
        }
    }
}

void MdiSubWindow::refreshPackagesTableView(const QModelIndex &indexA, const QModelIndex &indexB)
{
    packagesTableView->updateStandardItemModel(indexA, indexB);
    QStandardItemModel* model = packagesTableView->getModel();
    packagesTableView->hideColumn(reportData->getPackages()->record().indexOf("ID"));
    packagesTableView->hideColumn(reportData->getPackages()->record().indexOf("CVEReportID"));
    for (int i=0; i< model->columnCount(); ++i)
    {
        if (i == PackagesPackageNameColumnIndex)
        {
            for (int j=0; j< model->rowCount(); ++j)
            {
                model->item(j, i)->setTextAlignment(Qt::AlignLeft | Qt::AlignVCenter);
            }
        }
    }
    resizePackagesTableView();
}

void MdiSubWindow::on_checkBoxOnlyUnfixedPackages_stateChanged(int state)
{
    ui->spinBoxPackagesPage->setValue(1);
    executeSelectPackages();
}

void MdiSubWindow::on_comboBoxShowPackages_currentIndexChanged(int index)
{
    ui->spinBoxPackagesPage->setValue(1);
    executeSelectPackages();
}

void MdiSubWindow::on_pushButtonSearchPackages_clicked()
{
    ui->spinBoxPackagesPage->setValue(1);
    executeSelectPackages();
}

void MdiSubWindow::on_spinBoxPackagesPage_valueChanged(int value)
{
    executeSelectPackages();
}

void MdiSubWindow::on_pushButtonClearSearchPackages_clicked()
{
    ui->lineEditSearchPackages->clear();
    ui->spinBoxPackagesPage->setValue(1);
    executeSelectPackages(false);
}

void MdiSubWindow::executeSelectCVEs(bool search)
{
    static QMutex m;

    if (execSelectCVEs && execSelectCVEs->isRunning())
    {
        execSelectCVEs->moveToThread(QThread::currentThread());
        execSelectCVEs->quit();
        disconnect(execSelectCVEs, SIGNAL(finished()), this, SLOT(executeSelectCVEsFinished()));
        delete execSelectCVEs;
        execSelectCVEs = nullptr;
    }

    QMutexLocker locker(&m);

    try
    {
        if (!execSelectCVEs)
        {
            if (!reportData.isNull())
            {
                execSelectCVEs = QThread::create(selectCVEs, cvesTableMutex, reportData.get(), ui, cvesTableView, search);
                connect(execSelectCVEs, SIGNAL(finished()), this, SLOT(executeSelectCVEsFinished()));
                execSelectCVEs->start();
            }
        }
    }
    catch (...)
    {
        if (execSelectCVEs)
        {
            execSelectCVEs->moveToThread(QThread::currentThread());
            execSelectCVEs->quit();
            disconnect(execSelectCVEs, SIGNAL(finished()), this, SLOT(executeSelectCVEsFinished()));
            delete execSelectCVEs;
            execSelectCVEs = nullptr;
        }
    }
}

void MdiSubWindow::executeSelectCVEsFinished()
{
    execSelectCVEs->moveToThread(QThread::currentThread());
    disconnect(execSelectCVEs, SIGNAL(finished()), this, SLOT(executeSelectCVEsFinished()));
    delete execSelectCVEs;
    execSelectCVEs = nullptr;
    QMutexLocker locker(cvesTableMutex);
    QModelIndex startIndexCell = cvesTableView->getSqlQueryModel()->index(0, 0);
    QModelIndex endIndexCell = cvesTableView->getSqlQueryModel()->index(cvesTableView->getSqlQueryModel()->rowCount() - 1, cvesTableView->getSqlQueryModel()->columnCount() - 1);
    emit cvesTableViewDataUpdated(startIndexCell, endIndexCell);
}

void MdiSubWindow::selectCVEs(QMutex* cvesTableMutex, ReportData* reportData, Ui::MdiSubWindow* ui, QSqlTableView* cvesTableView, bool search)
{
    QMutexLocker locker(cvesTableMutex);
    if (reportData)
    {
        int numOfCVEsToShow = ui->comboBoxShowCVEs->currentData().toInt();
        int page = ui->spinBoxCVEsPage->value();
        qint64 packageID = ui->comboBoxCVEsPackages->currentData().toLongLong();
        QString status = ui->comboBoxCVEsStatus->currentData().toString();
        QString vector = ui->comboBoxCVEsAttackVector->currentData().toString();
        double cvss3score = ui->comboBoxCVEsMinimumCVSS->currentData().toDouble();
        QString filter = search ? ui->lineEditSearchCVEs->text() : QString("");
        qint64 totalNumOfCVEs = reportData->selectCVEsRowCount(packageID, status,  vector, cvss3score, 10, filter);
        ui->spinBoxCVEsPage->setMinimum(1);
        int pages = numOfCVEsToShow ? totalNumOfCVEs / numOfCVEsToShow + (totalNumOfCVEs % numOfCVEsToShow ? 1 : 0) : 1;
        reportData->selectCVEs(packageID, status,  vector, cvss3score, 10, numOfCVEsToShow, page, filter);
        if (reportData->getCVEs())
        {
            int startingRow = numOfCVEsToShow * (page - 1) + 1;
            int numOfCVEs = reportData->getCVEs()->rowCount();
            int endingRow = numOfCVEsToShow ? std::min(numOfCVEsToShow * page, numOfCVEsToShow * (page - 1) + numOfCVEs) : totalNumOfCVEs;
            ui->labelCVEsItems->setText(QString("Showing %1 to %2 of %3 items").arg(startingRow).arg(endingRow).arg(totalNumOfCVEs));
            ui->spinBoxCVEsPage->setMaximum( pages ? pages : 1);
        }
    }
}

void MdiSubWindow::refreshCVEsTableView(const QModelIndex& indexA, const QModelIndex& indexB)
{
    cvesTableView->updateStandardItemModel(indexA, indexB);
    QStandardItemModel* model = cvesTableView->getModel();
    cvesTableView->hideColumn(reportData->getCVEs()->record().indexOf("PID"));
    cvesTableView->hideColumn(reportData->getCVEs()->record().indexOf("IID"));
    for (int i=0; i< model->columnCount(); ++i)
    {
        if (i == CVEsPackageNameColumnIndex || i == CVEsLinkColumnIndex)
        {
            for (int j=0; j< model->rowCount(); ++j)
            {
                if (model->item(j, i))
                {
                    model->item(j, i)->setTextAlignment(Qt::AlignLeft | Qt::AlignVCenter);
                }
            }
        }
    }
    resizeCVEsTableView();
}

void MdiSubWindow::cvesTableViewClicked(const QModelIndex &index)
{
    if (index.column() == CVEsLinkColumnIndex)
    {
        if (index.data().toUrl().isValid())
        {
            QDesktopServices::openUrl(index.data().toUrl());
        }
    }
}

void MdiSubWindow::on_comboBoxCVEsPackages_currentIndexChanged(int index)
{
    ui->spinBoxCVEsPage->setValue(1);
    executeSelectCVEs();
}

void MdiSubWindow::on_comboBoxCVEsStatus_currentIndexChanged(int index)
{
    ui->spinBoxCVEsPage->setValue(1);
    executeSelectCVEs();
}

void MdiSubWindow::on_comboBoxCVEsAttackVector_currentIndexChanged(int index)
{
    ui->spinBoxCVEsPage->setValue(1);
    executeSelectCVEs();
}

void MdiSubWindow::on_comboBoxCVEsMinimumCVSS_currentIndexChanged(int index)
{
    ui->spinBoxCVEsPage->setValue(1);
    executeSelectCVEs();
}

void MdiSubWindow::on_comboBoxShowCVEs_currentIndexChanged(int index)
{
    ui->spinBoxCVEsPage->setValue(1);
    executeSelectCVEs();
}

void MdiSubWindow::on_pushButtonSearchCVEs_clicked()
{
    ui->spinBoxCVEsPage->setValue(1);
    executeSelectCVEs();
}

void MdiSubWindow::on_pushButtonClearSearchCVEs_clicked()
{
    ui->lineEditSearchCVEs->clear();
    ui->spinBoxCVEsPage->setValue(1);
    executeSelectCVEs(false);
}

void MdiSubWindow::on_spinBoxCVEsPage_valueChanged(int index)
{
    executeSelectCVEs();
}

void MdiSubWindow::executeSelectIgnoredCVEs(bool search)
{
    static QMutex m;

    if (execSelectIgnoreCVEs && execSelectIgnoreCVEs->isRunning())
    {
        execSelectIgnoreCVEs->moveToThread(QThread::currentThread());
        execSelectIgnoreCVEs->quit();
        disconnect(execSelectIgnoreCVEs, SIGNAL(finished()), this, SLOT(executeSelectIgnoredCVEsFinished()));
        delete execSelectIgnoreCVEs;
        execSelectIgnoreCVEs = nullptr;
    }

    QMutexLocker locker(&m);
    try
    {
        if (!execSelectIgnoreCVEs)
        {
            if (!reportData.isNull())
            {
                execSelectIgnoreCVEs = QThread::create(selectIgnoredCVEs, ignoredCVEsTableMutex, reportData.get(), ui, ignoredCVEsTableView, search);
                connect(execSelectIgnoreCVEs, SIGNAL(finished()), this, SLOT(executeSelectIgnoredCVEsFinished()));
                execSelectIgnoreCVEs->start();
            }
        }
    }
    catch (...)
    {
        if (execSelectIgnoreCVEs)
        {
            execSelectIgnoreCVEs->moveToThread(QThread::currentThread());
            execSelectIgnoreCVEs->quit();
            disconnect(execSelectIgnoreCVEs, SIGNAL(finished()), this, SLOT(executeSelectIgnoredCVEsFinished()));
            delete execSelectIgnoreCVEs;
            execSelectIgnoreCVEs = nullptr;
        }
    }
}

void MdiSubWindow::executeSelectIgnoredCVEsFinished()
{
    execSelectIgnoreCVEs->moveToThread(QThread::currentThread());
    disconnect(execSelectIgnoreCVEs, SIGNAL(finished()), this, SLOT(executeSelectIgnoredCVEsFinished()));
    delete execSelectIgnoreCVEs;
    execSelectIgnoreCVEs = nullptr;
    QMutexLocker locker(ignoredCVEsTableMutex);
    QModelIndex startIndexCell = ignoredCVEsTableView->getSqlQueryModel()->index(0, 0);
    QModelIndex endIndexCell = ignoredCVEsTableView->getSqlQueryModel()->index(ignoredCVEsTableView->getSqlQueryModel()->rowCount() - 1, ignoredCVEsTableView->getSqlQueryModel()->columnCount() - 1);
    emit ignoredCVEsTableViewDataUpdated(startIndexCell, endIndexCell);
}

void MdiSubWindow::selectIgnoredCVEs(QMutex* ignoredCVEsTableMutex, ReportData* reportData, Ui::MdiSubWindow* ui, QSqlTableView* ignoredCVEsTableView, bool search)
{
    QMutexLocker locker(ignoredCVEsTableMutex);
    if (reportData)
    {
        int numOfIgnoredCVEsToShow = ui->comboBoxShowIgnoredCVEs->currentData().toInt();
        int page = ui->spinBoxIgnoredCVEsPage->value();
        QString filter = search ? ui->lineEditSearchIgnoredCVEs->text() : QString("");
        qint64 totalNumOfIgnoredCVEs = reportData->selectIgnoredCVEsRowCount(filter);
        ui->spinBoxIgnoredCVEsPage->setMinimum(1);
        int pages = numOfIgnoredCVEsToShow ? totalNumOfIgnoredCVEs / numOfIgnoredCVEsToShow + (totalNumOfIgnoredCVEs % numOfIgnoredCVEsToShow ? 1 : 0) : 1;
        reportData->selectIgnoredCVEs(numOfIgnoredCVEsToShow, page, filter);
        if (reportData->getIgnoredCVEs())
        {
            int startingRow = numOfIgnoredCVEsToShow * (page - 1) + 1;
            int numOfIgnoredCVEs = reportData->getIgnoredCVEs()->rowCount();
            int endingRow = numOfIgnoredCVEsToShow ? std::min(numOfIgnoredCVEsToShow * page, numOfIgnoredCVEsToShow * (page - 1) + numOfIgnoredCVEs) : totalNumOfIgnoredCVEs;
            ui->labelIgnoredCVEsItems->setText(QString("Showing %1 to %2 of %3 items").arg(startingRow).arg(endingRow).arg(totalNumOfIgnoredCVEs));
            ui->spinBoxIgnoredCVEsPage->setMaximum( pages ? pages : 1);
        }
    }
}

void MdiSubWindow::refreshIgnoredCVEsTableView(const QModelIndex &indexA, const QModelIndex &indexB)
{
    ignoredCVEsTableView->updateStandardItemModel(indexA, indexB);
    QStandardItemModel* model = ignoredCVEsTableView->getModel();
    ignoredCVEsTableView->hideColumn(reportData->getIgnoredCVEs()->record().indexOf("PID"));
    ignoredCVEsTableView->hideColumn(reportData->getIgnoredCVEs()->record().indexOf("IID"));
    for (int i=0; i< model->columnCount(); ++i)
    {
        if (i == CVEsPackageNameColumnIndex || i == CVEsLinkColumnIndex)
        {
            for (int j=0; j< model->rowCount(); ++j)
            {
                model->item(j, i)->setTextAlignment(Qt::AlignLeft | Qt::AlignVCenter);
            }
        }
    }
    resizeIgnoredCVEsTableView();
}

void MdiSubWindow::ignoredCVEsTableViewClicked(const QModelIndex &index)
{
    if (index.column() == IgnoredCVEsLinkColumnIndex)
    {
        if (index.data().toUrl().isValid())
        {
            QDesktopServices::openUrl(index.data().toUrl());
        }
    }
}

void MdiSubWindow::on_comboBoxShowIgnoredCVEs_currentIndexChanged(int index)
{
    ui->spinBoxIgnoredCVEsPage->setValue(1);
    executeSelectIgnoredCVEs();
}

void MdiSubWindow::on_pushButtonSearchIgnoredCVEs_clicked()
{
    ui->spinBoxIgnoredCVEsPage->setValue(1);
    executeSelectIgnoredCVEs();
}

void MdiSubWindow::on_pushButtonClearSearchIgnoredCVEe_clicked()
{
    ui->lineEditSearchIgnoredCVEs->clear();
    ui->spinBoxIgnoredCVEsPage->setValue(1);
    executeSelectIgnoredCVEs(false);
}

void MdiSubWindow::on_spinBoxIgnoredCVEsPage_valueChanged(int index)
{
    executeSelectIgnoredCVEs();
}
