/*!
   QCVECheckReport project

   @file: mdicvedata.cpp

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

#include "mdicvedata.h"
#include "qsqlitemanager.h"
#include "ui_mdicvedata.h"
#include <QResizeEvent>
#include <QScrollBar>
#include <QMutex>

#define NVDsNVDIDColumnIndex 0
#define NVDsSummaryColumnIndex 1
#define NVDsScoreV2ColumnIndex 2
#define NVDsScoreV3ColumnIndex 3
#define NVDsModifiedColumnIndex 4
#define NVDsVectorColumnIndex 5
#define NVDsVectorStringColumnIndex 6
#define ProductsProductIDColumnIndex 0
#define ProductsVendorColumnIndex 1
#define ProductsProductColumnIndex 2
#define ProductsVersionStartColumnIndex 3
#define ProductsStartOperatorColumnIndex 4
#define ProductsVersionEndColumnIndex 5
#define ProductsEndOperatorColumnIndex 6

#define NVDIDWidth 150
#define SummaryWidth 300
#define CVSSScoreWidth 100
#define ModifiedWidth 150
#define VectorWidth 180
#define VectorStringWidth 180

#define ProductIDWidth 150
#define VendorWidth 150
#define ProductWidth 150
#define VersionStartWidth 150
#define OperatorStartWidth 150
#define VersionEndWidth 150
#define OperatorEndWidth 150

MdiCVEData::MdiCVEData(QSQLiteManager* sqlManager, QWidget *parent)
    : QMdiSubWindow(parent), sqliteManager(sqlManager)
    , ui(new Ui::MdiCVEData), selectedProductID(""), nvdsTableMutex(new QMutex()), productsTableMutex(new QMutex())
{
    ui->setupUi(this);

    setWindowTitle("NVD Data");

    if (!nvdsTableView)
    {
        nvdsTableView = new QSqlTableView(sqliteManager->getNVDDataNVDsModel(), this);
        connect(this, SIGNAL(nvdsTableViewDataUpdated(QModelIndex,QModelIndex)), this, SLOT(refreshNVDsTableView(QModelIndex,QModelIndex)));
        connect(nvdsTableView, SIGNAL(clicked(QModelIndex)), this, SLOT(nvdsTableViewClicked(QModelIndex)));
        nvdsTableView->setFocusPolicy(Qt::NoFocus);
        nvdsTableView->setSelectionBehavior(QTableView::SelectionBehavior::SelectRows);
        nvdsTableView->setSelectionMode(QTableView::NoSelection);
        // connect(cvesTableView->verticalScrollBar(), SIGNAL(valueChanged(int)), this, SLOT(fetchNextCVEs(int)));
        ui->groupBoxNVDs->layout()->replaceWidget(ui->tableWidgetNVDs, nvdsTableView);
        nvdsTableView->verticalHeader()->show();
        ui->tableWidgetNVDs->hide();
        nvdsTableView->show();
    }

    if (!productsTableView)
    {
        productsTableView = new QSqlTableView(sqliteManager->getNVDDataProductsModel(), this);
        connect(this, SIGNAL(productsTableViewDataUpdated(QModelIndex,QModelIndex)), this, SLOT(refreshProductsTableView(QModelIndex,QModelIndex)));
        productsTableView->setFocusPolicy(Qt::NoFocus);
        productsTableView->setSelectionBehavior(QTableView::SelectionBehavior::SelectRows);
        productsTableView->setSelectionMode(QTableView::NoSelection);
        // connect(packagesTableView->verticalScrollBar(), SIGNAL(valueChanged(int)), this, SLOT(fetchNextPackages(int)));
        ui->groupBoxProducts->layout()->replaceWidget(ui->tableWidgetProducts, productsTableView);
        productsTableView->verticalHeader()->show();
        ui->tableWidgetProducts->hide();
        productsTableView->show();
    }

    ui->spinBoxProductsPage->setMinimum(1);
    //ui->comboBoxShowPackages->addItem(tr("All"), 0);
    ui->comboBoxShowProducts->addItem(tr("10"), 10);
    ui->comboBoxShowProducts->addItem(tr("20"), 20);
    ui->comboBoxShowProducts->addItem(tr("50"), 50);
    ui->comboBoxShowProducts->addItem(tr("100"), 100);
    ui->comboBoxShowProducts->addItem(tr("250"), 250);
    ui->comboBoxShowProducts->setCurrentIndex(4);

    ui->spinBoxNVDsPage->setMinimum(1);
    //ui->comboBoxShowCVEs->addItem(tr("All"), 0);
    ui->comboBoxShowNs->addItem(tr("10"), 10);
    ui->comboBoxShowNs->addItem(tr("20"), 20);
    ui->comboBoxShowNs->addItem(tr("50"), 50);
    ui->comboBoxShowNs->addItem(tr("100"), 100);
    ui->comboBoxShowNs->addItem(tr("250"), 250);
    ui->comboBoxShowNs->setCurrentIndex(4);

    ui->comboBoxNVDsAttackVector->addItem(tr("All"), "");
    ui->comboBoxNVDsAttackVector->addItem(tr("Unknown"), "UNKNOWN");
    ui->comboBoxNVDsAttackVector->addItem(tr("Local"), "LOCAL");
    ui->comboBoxNVDsAttackVector->addItem(tr("Network"), "NETWORK");
    ui->comboBoxNVDsAttackVector->addItem(tr("Adjacent Network"), "ADJACENT_NETWORK");
    ui->comboBoxNVDsAttackVector->addItem(tr("Physical"), "PHYSICAL");

    ui->comboBoxNVDsMinimumCVSS->addItem(tr("None"), 0.0);
    ui->comboBoxNVDsMinimumCVSS->addItem(tr("Low"), 0.1);
    ui->comboBoxNVDsMinimumCVSS->addItem(tr("Medium"), 4.0);
    ui->comboBoxNVDsMinimumCVSS->addItem(tr("High"), 7.0);
    ui->comboBoxNVDsMinimumCVSS->addItem(tr("Critical"), 9.0);

    reloadData();
}

MdiCVEData::~MdiCVEData()
{
    disconnect(this, SIGNAL(nvdsTableViewDataUpdated(QModelIndex,QModelIndex)), this, SLOT(refreshNVDsTableView(QModelIndex,QModelIndex)));
    disconnect(nvdsTableView, SIGNAL(clicked(QModelIndex)), this, SLOT(nvdsTableViewClicked(QModelIndex)));
    disconnect(this, SIGNAL(productsTableViewDataUpdated(QModelIndex,QModelIndex)), this, SLOT(refreshProductsTableView(QModelIndex,QModelIndex)));
    delete ui;
    delete nvdsTableMutex;
    delete productsTableMutex;
}

void MdiCVEData::reloadData()
{
    setComboBoxNVDsProducts();
    ui->spinBoxNVDsPage->setValue(1);
    //executeSelectNVDs();
    ui->spinBoxProductsPage->setValue(1);
    //executeSelectProducts();
}

void MdiCVEData::scrollToGroupBox(GroupBoxEnum groupBox)
{
    switch (groupBox)
    {
    case GroupBoxEnum::NVDs:
        ui->scrollArea->verticalScrollBar()->setValue(ui->groupBoxNVDs->y());
        break;
    case GroupBoxEnum::Products:
        ui->scrollArea->verticalScrollBar()->setValue(ui->groupBoxProducts->y());
        break;
    }
}

void MdiCVEData::resizeEvent(QResizeEvent *ev)
{
    ui->scrollArea->move(10,40);
    ui->scrollArea->resize(ev->size() - QSize(20, 60));
}

void MdiCVEData::resizeNVDsTableView()
{
    if (nvdsTableView && nvdsTableView->getModel() && nvdsTableView->getModel()->columnCount())
    {
        int columnCount = nvdsTableView->getModel()->columnCount();
        nvdsTableView->horizontalHeader()->setDefaultSectionSize(nvdsTableView->width() / columnCount - 2);
        nvdsTableView->horizontalHeader()->setDefaultAlignment(Qt::AlignCenter);
        int widths[7] = { NVDIDWidth, SummaryWidth, CVSSScoreWidth, CVSSScoreWidth, ModifiedWidth, VectorWidth, VectorStringWidth };
        for (int i = 0; i < 7; i++)
        {
            nvdsTableView->setColumnWidth(i, widths[i]);
        }
        nvdsTableView->horizontalHeader()->setSectionResizeMode(NVDsSummaryColumnIndex, QHeaderView::Stretch);
    }
}

void MdiCVEData::resizeProductsTableView()
{
    if (productsTableView && productsTableView->getModel() && productsTableView->getModel()->columnCount())
    {
        int columnCount = productsTableView->getModel()->columnCount();
        productsTableView->horizontalHeader()->setDefaultSectionSize(productsTableView->width()  / columnCount - 2);
        productsTableView->horizontalHeader()->setDefaultAlignment(Qt::AlignCenter);
        int widths[7] = { ProductIDWidth, VendorWidth, ProductWidth, VersionStartWidth, OperatorStartWidth, VersionEndWidth, OperatorEndWidth };
        for (int i = ProductsProductIDColumnIndex; i < columnCount; i++)
        {
            productsTableView->setColumnWidth(i, widths[i]);
        }
        productsTableView->horizontalHeader()->setSectionResizeMode(ProductsVendorColumnIndex, QHeaderView::Stretch);
        productsTableView->horizontalHeader()->setSectionResizeMode(ProductsProductColumnIndex, QHeaderView::Stretch);
    }
}

void MdiCVEData::setComboBoxNVDsProducts()
{
    ui->comboBoxNVDsProducts->clear();
    ui->comboBoxNVDsProducts->addItem("");
    auto products = sqliteManager->getAllProductsNames();
    std::sort(products.begin(), products.end(), productsKeysComparison);
    ui->comboBoxNVDsProducts->addItems(products);
}

bool MdiCVEData::productsKeysComparison(const QString &product1, const QString &product2)
{
    if (!product1.isNull() && !product1.isEmpty() && !product2.isNull() && !product2.isEmpty())
    {
        return (product1 < product2);
    }
    else if (!product1.isNull() && !product1.isEmpty())
    {
        return false;
    }
    else if (!product2.isNull() && !product2.isEmpty())
    {
        return true;
    }

    return false;
}

void MdiCVEData::executeSelectNVDs(bool search)
{
    static QMutex m;

    if (execSelectNVDs && execSelectNVDs->isRunning())
    {
        execSelectNVDs->exit();
        disconnect(execSelectNVDs, SIGNAL(finished()), this, SLOT(executeSelectNVDsFinished()));
        delete execSelectNVDs;
        execSelectNVDs = nullptr;
    }

    QMutexLocker locker(&m);

    try
    {
        if (!execSelectNVDs)
        {
            execSelectNVDs = QThread::create(selectNVDs, nvdsTableMutex, ui, sqliteManager, nvdsTableView, search);
            connect(execSelectNVDs, SIGNAL(finished()), this, SLOT(executeSelectNVDsFinished()));
            execSelectNVDs->start();
        }
    }
    catch (...)
    {
        execSelectNVDs->quit();
        disconnect(execSelectNVDs, SIGNAL(finished()), this, SLOT(executeSelectNVDsFinished()));
        delete execSelectNVDs;
        execSelectNVDs = nullptr;
    }
}

void MdiCVEData::executeSelectNVDsFinished()
{
    disconnect(execSelectNVDs, SIGNAL(finished()), this, SLOT(executeSelectNVDsFinished()));
    delete execSelectNVDs;
    execSelectNVDs = nullptr;
    QModelIndex startIndexCell = nvdsTableView->getSqlQueryModel()->index(0, 0);
    QModelIndex endIndexCell = nvdsTableView->getSqlQueryModel()->index(nvdsTableView->getSqlQueryModel()->rowCount() - 1, nvdsTableView->getSqlQueryModel()->columnCount() - 1);
    emit nvdsTableViewDataUpdated(startIndexCell, endIndexCell);
}

void MdiCVEData::selectNVDs(QMutex *nvdsTableMutex, Ui::MdiCVEData *ui, QSQLiteManager *sqliteManager, QSqlTableView* nvdsTableView, bool search)
{
    QMutexLocker locker(nvdsTableMutex);
    int numOfNVDsToShow = ui->comboBoxShowNs->currentData().toInt();
    int page = ui->spinBoxNVDsPage->value();
    QString product = ui->comboBoxNVDsProducts->currentText();
    QString vector = ui->comboBoxNVDsAttackVector->currentData().toString();
    double cvss3score = ui->comboBoxNVDsMinimumCVSS->currentData().toDouble();
    QString filter = search ? ui->lineEditSearchNVDs->text() : QString("");
    qint64 totalNumOfNVDs = sqliteManager->getNVDDataNVDsRowCount(product, vector, cvss3score, filter);
    ui->spinBoxNVDsPage->setMinimum(1);
    int pages = numOfNVDsToShow ? totalNumOfNVDs / numOfNVDsToShow + (totalNumOfNVDs % numOfNVDsToShow ? 1 : 0) : 1;
    ui->spinBoxNVDsPage->setMaximum( pages ? pages : 1 );
    sqliteManager->setNVDDataNVDsModelQuery(product, vector, cvss3score, numOfNVDsToShow, page, filter);
    nvdsTableView->verticalScrollBar()->setMaximum(sqliteManager->getNVDDataNVDsModel()->rowCount());
    int startingRow = numOfNVDsToShow * (page - 1) + 1;
    int numOfNVDs = sqliteManager->getNVDDataNVDsModel()->rowCount();
    int endingRow = numOfNVDsToShow ? std::min(numOfNVDsToShow * page, numOfNVDsToShow * (page - 1) + numOfNVDs) : totalNumOfNVDs;
    ui->labelNVDsItems->setText(QString("Showing %1 to %2 of %3 items").arg(startingRow).arg(endingRow).arg(totalNumOfNVDs));
}

void MdiCVEData::refreshNVDsTableView(const QModelIndex& indexA, const QModelIndex& indexB)
{
    nvdsTableView->updateStandardItemModel(indexA, indexB);
    resizeNVDsTableView();
}

void MdiCVEData::on_comboBoxNVDsProducts_currentIndexChanged(int index)
{
    ui->spinBoxProductsPage->setValue(1);
    executeSelectNVDs();
}

void MdiCVEData::on_comboBoxNVDsAttackVector_currentIndexChanged(int index)
{
    ui->spinBoxNVDsPage->setValue(1);
    executeSelectNVDs();
}

void MdiCVEData::on_comboBoxNVDsMinimumCVSS_currentIndexChanged(int index)
{
    ui->spinBoxNVDsPage->setValue(1);
    executeSelectNVDs();
}

void MdiCVEData::on_comboBoxShowNs_currentIndexChanged(int index)
{
    ui->spinBoxNVDsPage->setValue(1);
    executeSelectNVDs();
}

void MdiCVEData::on_pushButtonSearchNVDs_clicked()
{
    ui->spinBoxNVDsPage->setValue(1);
    executeSelectNVDs();
}

void MdiCVEData::on_pushButtonClearSearchNVDs_clicked()
{
    ui->lineEditSearchNVDs->clear();
    ui->spinBoxNVDsPage->setValue(1);
    executeSelectNVDs(false);
}

void MdiCVEData::on_spinBoxNVDsPage_valueChanged(int value)
{
    executeSelectNVDs();
}

void MdiCVEData::nvdsTableViewClicked(const QModelIndex &index)
{
    selectedProductID = nvdsTableView->getModel()->data(index.sibling(index.row(), 0)).toString();
    executeSelectProducts(selectedProductID);
}

void MdiCVEData::selectProducts(QMutex* productsTableMutex, Ui::MdiCVEData *ui, QSQLiteManager *sqliteManager, QSqlTableView* productsTableView, const QString& productID, bool search)
{
    QMutexLocker locker(productsTableMutex);
    int numOfProductsToShow = ui->comboBoxShowProducts->currentData().toInt();
    int page = ui->spinBoxProductsPage->value();
    QString filter = search ? ui->lineEditSearchProducts->text() : QString("");
    qint64 totalNumOfProducts = sqliteManager->getNVDDataProductsRowCount(productID, search ? ui->lineEditSearchProducts->text() : QString(""));
    ui->spinBoxProductsPage->setMinimum(1);
    int pages = numOfProductsToShow ? totalNumOfProducts / numOfProductsToShow + (totalNumOfProducts % numOfProductsToShow ? 1 : 0) : 1;
    ui->spinBoxProductsPage->setMaximum( pages ? pages : 1 );
    sqliteManager->setNVDDataProductsModelQuery(productID, numOfProductsToShow, page, filter);
    int startingRow = ui->comboBoxShowProducts->currentData().toInt() * (ui->spinBoxProductsPage->value() - 1) + 1;
    int numOfProducts = sqliteManager->getNVDDataProductsModel()->rowCount();
    int endingRow = numOfProductsToShow ? std::min(numOfProductsToShow * page, numOfProductsToShow * (page - 1) + numOfProducts) : totalNumOfProducts;
    ui->labelProductsItems->setText(QString("Showing %1 to %2 of %3 items").arg(startingRow).arg(endingRow).arg(totalNumOfProducts));
}

void MdiCVEData::executeSelectProducts(const QString &productID, bool search)
{
    static QMutex m;

    if (execSelectProducts && execSelectProducts->isRunning())
    {
        execSelectProducts->exit();
        disconnect(execSelectProducts, SIGNAL(finished()), this, SLOT(executeSelectProductsFinished()));
        delete execSelectProducts;
        execSelectProducts = nullptr;
    }

    QMutexLocker locker(&m);

    try
    {        
        if (!execSelectProducts)
        {
            execSelectProducts = QThread::create(selectProducts, productsTableMutex, ui, sqliteManager, productsTableView, productID, search);
            connect(execSelectProducts, SIGNAL(finished()), this, SLOT(executeSelectProductsFinished()));
            execSelectProducts->start();
        }
    }
    catch (...)
    {
        execSelectProducts->quit();
        disconnect(execSelectProducts, SIGNAL(finished()), this, SLOT(executeSelectProductsFinished()));
        delete execSelectProducts;
        execSelectProducts = nullptr;
    }
}

void MdiCVEData::executeSelectProductsFinished()
{
    disconnect(execSelectProducts, SIGNAL(finished()), this, SLOT(executeSelectProductsFinished()));
    delete execSelectProducts;
    execSelectProducts = nullptr;
    QModelIndex startIndexCell = productsTableView->getSqlQueryModel()->index(0, 0);
    QModelIndex endIndexCell = productsTableView->getSqlQueryModel()->index(productsTableView->getSqlQueryModel()->rowCount() - 1, productsTableView->getSqlQueryModel()->columnCount() - 1);
    emit productsTableViewDataUpdated(startIndexCell, endIndexCell);
}

void MdiCVEData::refreshProductsTableView(const QModelIndex &indexA, const QModelIndex &indexB)
{
    productsTableView->updateStandardItemModel(indexA, indexB);
    resizeProductsTableView();
}

void MdiCVEData::on_comboBoxShowProducts_currentIndexChanged(int index)
{
    ui->spinBoxProductsPage->setValue(1);
    executeSelectProducts(selectedProductID);
}

void MdiCVEData::on_pushButtonSearchProducts_clicked()
{
    ui->spinBoxProductsPage->setValue(1);
    executeSelectProducts(selectedProductID);
}

void MdiCVEData::on_pushButtonClearSearchProducts_clicked()
{
    ui->lineEditSearchProducts->clear();
    ui->spinBoxProductsPage->setValue(1);
    executeSelectProducts(selectedProductID);
}

void MdiCVEData::on_spinBoxProductsPage_valueChanged(int value)
{
    executeSelectProducts(selectedProductID);
}
