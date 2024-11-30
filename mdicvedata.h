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
