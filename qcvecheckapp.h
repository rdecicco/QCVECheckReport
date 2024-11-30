#ifndef QCVECHECKAPP_H
#define QCVECHECKAPP_H

#include <QMainWindow>
#include <QResizeEvent>
#include <dialogimportcvereport.h>
#include "dialogimportcvedb.h"
#include "mdicvedata.h"
#include "mdipdfreport.h"
#include "mdisubwindow.h"
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
    void importCVEDBFinished();

private slots:
    void on_action_Open_triggered();
    void on_action_Exit_triggered();
    void on_comboBoxReports_currentIndexChanged(int index);
    void on_pushButtonOpen_clicked();
    void on_pushButtonGeneral_clicked();

    void on_pushButtonSummary_clicked();

    void on_pushButtonPackages_clicked();

    void on_pushButtonCVEs_clicked();

    void on_pushButtonIgnoredCVEs_clicked();

    void on_actionImport_CVE_DB_triggered();

    void on_pushButtonCVEData_clicked();

    void on_pushButtonExportReport_clicked();

    static void importCVEReport(QCVECheckApp* parent, const QString& jsonReportFileName, const QString& CVEDBFileName);
    static void importCVEDB(QCVECheckApp *parent, const QString& CVEDBFileName);

    void jsonCVEReportImported(const QString& jsonReportFileName);
    void CVEDBImported();

    void UpdateCVEReportsComboBox();

    void on_actionAbout_QCVECheckReport_triggered();

private:
    Ui::QCVECheckApp *ui;
    DialogImportCVEReport *dialogImportCVEReport;
    DialogImportCVEDB *dialogImportCVEDB;
    QSQLiteManager* sqliteDBManager;
    JsonCVECheckReportManager jsonCVEReportManager;
    QStringList jsonCVEReportsList;

    QMap<QString, MdiPDFReport*> pdfReportsMap;
    QMap<QString, MdiSubWindow*> subWindowsMap;
    MdiCVEData* mdiCVEData = nullptr;

    void OpenCVEReportWindow(const QString &reportName);
    void OpenPDFReportWindow(const QString &reportName);

    QThread* importCVEReportThread = nullptr;
    QThread* importCVEDbThread = nullptr;

    QMutex* subWindowMapMutex;
    QMutex* mdiCVEDataMutex;

protected:
    void resizeEvent(QResizeEvent *ev) override;

};
#endif // QCVECHECKAPP_H
