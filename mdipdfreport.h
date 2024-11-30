#ifndef MDIPDFREPORT_H
#define MDIPDFREPORT_H

#include "reportdata.h"
#include <QMdiSubWindow>
#include <QSharedPointer>
#include <QPrinter>
#include <QPageLayout>
#include <QPageSize>
#include <PDFWriter.h>


namespace Ui {
class MdiPDFReport;
}

class MdiPDFReport : public QMdiSubWindow
{
    Q_OBJECT

public:
    explicit MdiPDFReport(const QString& fileName = QString(), QSQLiteManager *sqlManager = nullptr, QWidget *parent = nullptr);
    ~MdiPDFReport();
    void LoadReportData();

private slots:
    void ReportLoaded(bool ok);
    void ReportPrinted(const QString& tmpFilePath, bool success);

private:
    Ui::MdiPDFReport *ui;
    QString reportFile;
    QSQLiteManager* sqliteManager = nullptr;
    QSharedPointer<ReportData> reportData;

    QMarginsF pageMargins;
    QPageLayout pageLayout;
    QSize pageSize;

    void PrintReport();    
    EStatusCode PDFModifyFooterContext(const QString &srcFile, const QString &outFile);
    QString randomString(int length, QString string = QString());


protected:
    void resizeEvent(QResizeEvent *ev) override;

};

#endif // MDIPDFREPORT_H
