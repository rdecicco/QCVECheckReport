/*!
   QCVECheckReport project

   @file: mdipdfreport.h

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

#ifndef MDIPDFREPORT_H
#define MDIPDFREPORT_H

#include "reportdata.h"
#include <QMdiSubWindow>
#include <QSharedPointer>
#include <QPrinter>
#include <QPageLayout>
#include <QPageSize>

#if PDFWRITER
#include <PDFWriter.h>
#endif

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

#if PDFWRITER
    EStatusCode PDFModifyFooterContext(const QString &srcFile, const QString &outFile);
#endif

    QString randomString(int length, QString string = QString());

protected:
    void resizeEvent(QResizeEvent *ev) override;

};

#endif // MDIPDFREPORT_H
