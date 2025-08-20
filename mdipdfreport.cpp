/*!
   QCVECheckReport project

   @file: mdipdfreport.cpp

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

#include "mdipdfreport.h"
#include "qmessagebox.h"
#include "ui_mdipdfreport.h"
#include <QResizeEvent>
#include <QFileDialog>
#include <QWebEngineProfile>
#include <QPrinterInfo>

#if PDFWRITER
#include "AbstractContentContext.h"
#include "PDFDocumentCopyingContext.h"
#include "PDFModifiedPage.h"
#include "PDFUsedFont.h"
#include <PDFWriter.h>
#include <PDFParser.h>
#include <PDFPage.h>
#include <PDFObjectCast.h>
#include <PDFDictionary.h>
#include <PDFDocumentCopyingContext.h>
#include <ObjectsContext.h>
#include <DictionaryContext.h>
#include <PageContentContext.h>
#include <DocumentContext.h>
using namespace PDFHummus;
#endif

MdiPDFReport::MdiPDFReport(const QString &fileName, QSQLiteManager* sqlManager, QWidget *parent):
    QMdiSubWindow(parent), reportFile(fileName), pageMargins{25, 35, 25, 35}, sqliteManager(sqlManager),
    ui(new Ui::MdiPDFReport)
{
    pageLayout = QPageLayout(QPageSize(QPageSize::A4), QPageLayout::Portrait, pageMargins);
    pageSize = pageLayout.pageSize().sizePoints();
    srand(QTime().msecsSinceStartOfDay());
    ui->setupUi(this);
    connect(ui->webEngineView, SIGNAL(loadFinished(bool)), this, SLOT(ReportLoaded(bool)));
    connect(ui->webEngineView, SIGNAL(pdfPrintingFinished(QString,bool)), this, SLOT(ReportPrinted(QString,bool)));
}

MdiPDFReport::~MdiPDFReport()
{
    disconnect(ui->webEngineView, SIGNAL(loadFinished(bool)), this, SLOT(ReportLoaded(bool)));
    disconnect(ui->webEngineView, SIGNAL(pdfPrintingFinished(QString, bool)), this, SLOT(ReportPrinted(QString,bool)));
    delete ui;
}

void MdiPDFReport::resizeEvent(QResizeEvent *ev)
{
    ui->webEngineView->setGeometry(12, 36, ev->size().width() - 24, ev->size().height() - 48);
}

void MdiPDFReport::LoadReportData()
{
    try
    {
        reportData = QSharedPointer<ReportData>::create(reportFile, sqliteManager, this);
        if (!reportData.isNull())
        {
            const CVEReportDTO& reportDTO = reportData->getFullCVEReport();
            setWindowTitle(reportDTO.getFileName());
            ui->webEngineView->setHtml(reportData->getHtmlReport());
        }
    }
    catch (...)
    {
        QMessageBox::critical(this, "Export report failed", "Report loading failed");
    }
}

void MdiPDFReport::ReportLoaded(bool ok)
{
    try
    {
        if (ok)
        {
            PrintReport();
        }
        else
        {
            QMessageBox::critical(this, "Report load failed", "HTML report unseccesfully loaded");
            close();
        }
    }
    catch (...)
    {
        QMessageBox::critical(this, "Export report failed", "Report loading failed");
        close();
    }
}

QString MdiPDFReport::randomString(int length, QString string)
{
    static QString possibleCharacters("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");

    if (length <= 0)
        return string;
    else
        return randomString(--length, string.append(possibleCharacters.at(rand() % possibleCharacters.length())));
}

void MdiPDFReport::PrintReport()
{
    QString tmpFilePath = QDir::tempPath() + QDir::separator() + randomString(10) + ".pdf";
    ui->webEngineView->printToPdf(tmpFilePath, pageLayout);
}

void MdiPDFReport::ReportPrinted(const QString &fileName, bool success)
{
    try
    {
        if (success)
        {
            QFileDialog fileDialog;
            QString filePath = fileDialog.getSaveFileName(this, "Save pdf report", QDir::homePath(), "*.pdf");
            if (!filePath.isEmpty())
            {
                QFile destination(filePath);
                if (destination.exists(filePath))
                {
                    destination.remove(filePath);
                }

#if PDFWRITER
                if (eFailure == PDFModifyFooterContext(fileName, filePath))
                {
                    QMessageBox::critical(this, "Export report failed", "Report printing failed");
                    return;
                }
#else
                QFile::copy(fileName, filePath);
#endif
                QFile::remove(fileName);
            }
        }
    }
    catch (...)
    {
        QMessageBox::critical(this, "Export report failed", "Report printing failed");
    }
}

#if PDFWRITER
EStatusCode MdiPDFReport::PDFModifyFooterContext(const QString& srcFile, const QString& outFile)
{
    EStatusCode status = eSuccess;
    try
    {
        PDFWriter inPDFWriter;
        PDFDocumentCopyingContext* srcCopyContext = inPDFWriter.CreatePDFCopyingContext(srcFile.toStdString());
        PDFParser* srcPDFParser = srcCopyContext->GetSourceDocumentParser();

        PDFWriter outPDFWriter;
        outPDFWriter.StartPDF(outFile.toStdString(), ePDFVersion14);

        DocumentContext& outDocumentContext = outPDFWriter.GetDocumentContext();

        PDFUsedFont* font = outPDFWriter.GetFontForFile("DejaVuSerif-Bold.ttf", 0);
        if(!font)
        {
            status = eFailure;
            return status;
        }
        font->WriteFontDefinition();
        AbstractContentContext::TextOptions textOptions(font, 32, AbstractContentContext::eRGB, 50);

        unsigned long pagesNum = srcPDFParser->GetPagesCount();
        for (int i = 0; i < pagesNum; i++)
        {
            PDFPage page;
            page.SetMediaBox(PDFRectangle(0, 0, 595, 842));

            PageContentContext* pageContentContext = outPDFWriter.StartPageContentContext(&page);
            if (pageContentContext)
            {
                PDFPageRange singlePageRange;
                singlePageRange.mType = PDFPageRange::eRangeTypeSpecific;
                singlePageRange.mSpecificRanges.push_back(ULongAndULong(i,i));

                status = outPDFWriter.MergePDFPagesToPage(&page, srcFile.toStdString(), singlePageRange);
                if(status != PDFHummus::eSuccess)
                    break;

                pageContentContext->cm(1,0,0,-1,0,3600);

                std::string confidential = QString("%1").arg(tr("CONFIDENTIAL")).toStdString();
                PDFUsedFont::TextMeasures confidentialTextDimensions = font->CalculateTextDimensions(confidential, 14);
                pageContentContext->WriteText(180, 180, confidential, textOptions);
                std::string filename = QString("%1").arg(reportData->getFullCVEReport().getFileName()).toStdString();
                PDFUsedFont::TextMeasures filenameTextDimensions = font->CalculateTextDimensions(filename, 14);
                pageContentContext->WriteText(2400/2 - filenameTextDimensions.width/2 - 180, 180, filename, textOptions);
                std::string pagenumber = QString("%1: %2/%3").arg(tr("Page")).arg(i+1).arg(pagesNum).toStdString();
                PDFUsedFont::TextMeasures pageNumberTextDimensions = font->CalculateTextDimensions(pagenumber, 14);
                pageContentContext->WriteText(2400 - 180 - pageNumberTextDimensions.width, 180, pagenumber, textOptions);

                status = outPDFWriter.EndPageContentContext(pageContentContext);
                if(status != PDFHummus::eSuccess)
                    break;

                outPDFWriter.WritePage(&page);
            }
        }

        srcCopyContext->End();
        delete srcCopyContext;
        outPDFWriter.EndPDF();
        inPDFWriter.Reset();
    }
    catch (...)
    {
        QMessageBox::critical(this, "Export report failed", "Report modify footer failed");
    }
    return status;
}
#endif
