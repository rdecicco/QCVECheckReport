#include "mdipdfreport.h"
#include "AbstractContentContext.h"
#include "PDFDocumentCopyingContext.h"
#include "PDFModifiedPage.h"
#include "PDFUsedFont.h"
#include "qmessagebox.h"
#include "ui_mdipdfreport.h"
#include <QResizeEvent>
#include <QFileDialog>
#include <QWebEngineProfile>
#include <QPrinterInfo>
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

                if (eFailure == PDFModifyFooterContext(fileName, filePath))
                {
                    QMessageBox::critical(this, "Export report failed", "Report printing failed");
                    return;
                }

                QFile::remove(fileName);
            }
        }
    }
    catch (...)
    {
        QMessageBox::critical(this, "Export report failed", "Report printing failed");
    }
}


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
