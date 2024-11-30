#include "html2pdfconverter.h"
#include <QApplication>

Html2PdfConverter::Html2PdfConverter(QString inputPath, QString outputPath)
    : m_inputPath(std::move(inputPath))
    , m_outputPath(std::move(outputPath))
    , m_view(new QWebEngineView)
{
    connect(m_view.data(), &QWebEngineView::loadFinished,
            this, &Html2PdfConverter::loadFinished);
    connect(m_view.data(), &QWebEngineView::pdfPrintingFinished,
            this, &Html2PdfConverter::pdfPrintingFinished);
}

int Html2PdfConverter::run()
{
    m_view->load(QUrl::fromUserInput(m_inputPath));
    return QCoreApplication::exec();
}

void Html2PdfConverter::loadFinished(bool ok)
{
    if (!ok) {
        QTextStream(stderr)
            << tr("failed to load URL '%1'").arg(m_inputPath) << "\n";
        QCoreApplication::exit(1);
        return;
    }

    m_view->printToPdf(m_outputPath);
}

void Html2PdfConverter::pdfPrintingFinished(const QString &filePath, bool success)
{
    if (!success) {
        QTextStream(stderr)
            << tr("failed to print to output file '%1'").arg(filePath) << "\n";
        QCoreApplication::exit(1);
    } else {
        QCoreApplication::quit();
    }
}
