/*!
   QCVECheckReport project

   @file: html2pdfconverter.cpp

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
