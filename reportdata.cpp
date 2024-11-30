/*!
   QCVECheckReport project

   @file: reportdata.cpp

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


#include "reportdata.h"
#include "DTO/issuedto.h"
#include "DTO/nvddto.h"
#include "DTO/packagedto.h"
#include "qsqlitemanager.h"
#include <QMessageBox>

ReportData::ReportData(const QString reportFile, QSQLiteManager *sqlManager, QObject *parent)
    : QObject{parent}, reportName(reportFile), sqliteManager(sqlManager)
{
    LoadReportData();
}

ReportData::~ReportData()
{
}

void ReportData::LoadReportData()
{
    try
    {
        if (sqliteManager)
        {
            fullCVEReport = sqliteManager->getFullCVEReport(reportName);
            if (!CalculateSummary())
            {
                QMessageBox::critical(nullptr, "Summary Error", "Processing of summary failed");
            }
            packages = sqliteManager->getPackagesModel();
            cves = sqliteManager->getCVEsModel();
            ignoredCVEs = sqliteManager->getIgnoredCVEsModel();
        }
    }
    catch (...)
    {

    }
}

bool ReportData::CalculateSummary()
{
    try
    {
        if (fullCVEReport)
        {
            const CVEReportDTO& cveReportDTO = getFullCVEReport();
            for (auto& package : cveReportDTO.getPackages())
            {
                const PackageDTO* packageDTO = static_cast<const PackageDTO*>(package.get());
                if (packageDTO)
                {
                    if (packageDTO->getIssues().count() > 0)
                    {
                        for (auto& sharedIssueDTO : packageDTO->getIssues())
                        {
                            const IssueDTO* issueDTO = static_cast<const IssueDTO*>(sharedIssueDTO.get());
                            if (issueDTO)
                            {
                                const NVDDTO* nvdDTO = static_cast<const NVDDTO*>(issueDTO->getNVD().get());
                                if (nvdDTO)
                                {
                                    qint64 CVSS2Score = nvdDTO->getScoreV2().remove('.').toLongLong();
                                    qint64 CVSS3Score  = nvdDTO->getScoreV3().remove('.').toLongLong();

                                    QString status = issueDTO->getStatus();
                                    if (status == "Patched")
                                    {
                                        summary.packagesWithKnowenCVS.Patched++;
                                    }
                                    else if (status == "Unpatched")
                                    {
                                        summary.packagesWithKnowenCVS.Unpatched++;

                                        if (CVSS3Score >= 90)
                                        {
                                            summary.unpatchedCVEBySeverity.Critical++;
                                        }
                                        else if (CVSS3Score >= 70 && CVSS3Score < 90)
                                        {
                                            summary.unpatchedCVEBySeverity.High++;
                                        }
                                        else if (CVSS3Score >= 40 && CVSS3Score < 70)
                                        {
                                            summary.unpatchedCVEBySeverity.Medium++;
                                        }
                                        else if (CVSS3Score >= 1 && CVSS3Score < 40)
                                        {
                                            summary.unpatchedCVEBySeverity.Low++;
                                        }
                                        else if (CVSS3Score < 1)
                                        {
                                            summary.unpatchedCVEBySeverity.None++;
                                        }
                                    }
                                    else if (status == "Ignored")
                                    {
                                        summary.packagesWithKnowenCVS.Ignored++;
                                    }

                                    if (CVSS3Score >= 90)
                                    {
                                        summary.severitySummary.Critical++;
                                    }
                                    else if (CVSS3Score >= 70 && CVSS3Score < 90)
                                    {
                                        summary.severitySummary.High++;
                                    }
                                    else if (CVSS3Score >= 40 && CVSS3Score < 70)
                                    {
                                        summary.severitySummary.Medium++;
                                    }
                                    else if (CVSS3Score >= 1 && CVSS3Score < 40)
                                    {
                                        summary.severitySummary.Low++;
                                    }
                                    else if (CVSS3Score < 1)
                                    {
                                        summary.severitySummary.None++;
                                    }
                                }
                            }
                        }
                    }
                    else
                    {
                        summary.packagesWithKnowenCVS.Unknowen++;
                    }
                }
            }
            return true;
        }
    }
    catch (...)  {
        return false;
    }
    return false;
}

void ReportData::selectPackages(bool showUnpatchedOnly, int entries, int page, const QString& filter)
{
    sqliteManager->setPackagesModelQuery(reportName, showUnpatchedOnly, entries, page, filter);
}

qint64 ReportData::selectPackagesRowCount(bool showUnpatchedOnly, const QString& filter)
{
    return sqliteManager->getPackagesRowCount(reportName, showUnpatchedOnly, filter);
}

void ReportData::selectCVEs(qint64 packageID, const QString& status, const QString& vector, double startingCVSS3, double endingCVSS3, int entries, int page, const QString& filter)
{
    sqliteManager->setCVEsModelQuery(reportName, packageID,  status, vector, startingCVSS3, endingCVSS3, entries, page, filter);
}

qint64 ReportData::selectCVEsRowCount(qint64 packageID, const QString& status, const QString& vector, double startingCVSS3, double endingCVSS3, const QString& filter)
{
    return sqliteManager->getCVEsRowCount(reportName, packageID,  status, vector, startingCVSS3, endingCVSS3, filter);
}

void ReportData::selectIgnoredCVEs(int entries, int page, const QString& filter)
{
    sqliteManager->setIgnoredCVEsModelQuery(reportName, entries, page, filter);
}

qint64 ReportData::selectIgnoredCVEsRowCount(const QString& filter)
{
    return sqliteManager->getIgnoredCVEsRowCount(reportName, filter);
}

QTextDocument* ReportData::GenerateHtmlReport()
{
    QTextDocument* htmlDocument = new QTextDocument(this);
    htmlDocument->setHtml(getHtmlReport());
    return htmlDocument;
}

QString ReportData::getHtmlReport()
{
    QString htmlReport;
    htmlReport.append("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN \"http://www.w3.org/TR/html4/strict.dtd\">");
    htmlReport.append("<HTML>");
    htmlReport.append(getHtmlHeader());
    htmlReport.append(getHtmlBody());
    htmlReport.append("</HTML>");
    return htmlReport;
}

QString ReportData::setStyleSheet()
{
    double totalUnpatchedRatio = (summary.unpatchedCVEBySeverity.Critical + summary.unpatchedCVEBySeverity.High + summary.unpatchedCVEBySeverity.Low + summary.unpatchedCVEBySeverity.Medium + summary.unpatchedCVEBySeverity.None) / 360.0f;
    double totalPackagesWithKnowenCVEsRatio = (summary.packagesWithKnowenCVS.Unpatched + summary.packagesWithKnowenCVS.Patched + summary.packagesWithKnowenCVS.Ignored) / 360.0f;
    QString htmlStyle = QString("<STYLE>");
    htmlStyle.append("body {"
                     "font-family: verdana;"
                     "backgroud-color: #101010h;"
                     "text-align: center;"
                     "}"
                     "h1 {"
                     "text-align: center;"
                     "}"
                     "h2 {"
                     "margin-top: 5mm;"
                     "text-align: center;"
                     "}"
                     "h3 {"
                     "text-align: center;"
                     "}"
                     "p {"
                     "text-align: center;"
                     "}"
                     "div { page-break-inside: avoid; }"
                     "table {"
                     "padding: 5px;"
                     "margin-left: auto;"
                     "margin-right: auto;"
                     "margin-bottom: 5mm;"
                     "page-break-inside:auto;"
                     "}"
                     "table .content {"
                     "border: 2px double black;"
                     "border-radius: 5px;"
                     "padding: 5px;"
                     "text-align: center;"
                     "margin-left: auto;"
                     "margin-right: auto;"
                     "page-break-inside:auto;"
                     "}"
                     "table .content tr { "
                     "page-break-inside:auto; page-break-after:auto;"
                     "}"
                     "table .content thead "
                     "{"
                     "display:table-header-group;"
                     "}"
                     "table .content tfoot { "
                     "display:table-footer-group;"
                     "}"
                     "table .content th {"
                     "font-size: 8pt;"
                     "border: 1px solid black;"
                     "text-align: center;"
                     "padding: 5px;"
                     "background-color: darkcyan;"
                     "}"
                     "table .content td {"
                     "border: 1px solid black;"
                     "font-size: 6pt;"
                     "text-align: center;"
                     "padding: 5px;"
                     "}"
                     "table .content td .chart {"
                     "text-align: center;"
                     "}"
                     ".unpatchedCVEBySeverityPieChart {"
                     "width: 200px;"
                     "height: 200px;"
                     "border-radius: 50%;"
                     "margin-right: auto;"
                     "margin-left: auto;" +
                     QString("background-image: conic-gradient("
                             "green 0deg %1deg,"
                             "steelblue %1deg %2deg,"
                             "gold %2deg %3deg,"
                             "orange %3deg %4deg,"
                             "red %4deg %5deg"
                             ");")
                         .arg(summary.unpatchedCVEBySeverity.None/totalUnpatchedRatio)
                         .arg((summary.unpatchedCVEBySeverity.None + summary.unpatchedCVEBySeverity.Low)/totalUnpatchedRatio)
                         .arg((summary.unpatchedCVEBySeverity.None + summary.unpatchedCVEBySeverity.Low + summary.unpatchedCVEBySeverity.Medium)/totalUnpatchedRatio)
                         .arg((summary.unpatchedCVEBySeverity.None + summary.unpatchedCVEBySeverity.Low + summary.unpatchedCVEBySeverity.Medium +summary.unpatchedCVEBySeverity.High)/totalUnpatchedRatio)
                         .arg((summary.unpatchedCVEBySeverity.None + summary.unpatchedCVEBySeverity.Low + summary.unpatchedCVEBySeverity.Medium +summary.unpatchedCVEBySeverity.High + summary.unpatchedCVEBySeverity.Critical)/totalUnpatchedRatio) +
                     "}"
                     ".packagesWithKnowenCVEsPieChart {"
                     "width: 200px;"
                     "height: 200px;"
                     "border-radius: 50%;"
                     "margin-right: auto;"
                     "margin-left: auto;" +
                     QString("background-image: conic-gradient("
                             "green 0deg %1deg,"
                             "red %1deg %2deg,"
                             "blue %2deg %3deg"
                             ");")
                         .arg(summary.packagesWithKnowenCVS.Patched/totalPackagesWithKnowenCVEsRatio)
                         .arg((summary.packagesWithKnowenCVS.Patched + summary.packagesWithKnowenCVS.Unpatched)/totalPackagesWithKnowenCVEsRatio)
                         .arg((summary.packagesWithKnowenCVS.Patched + summary.packagesWithKnowenCVS.Unpatched + summary.packagesWithKnowenCVS.Ignored)/totalPackagesWithKnowenCVEsRatio) +
                     "}"
                     /* basic positioning */
                     ".legend { list-style: block; }"
                     ".legend li { display: inline-block; font-size: 8pt; margin-right: 10px; }"
                     ".legend span { border: 1px solid #ccc; float: left; width: 10px; height: 10px; margin-left: 2px }"
                     ".legend nobr { margin-left: 2px; }"
                     /* your colors */
                     ".legend .unpatchedCVEBySeverityNone { background-color: green; }"
                     ".legend .unpatchedCVEBySeverityLow { background-color: steelblue; }"
                     ".legend .unpatchedCVEBySeverityMedium { background-color: gold; }"
                     ".legend .unpatchedCVEBySeverityHigh { background-color: orange; }"
                     ".legend .unpatchedCVEBySeverityCritical { background-color: red; }"
                     ".legend .packagesWithKnowenCVEsPatched { background-color: green; }"
                     ".legend .packagesWithKnowenCVEsUnpatched { background-color: red; }"
                     ".legend .packagesWithKnowenCVEsIgnored { background-color: blue; }"
                     "@media print {"
                     "@page {"
                     "size: A4;"
                     "}"
                     ".pagebreak {"
                     "page-break-after: always;"
                     "padding-top: 20mm;"
                     "}"
                     "body {"
                     "counter-reset: pageNumber;"
                     "display: table;"
                     "table-layout: fixed;"
                     "padding-top: 50px;"
                     "padding-bottom: 50px;"
                     "height: 28mm;"
                     "page-break-inside:auto;"
                     "}"
                     "div { page-break-inside: auto; }"
                     "table {"                     
                     "margin-left: auto;"
                     "margin-right: auto;"
                     "width: 190mm;"
                     "}"
                     "#pagelayout {"
                     "page-break-inside: always;"
                     "margin-top: 50px;"
                     "margin-bottom: 50px;"
                     "}"
                     "table .content {"
                     "page-break-inside: auto;"
                     "border: 2px double black;"
                     "border-radius: 5px;"
                     "text-align: center;"
                     "margin-left: auto;"
                     "margin-right: auto;"
                     "}"
                     "table .content tr { page-break-inside: auto; page-break-after: auto; }"
                     "table .content thead { display: table-header-group; }"
                     "table .content tfoot { display: table-footer-group; }"
                     "table .content tbody {"
                     "margin-left: auto;"
                     "margin-right: auto;"
                     "}"
                     "#header {"
                     "position: absolute;"
                     "width: 100%;"
                     "top: 0;"
                     "left: 0;"
                     "right: 0;"
                     "}"
                     "#footer {"
                     "display: none;"
                     "position: fixed;"
                     "width: 100%;"
                     "bottom: 0;"
                     "left: 0;"
                     "right: 0;"
                     "}"
                     "span.page-number::before {"
                     "counter-increment: pagenumber;"
                     "content: counter(pagenumber);"
                     "}"
                     "}"
                     "@media screen {"
                     "span.page-number::after {"
                     "content: 'All pages';"
                     "}"
                     "}"
                     );
    htmlStyle.append("</STYLE>");
    return htmlStyle;
}

QString ReportData::getHtmlHeader()
{
    QString htmlHeader = QString("<HEAD>"
                                 "<TITLE>%1</TITLE>"
                                 + setStyleSheet() +
                                 "</HEAD>").arg(reportName);
    return htmlHeader;
}

QString ReportData::getHtmlBody()
{
    QString htmlBody = QString("<BODY>");
    htmlBody.append("<DIV id='pagelayout' style='overflow-x:auto;'>");
    htmlBody.append("<TABLE>");
    htmlBody.append("<THEAD id='header'>");
    htmlBody.append(QString("<TR><TH width='30%'><IMG src='qrc:///CVE.png' align='center' width='100' height='100'/></TH><TH style='font-size: 24pt;' width='40%'><B>%1</B></TH><TH width='30%'><IMG src='qrc:///CVE.png' align='center' width='100' height='100'/></TH></TR>").arg(tr("CVECheck Report")));
    htmlBody.append("</THEAD>");
    htmlBody.append("<TBODY>");
    htmlBody.append("<TR><TD colspan='3'>");
    htmlBody.append(getHtmlReportGeneralInformation());
    htmlBody.append("</TD></TR>");
    htmlBody.append("<TR><TD colspan='3'>");
    htmlBody.append(getHtmlReportSummary());
    htmlBody.append("</TD></TR>");
    htmlBody.append("<TR><TD colspan='3'>");
    htmlBody.append(("<div class='pagebreak'></div>"));
    htmlBody.append("</TD></TR>");
    htmlBody.append("<TR><TD colspan='3'>");
    htmlBody.append(getHtmlReportPackages());
    htmlBody.append("</TD></TR>");
    htmlBody.append("<TR><TD colspan='3'>");
    htmlBody.append(("<div class='pagebreak'></div>"));
    htmlBody.append("</TD></TR>");
    htmlBody.append("<TR><TD colspan='3'>");
    htmlBody.append(getHtmlReportUnpatchedCriticalCVEs());
    htmlBody.append("</TD></TR>");
    htmlBody.append("<TR><TD colspan='3'>");
    htmlBody.append(("<div class='pagebreak'></div>"));
    htmlBody.append("</TD></TR>");
    htmlBody.append("<TR><TD colspan='3'>");
    htmlBody.append(getHtmlReportUnpatchedHighCVEs());
    htmlBody.append("</TD></TR>");
    htmlBody.append("<TR><TD colspan='3'>");
    htmlBody.append(("<div class='pagebreak'></div>"));
    htmlBody.append("</TD></TR>");
    htmlBody.append("<TR><TD colspan='3'>");
    htmlBody.append(getHtmlReportUnpatchedMediumCVEs());
    htmlBody.append("</TD></TR>");
    htmlBody.append("<TR><TD colspan='3'>");
    htmlBody.append(("<div class='pagebreak'></div>"));
    htmlBody.append("</TD></TR>");
    htmlBody.append("<TR><TD colspan='3'>");
    htmlBody.append(getHtmlReportUnpatchedLowCVEs());
    htmlBody.append("</TD></TR>");
    htmlBody.append("<TR><TD colspan='3'>");
    htmlBody.append(("<div class='pagebreak'></div>"));
    htmlBody.append("</TD></TR>");
    htmlBody.append("<TR><TD colspan='3'>");
    htmlBody.append(getHtmlReportUnpatchedNoneCVEs());
    htmlBody.append("</TD></TR>");
    htmlBody.append("<TR><TD colspan='3'>");
    htmlBody.append(("<div class='pagebreak'></div>"));
    htmlBody.append("</TD></TR>");
    htmlBody.append("<TR><TD colspan='3'>");
    htmlBody.append(getHtmlReportIgnoredCVEs());
    htmlBody.append("</TD></TR>");
    htmlBody.append("</TBODY>");
    htmlBody.append("<TFOOT id='footer'>");
    htmlBody.append(QString("<TR align='bottom'><TD align='center' width='30%'>CONFIDENTIAL</TD><TD align='center'>%1</TD><TD align='center' width='30%'><span class='page-number'/></TD></TR>").arg(reportName));
    htmlBody.append("</TFOOT>");
    htmlBody.append("</DIV>");
    htmlBody.append("</BODY>");
    return htmlBody;
}

QString ReportData::getHtmlReportGeneralInformation()
{
    CVEReportDTO* reportDTO = static_cast<CVEReportDTO*>(fullCVEReport.get());
    QString generalInformation = QString("<H2>%1</H2>").arg(tr("General Information"));
    generalInformation.append(QString("<TABLE class='content' width='90%'>"));
    generalInformation.append(QString("<TR><TH colspan='2'>%1: %2</TH></TR>").arg(tr("Report Name")).arg(reportName));
    generalInformation.append(QString("<TR><TD width='50%'>%1: %2</TD><TD width='50%'>%3: %4</TD></TR>").arg(tr("Owner")).arg(reportDTO->getOwner()).arg(tr("Date")).arg(reportDTO->getDate().toLocalTime().toString()));
    generalInformation.append("</TABLE>");
    return generalInformation;
}

QString ReportData::getHtmlReportSummary()
{
    QString summary = QString("<H2>%1</H2>").arg(tr("Report Summary"));
    summary.append("<TABLE class='content' width='90%'>");
    summary.append(QString("<TR><TH colspan='2'>%1</TH></TR>").arg(tr("CVEs")));
    summary.append(QString("<TR><TD width='50%'>%1: %2</TD><TD width='50%'>%3: %4</TD></TR>").arg(tr("Unpatched")).arg(this->summary.packagesWithKnowenCVS.Unpatched).arg("Patched").arg(this->summary.packagesWithKnowenCVS.Patched));
    summary.append(QString("<TR><TD>%1: %2</TD><TD>%3: %4</TD></TR>").arg(tr("Unpatched Critical/High")).arg(this->summary.unpatchedCVEBySeverity.High + this->summary.unpatchedCVEBySeverity.Critical).arg("Ignored").arg(this->summary.packagesWithKnowenCVS.Ignored));
    summary.append(QString("<TR><TD><DIV class='unpatchedCVEBySeverityPieChart'/></TD><TD align='center'><DIV class='packagesWithKnowenCVEsPieChart'/></TD></TR>"));
    summary.append(QString("<TR><TD valign='middle'>"
                           "<ul class='legend'>"
                           "<li><span class='unpatchedCVEBySeverityNone'></span><nobr>None (%1)</nobr></li>"
                           "<li><span class='unpatchedCVEBySeverityLow'></span><nobr>Low (%2)</nobr></li>"
                           "<li><span class='unpatchedCVEBySeverityMedium'></span><nobr>Medium (%3)</nobr></li>"
                           "<li><span class='unpatchedCVEBySeverityHigh'></span><nobr>High (%4)</nobr></li>"
                           "<li><span class='unpatchedCVEBySeverityCritical'></span><nobr>Critical (%5)</nobr></li>"
                           "</ul>"
                           "</TD><TD valign='middle'>"
                           "<ul class='legend'>"
                           "<li><span class='packagesWithKnowenCVEsPatched'></span><nobr>Patched (%6)</nobr></li>"
                           "<li><span class='packagesWithKnowenCVEsUnpatched'></span><nobr>Unpatched (%7)</nobr></li>"
                           "<li><span class='packagesWithKnowenCVEsIgnored'></span><nobr>Ignored (%8)</nobr></li>"
                           "</ul>"
                           "</TD></TR>")
                       .arg(this->summary.unpatchedCVEBySeverity.None)
                       .arg(this->summary.unpatchedCVEBySeverity.Low)
                       .arg(this->summary.unpatchedCVEBySeverity.Medium)
                       .arg(this->summary.unpatchedCVEBySeverity.High)
                       .arg(this->summary.unpatchedCVEBySeverity.Critical)
                       .arg(this->summary.packagesWithKnowenCVS.Patched)
                       .arg(this->summary.packagesWithKnowenCVS.Unpatched)
                       .arg(this->summary.packagesWithKnowenCVS.Ignored)
                   );
    summary.append("</TABLE>");
    return summary;
}

QString ReportData::getHtmlReportPackages()
{
    QString html = QString("<H2>%1</H2>").arg(tr("Unpatched Packages"));
    html.append(QString("<TABLE class='content' width='90%'>"));
    QList<QVariantList> packages = sqliteManager->getPackagesRecords(reportName);
    html.append("<THEAD>"
                "<TR><TH colspan='11'>" +
                QString("<B>%1</B>").arg(tr("Unpatched Packages")) +
                "</TH></TR>"
                "<TR><TH>Name</TH><TH>Layer</TH><TH>Version</TH><TH>Critical</TH><TH>High</TH><TH>Medium</TH><TH>Low</TH><TH>None</TH><TH>Unpatched</TH><TH>Patched</TH><TH>Ignored</TH></TR>"
                "</THEAD>");
    html.append("<TBODY>");
    for (auto& package : packages)
    {
        html.append("<TR>");
        html.append("<TD width=150>" + package.at(1).toString() + "</TD>"); //Name
        html.append("<TD width=150>" + package.at(2).toString() + "</TD>"); //Layer
        html.append("<TD width=240>" + package.at(3).toString() + "</TD>"); //Version
        html.append(QString("<TD bgcolor='%1' width=100>" + package.at(5).toString() + "</TD>").arg(package.at(5).toInt()==0 ? "transparent" : "red")); //Critical
        html.append(QString("<TD bgcolor='%1' width=100>" + package.at(6).toString() + "</TD>").arg(package.at(6).toInt()==0 ? "transparent" : "orange")); //High
        html.append(QString("<TD bgcolor='%1' width=100>" + package.at(7).toString() + "</TD>").arg(package.at(7).toInt()==0 ? "transparent" : "gold")); //Medium
        html.append(QString("<TD bgcolor='%1' width=100>" + package.at(8).toString() + "</TD>").arg(package.at(8).toInt()==0 ? "transparent" : "steelblue")); //Low
        html.append(QString("<TD bgcolor='%1' width=100>" + package.at(9).toString() + "</TD>").arg(package.at(9).toInt()==0 ? "transparent" : "green")); //None
        html.append("<TD width=10%>" + package.at(10).toString() + "</TD>"); //Unpatched
        html.append("<TD width=10%>" + package.at(11).toString() + "</TD>"); //Patched
        html.append("<TD width=10%>" + package.at(12).toString() + "</TD>"); //Ignored
        html.append("</TR>");
    }
    html.append("</TBODY>");
    html.append("</TABLE>");
    return html;
}

QString ReportData::getHtmlReportUnpatchedCriticalCVEs()
{
    QString html = QString("<H2>%1</H2>").arg(tr("Unpatched Critical CVEs"));
    html.append(QString("<TABLE class='content' width='90%'>"));
    QList<QVariantList> cves = sqliteManager->getCVEsRecords(reportName, 0, "Unpatched", "", 9.0f, 10.0f);
    html.append("<THEAD>"
                "<TR><TH colspan='7'>" +
                QString("<B>%1</B>").arg(tr("Unpatched Critical CVEs")) +
                "</TH></TR>"
                "<TR><TH>Name</TH><TH>Layer</TH><TH>Version</TH><TH>NVDID</TH><TH>CVSS3 Score</TH><TH>Vector</TH><TH>Link</TH></TR>"
                "</THEAD>");
    html.append("<TBODY>");
    for (auto& cve : cves)
    {
        html.append("<TR>");
        html.append("<TD width=150>" + cve.at(1).toString() + "</TD>"); //Name
        html.append("<TD width=150>" + cve.at(2).toString() + "</TD>"); //Layer
        html.append("<TD width=240>" + cve.at(3).toString() + "</TD>"); //Version
        html.append("<TD width=150>" + cve.at(6).toString() + "</TD>"); //NVDID
        html.append("<TD width=100>" + cve.at(7).toString() + "</TD>"); //CVSS3 Score
        html.append("<TD width=180>" + cve.at(8).toString() + "</TD>"); //Vector
        html.append("<TD>" + cve.at(9).toString() + "</TD>"); //Link
        html.append("</TR>");
    }
    html.append("</TBODY>");
    html.append("</TABLE>");
    return html;
}

QString ReportData::getHtmlReportUnpatchedHighCVEs()
{
    QString html = QString("<H2>%1</H2>").arg(tr("Unpatched High CVEs"));
    html.append(QString("<TABLE class='content' width='90%'>"));
    QList<QVariantList> cves = sqliteManager->getCVEsRecords(reportName, 0, "Unpatched", "", 7.0f, 8.9f);
    html.append("<THEAD>"
                "<TR><TH colspan='7'>" +
                QString("<B>%1</B>").arg(tr("Unpatched High CVEs")) +
                "</TH></TR>"
                "<TR><TH>Name</TH><TH>Layer</TH><TH>Version</TH><TH>NVDID</TH><TH>CVSS3 Score</TH><TH>Vector</TH><TH>Link</TH></TR>"
                "</THEAD>");
    html.append("<TBODY>");
    for (auto& cve : cves)
    {
        html.append("<TR>");
        html.append("<TD width=150>" + cve.at(1).toString() + "</TD>"); //Name
        html.append("<TD width=150>" + cve.at(2).toString() + "</TD>"); //Layer
        html.append("<TD width=240>" + cve.at(3).toString() + "</TD>"); //Version
        html.append("<TD width=150>" + cve.at(6).toString() + "</TD>"); //NVDID
        html.append("<TD width=100>" + cve.at(7).toString() + "</TD>"); //CVSS3 Score
        html.append("<TD width=180>" + cve.at(8).toString() + "</TD>"); //Vector
        html.append("<TD>" + cve.at(9).toString() + "</TD>"); //Link
        html.append("</TR>");
    }
    html.append("</TBODY>");
    html.append("</TABLE>");
    return html;
}

QString ReportData::getHtmlReportUnpatchedMediumCVEs()
{
    QString html = QString("<H2>%1</H2>").arg(tr("Unpatched Medium CVEs"));
    html.append(QString("<TABLE class='content' width='90%'>"));
    QList<QVariantList> cves = sqliteManager->getCVEsRecords(reportName, 0, "Unpatched", "", 4.0f, 6.9f);
    html.append("<THEAD>"
                "<TR><TH colspan='7'>" +
                QString("<B>%1</B>").arg(tr("Unpatched Medium CVEs")) +
                "</TH></TR>"
                "<TR><TH>Name</TH><TH>Layer</TH><TH>Version</TH><TH>NVDID</TH><TH>CVSS3 Score</TH><TH>Vector</TH><TH>Link</TH></TR>"
                "</THEAD>");
    html.append("<TBODY>");
    for (auto& cve : cves)
    {
        html.append("<TR>");
        html.append("<TD width=150>" + cve.at(1).toString() + "</TD>"); //Name
        html.append("<TD width=150>" + cve.at(2).toString() + "</TD>"); //Layer
        html.append("<TD width=240>" + cve.at(3).toString() + "</TD>"); //Version
        html.append("<TD width=150>" + cve.at(6).toString() + "</TD>"); //NVDID
        html.append("<TD width=100>" + cve.at(7).toString() + "</TD>"); //CVSS3 Score
        html.append("<TD width=180>" + cve.at(8).toString() + "</TD>"); //Vector
        html.append("<TD>" + cve.at(9).toString() + "</TD>"); //Link
        html.append("</TR>");
    }
    html.append("</TBODY>");
    html.append("</TABLE>");
    return html;
}

QString ReportData::getHtmlReportUnpatchedLowCVEs()
{
    QString html = QString("<H2>%1</H2>").arg(tr("Unpatched Low CVEs"));
    html.append(QString("<TABLE class='content' width='90%'>"));
    QList<QVariantList> cves = sqliteManager->getCVEsRecords(reportName, 0, "Unpatched", "", 0.1f, 3.9f);
    html.append("<THEAD>"
                "<TR><TH colspan='7'>" +
                QString("<B>%1</B>").arg(tr("Unpatched Low CVEs")) +
                "</TH></TR>"
                "<TR><TH>Name</TH><TH>Layer</TH><TH>Version</TH><TH>NVDID</TH><TH>CVSS3 Score</TH><TH>Vector</TH><TH>Link</TH></TR>"
                "</THEAD>");
    html.append("<TBODY>");
    for (auto& cve : cves)
    {
        html.append("<TR>");
        html.append("<TD width=150>" + cve.at(1).toString() + "</TD>"); //Name
        html.append("<TD width=150>" + cve.at(2).toString() + "</TD>"); //Layer
        html.append("<TD width=240>" + cve.at(3).toString() + "</TD>"); //Version
        html.append("<TD width=150>" + cve.at(6).toString() + "</TD>"); //NVDID
        html.append("<TD width=100>" + cve.at(7).toString() + "</TD>"); //CVSS3 Score
        html.append("<TD width=180>" + cve.at(8).toString() + "</TD>"); //Vector
        html.append("<TD>" + cve.at(9).toString() + "</TD>"); //Link
        html.append("</TR>");
    }
    html.append("</TBODY>");
    html.append("</TABLE>");
    return html;
}

QString ReportData::getHtmlReportUnpatchedNoneCVEs()
{
    QString html = QString("<H2>%1</H2>").arg(tr("Unpatched None CVEs"));
    html.append(QString("<TABLE class='content' width='90%'>"));
    QList<QVariantList> cves = sqliteManager->getCVEsRecords(reportName, 0, "Unpatched", "", 0.0f, 0.0f);
    html.append("<THEAD>"
                "<TR><TH colspan='7'>" +
                QString("<B>%1</B>").arg(tr("Unpatched None CVEs")) +
                "</TH></TR>"
                "<TR><TH>Name</TH><TH>Layer</TH><TH>Version</TH><TH>NVDID</TH><TH>CVSS3 Score</TH><TH>Vector</TH><TH>Link</TH></TR>"
                "</THEAD>");
    html.append("<TBODY>");
    for (auto& cve : cves)
    {
        html.append("<TR>");
        html.append("<TD width=150>" + cve.at(1).toString() + "</TD>"); //Name
        html.append("<TD width=150>" + cve.at(2).toString() + "</TD>"); //Layer
        html.append("<TD width=240>" + cve.at(3).toString() + "</TD>"); //Version
        html.append("<TD width=150>" + cve.at(6).toString() + "</TD>"); //NVDID
        html.append("<TD width=100>" + cve.at(7).toString() + "</TD>"); //CVSS3 Score
        html.append("<TD width=180>" + cve.at(8).toString() + "</TD>"); //Vector
        html.append("<TD>" + cve.at(9).toString() + "</TD>"); //Link
        html.append("</TR>");
    }
    html.append("</TBODY>");
    html.append("</TABLE>");
    return html;
}

QString ReportData::getHtmlReportIgnoredCVEs()
{
    QString html = QString("<H2>%1</H2>").arg(tr("Ignored CVEs"));
    html.append(QString("<TABLE class='content' width='90%'>"));
    QList<QVariantList> cves = sqliteManager->getIgnoredCVEsRecords(reportName);
    html.append("<THEAD>"
                "<TR><TH colspan='7'>" +
                QString("<B>%1</B>").arg(tr("Ignored CVEs")) +
                "</TH></TR>"
                "<TR><TH>Name</TH><TH>Layer</TH><TH>Version</TH><TH>NVDID</TH><TH>CVSS3 Score</TH><TH>Vector</TH><TH>Link</TH></TR>"
                "</THEAD>");
    html.append("<TBODY>");
    for (auto& cve : cves)
    {
        html.append("<TR>");
        html.append("<TD width=150>" + cve.at(1).toString() + "</TD>"); //Name
        html.append("<TD width=150>" + cve.at(2).toString() + "</TD>"); //Layer
        html.append("<TD width=240>" + cve.at(3).toString() + "</TD>"); //Version
        html.append("<TD width=150>" + cve.at(6).toString() + "</TD>"); //NVDID
        html.append("<TD width=100>" + cve.at(7).toString() + "</TD>"); //CVSS3 Score
        html.append("<TD width=180>" + cve.at(8).toString() + "</TD>"); //Vector
        html.append("<TD>" + cve.at(9).toString() + "</TD>"); //Link
        html.append("</TR>");
    }
    html.append("</TBODY>");
    html.append("</TABLE>");
    return html;
}
