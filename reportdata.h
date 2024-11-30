/*!
   QCVECheckReport project

   @file: reportdata.h

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

#ifndef REPORTDATA_H
#define REPORTDATA_H

#include "DTO/cvereportdto.h"
#include "qpdfwriter.h"
#include "qsqlitemanager.h"
#include <QSqlTableModel>
#include <QObject>
#include <QSqlRecord>
#include <QTextDocument>

class ReportData : public QObject
{
    Q_OBJECT

public:
    enum class CVSS2Severity
    {
        Low,
        Medium,
        High
    };

    enum class CVSS3Severity
    {
        None,
        Low,
        Medium,
        High,
        Critical
    };

    enum class AttackVector
    {
        Unknown,
        Network,
        Adjacent,
        Local,
        Phisical
    };

    enum class Complessity
    {
        Low,
        High
    };

    enum class PrivilegesRequired
    {
        None,
        Low,
        High
    };

    enum class UserInteraction
    {
        None,
        Required
    };

    enum class Scope
    {
        Unchanged,
        Changed
    };

    enum class ConfidentialityImpact
    {
        None,
        Low,
        High
    };

    enum class IntegrityImpact
    {
        None,
        Low,
        High
    };

    enum class AvailabilityImpact
    {
        None,
        Low,
        High
    };

    enum class ExploitCodeMaturity
    {
        Undefined,
        Unproven,
        ProofOfConcept,
        Functional,
        High
    };

    enum class RemediationLevel
    {
        NotDefined,
        Unavailable,
        Workaround,
        TemporaryFix,
        OfficialFix
    };

    enum class ReportConfidence
    {
        NotDefined,
        Unknown,
        Reasonable,
        Confirmed
    };

    enum class SecurityRequirements
    {
        NotDefined,
        Low,
        Medium,
        High
    };

    struct Summary {
        struct SeveritySummary {
            qint64 None = 0;
            qint64 Low = 0;
            qint64 Medium = 0;
            qint64 High = 0;
            qint64 Critical = 0;
        } severitySummary;

        struct UnpatchedCVEBySeverity {
            qint64 None = 0;
            qint64 Low = 0;
            qint64 Medium = 0;
            qint64 High = 0;
            qint64 Critical = 0;
        } unpatchedCVEBySeverity;

        struct PackagesWithKnowenCVS {
            qint64 Unknowen = 0;
            qint64 Patched = 0;
            qint64 Unpatched = 0;
            qint64 Ignored = 0;
        } packagesWithKnowenCVS;
    };

    explicit ReportData(const QString reportFile, QSQLiteManager* sqlManager, QObject *parent = nullptr);

    ~ReportData() override;

    const CVEReportDTO& getFullCVEReport() const { return static_cast<const CVEReportDTO&>(*fullCVEReport); };
    const Summary& getSummary() { return summary; };
    QSqlQueryModel* getPackages() { return packages; };
    QSqlQueryModel* getCVEs() { return cves; };
    QSqlQueryModel* getIgnoredCVEs() { return ignoredCVEs; };

    qint64 selectPackagesRowCount(bool showUnpatchedOnly=false, const QString &filter=QString(""));
    qint64 selectCVEsRowCount(qint64 packageID=0, const QString& status=QString(""), const QString& vector=QString(""), double startingCVSS3 = 0, double endingCVSS3 = 10, const QString& filter=QString(""));
    qint64 selectIgnoredCVEsRowCount(const QString &filter=QString(""));

    QTextDocument* GenerateHtmlReport();
    QString getHtmlReport();

public slots:
    void selectPackages(bool showUnpatchedOnly, int entries, int page, const QString &filter);
    void selectCVEs(qint64 packageID, const QString& status, const QString& vector, double startingCVSS3, double endingCVSS3, int entries, int page, const QString& filter);
    void selectIgnoredCVEs(int entries, int page, const QString &filter);

protected:
    AbstractDTO::SharedDTO fullCVEReport;
    struct Summary summary;
    QSqlQueryModel* packages;
    QSqlQueryModel* cves;
    QSqlQueryModel* ignoredCVEs;

private:
    QString reportName;
    QSQLiteManager* sqliteManager;
    void LoadReportData();
    bool CalculateSummary();
    QPdfWriter* pdfWriter;    
    QString setStyleSheet();
    QString getHtmlHeader();
    QString getHtmlBody();
    QString getHtmlReportGeneralInformation();
    QString getHtmlReportSummary();
    QString getHtmlReportPackages();
    QString getHtmlReportUnpatchedCriticalCVEs();
    QString getHtmlReportUnpatchedHighCVEs();
    QString getHtmlReportUnpatchedMediumCVEs();
    QString getHtmlReportUnpatchedLowCVEs();
    QString getHtmlReportUnpatchedNoneCVEs();
    QString getHtmlReportIgnoredCVEs();
};

#endif // REPORTDATA_H
