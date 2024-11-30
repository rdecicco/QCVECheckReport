/*!
   QCVECheckReport project

   @file: qsqlitemanager.h

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

#ifndef QSQLITEMANAGER_H
#define QSQLITEMANAGER_H

#include <QObject>
#include <QSqlDatabase>
#include <QJsonDocument>
#include "DTO/abstractdto.h"
#include "DTO/packagedto.h"
#include "qmutex.h"
#include "qsqlquerymodel.h"
#include "qsqlresult.h"

class QSQLiteManager: public QObject
{
    Q_OBJECT
    const QString CVEReportsDBFile = "CVEReportsDB.db";

public:
    explicit QSQLiteManager(QObject *parent = nullptr);
    ~QSQLiteManager();

    bool openConnection();
    bool closeConnection();
    bool isNewReport(QString jsonReportFileName);
    bool importJson(const QString& FileName, const QJsonDocument& jsonCVEReport);
    bool importCVEDb(const QString &CVEDBFileName);
    QStringList getCVEReportsList();

    AbstractDTO::SharedDTO getFullCVEReport(const QString& reportName);

    QSqlQueryModel* getPackagesModel() { return packagesModel; };
    QSqlQueryModel* getCVEsModel() { return cvesModel; };
    QSqlQueryModel* getIgnoredCVEsModel() { return ignoredCVEsModel; };
    QSqlQueryModel* getNVDDataProductsModel() { return nvdDataProductsModel; };
    QSqlQueryModel* getNVDDataNVDsModel() { return nvdDataNVDsModel; };

    QList<PackageDTO> getAllPackages();
    qint64 getPackagesRowCount(const QString &reportName, bool showUnpatchedOnly = true, const QString &filter = QString(""));
    qint64 getCVEsRowCount(const QString& reportName, qint64 packageID = 0, const QString& status = QString(""), const QString& vector = QString(""), double startingCVSS3 = 0, double endingCVSS3 = 10, const QString& filter= QString(""));
    qint64 getIgnoredCVEsRowCount(const QString &reportName, const QString &filter = QString(""));

    qint64 getNVDDataNVDsRowCount(const QString& product = QString(""), const QString& vector = QString(""), double cvss3 = 0, const QString& filter= QString(""));
    qint64 getNVDDataProductsRowCount(const QString& productID = QString(""), const QString &filter = QString(""));

    QStringList getAllProductsNames();

    QList<QVariantList> getPackagesRecords(const QString& reportName, bool showUnpatchedOnly = true, int entries = 0, int page = 1, const QString &filter = QString(""));
    QList<QVariantList> getCVEsRecords(const QString& reportName, qint64 packageID = 0, const QString& status = QString(""), const QString& vector = QString(""), double startingCVSS3 = 0, double endingCVSS3 = 10, int entries = 0, int page = 1, const QString& filter = QString(""));
    QList<QVariantList> getIgnoredCVEsRecords(const QString& reportName, int entries = 0, int page = 1, const QString &filter = QString(""));

public slots:
    void setPackagesModelQuery(const QString& reportName, bool showUnpatchedOnly = true, int entries = 0, int page = 1, const QString &filter = QString(""));
    void setCVEsModelQuery(const QString& reportName, qint64 packageID = 0, const QString& status = QString(""), const QString& vector = QString(""), double startingCVSS3 = 0, double endingCVSS3 = 10, int entries = 0, int page = 1, const QString& filter = QString(""));
    void setIgnoredCVEsModelQuery(const QString& reportName, int entries = 0, int page = 1, const QString &filter = QString(""));

    void setNVDDataNVDsModelQuery(const QString& product = QString(""), const QString& vector = QString(""), double cvss3 = 0, int entries = 0, int page = 1, const QString& filter = QString(""));
    void setNVDDataProductsModelQuery(const QString &productID, int entries = 0, int page = 1, const QString &filter = QString(""));

protected:
    QString getPackagesQueryString(const QString& reportName, bool showUnpatchedOnly = true, int entries = 0, int page = 1, const QString &filter = QString(""));
    QString getCVEsQueryString(const QString& reportName, qint64 packageID = 0, const QString& status = QString(""), const QString& vector = QString(""), double startingCVSS3 = 0, double endingCVSS3 = 0, int entries = 0, int page = 1, const QString& filter = QString(""));
    QString getIgnoredCVEsQueryString(const QString& reportName, int entries = 0, int page = 1, const QString &filter = QString(""));

private:
    QSqlDatabase sqlDatabase;
    QSqlQueryModel* packagesModel;
    QSqlQueryModel* cvesModel;
    QSqlQueryModel* ignoredCVEsModel;
    QSqlQueryModel* nvdDataProductsModel;
    QSqlQueryModel* nvdDataNVDsModel;
    QMutex* m;
};

#endif // QSQLITEMANAGER_H
