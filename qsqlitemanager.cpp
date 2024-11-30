/*!
   QCVECheckReport project

   @file: qsqlitemanager.cpp

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

#include "qsqlitemanager.h"
#include "DAO/issuedao.h"
#include "DAO/nvddao.h"
#include "DAO/packagedao.h"
#include "DAO/packageproductdao.h"
#include "DAO/productdao.h"
#include "DTO/cvereportdto.h"
#include "DAO/cvereportdao.h"
#include "DTO/issuedto.h"
#include "DTO/packagedto.h"
#include "DTO/packageproductdto.h"
#include "qfileinfo.h"
#include <QSqlDriverCreator>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QSqlQuery>
#include <QException>
#include <QMessageBox>
#include <QSqlError>
#include <QSqlRecord>
#include <QStringBuilder>
#include <QSqlField>
#include <QFile>
#include <QSqlDriver>
#include <QSqlResult>
#include <QSqlQuery>

QSQLiteManager::QSQLiteManager(QObject *parent)
    : QObject{parent}, m(new QMutex())
{
    if (QFile::exists(CVEReportsDBFile))
    {
        sqlDatabase = QSqlDatabase::addDatabase("QSQLITE", CVEReportsDBFile);
        packagesModel = new QSqlQueryModel(this);
        cvesModel = new QSqlQueryModel(this);
        ignoredCVEsModel = new QSqlQueryModel(this);
        nvdDataNVDsModel = new QSqlQueryModel(this);
        nvdDataProductsModel = new QSqlQueryModel(this);
    }
    else
    {
        QMessageBox::critical(nullptr, tr("SQL Database Error"), tr("File not found"));
    }
}

bool QSQLiteManager::openConnection()
{
    try
    {
        if (!sqlDatabase.open())
        {
            QMessageBox::critical(nullptr, "SQL Database Error", sqlDatabase.lastError().text());
            return false;
        }
        if (!sqlDatabase.driver()->open(CVEReportsDBFile))
        {
            QMessageBox::critical(nullptr, "SQL Database Error", sqlDatabase.lastError().text());
            closeConnection();
            return false;
        }
    }
    catch (...)
    {                
        closeConnection();
    }
    return true;
}

bool QSQLiteManager::closeConnection()
{
    try
    {
        if (sqlDatabase.driver()->isOpen())
        {
            sqlDatabase.driver()->close();
        }
        if (sqlDatabase.isOpen())
        {
            sqlDatabase.close();
        }
        return true;
    }
    catch (...)
    {
        return false;
    }
}

bool QSQLiteManager::isNewReport(QString jsonReportFileName)
{
    QMutexLocker locker(m);
    try
    {
        if (openConnection())
        {
            CVEReportDAO cveReportDAO(sqlDatabase);
            bool result = cveReportDAO.isNewReport(jsonReportFileName);
            closeConnection();
            return result;
        }
    }
    catch (...)
    {
        closeConnection();
    }

    return false;
}

QSQLiteManager::~QSQLiteManager()
{
    {
        QMutexLocker locker(m);
        closeConnection();
        delete packagesModel;
        delete cvesModel;
        delete ignoredCVEsModel;
    }
    delete m;
}

bool QSQLiteManager::importJson(const QString &FileName, const QJsonDocument &jsonDocument)
{
    QMutexLocker locker(m);
    try
    {
        if (openConnection())
        {
            if (sqlDatabase.transaction())
            {
                if (jsonDocument.isObject())
                {
                    QJsonObject CVEReport = jsonDocument.object();
                    QJsonValue version = CVEReport.value("version");
                    if (version.isNull() || !version.isString())
                    {
                        throw new QException();
                    }

                    QFileInfo fileInfo = QFileInfo(FileName);
                    std::shared_ptr<CVEReportDTO> cveReportDTO = std::make_shared<CVEReportDTO>(std::make_shared<CVEReportDTO::CVEReportKey>(), FileName, version.toInt(), fileInfo.lastModified(), fileInfo.owner());
                    CVEReportDAO CVEReportDAO(sqlDatabase);
                    const std::shared_ptr<AbstractDTO::Key> cveReportsKey = CVEReportDAO.createDTO(*cveReportDTO);

                    QJsonValue packages = CVEReport.value("package");
                    if (!packages.isArray())
                    {
                        throw new QException();
                    }
                    for (auto&& package : packages.toArray())
                    {
                        if (!package.isObject())
                        {
                            throw new QException();
                        }
                        QJsonObject packageObject = package.toObject();
                        std::shared_ptr<PackageDTO> packageDTO = std::make_shared<PackageDTO>(std::make_shared<PackageDTO::PackageKey>(), packageObject.value("name").toString(), packageObject.value("layer").toString(), packageObject.value("version").toString(), cveReportDTO);
                        PackageDAO packageDAO(sqlDatabase);
                        const std::shared_ptr<AbstractDTO::Key> packageKey = packageDAO.createDTO(*packageDTO);

                        for (auto&& packageProductKey : packageObject.keys())
                        {
                            if (packageProductKey == "products")
                            {
                                QJsonValue packageProducts = packageObject.value("products");
                                if (!packageProducts.isArray())
                                {
                                    throw new QException();
                                }
                                for (auto&& packageProduct : packageProducts.toArray())
                                {
                                    if (!packageProduct.isObject())
                                    {
                                        throw new QException();
                                    }
                                    QJsonObject packageProductObject = packageProduct.toObject();
                                    std::shared_ptr<PackageProductDTO> packageProductDTO = std::make_shared<PackageProductDTO>(std::make_shared<PackageProductDTO::PackageProductKey>(), packageProductObject.value("product").toString(), packageProductObject.value("cvesInRecord").toString() == "Yes" ? true : false, packageDTO);
                                    PackageProductDAO packageProductDAO(sqlDatabase);
                                    const std::shared_ptr<AbstractDTO::Key> packageProductKey = packageProductDAO.createDTO(*packageProductDTO);
                                }
                            }
                            else if (packageProductKey == "issue")
                            {
                                QJsonValue issues = packageObject.value("issue");
                                if (!issues.isArray())
                                {
                                    throw new QException();
                                }
                                for (auto&& issue : issues.toArray())
                                {
                                    if (!issue.isObject())
                                    {
                                        throw new QException();
                                    }
                                    QJsonObject issueObject = issue.toObject();

                                    NVDDAO nvdDAO(sqlDatabase);
                                    std::shared_ptr<AbstractDTO> nvdDTO = nvdDAO.readDTO(std::make_shared<NVDDTO::NVDKey>(issueObject.value("id").toString()));
                                    std::shared_ptr<AbstractDTO> issueDTO = std::make_shared<IssueDTO>(std::make_shared<IssueDTO::IssueKey>(), issueObject.value("status").toString(), issueObject.value("link").toString(), packageDTO, nvdDTO);
                                    IssueDAO issueDAO(sqlDatabase);
                                    const std::shared_ptr<AbstractDTO::Key> issueKey = issueDAO.createDTO(*issueDTO);
                                }
                            }
                            else if (packageProductKey != "name" && packageProductKey != "layer" && packageProductKey != "version")
                            {
                                throw new QException();
                            }
                        }
                    }
                }
                else
                {
                    throw new QException();
                }
                sqlDatabase.commit();
            }
            closeConnection();
        }
    }
    catch (...)
    {
        if (sqlDatabase.isOpen())
        {
            sqlDatabase.rollback();
            closeConnection();;
        }
        return false;
    }
    return true;
}

bool QSQLiteManager::importCVEDb(const QString& CVEDBFileName)
{
    QMutexLocker locker(m);
    QSqlDatabase cveDbDatabase;
    try
    {
        if (openConnection())
        {
            if (QSqlDatabase::contains(CVEDBFileName))
            {
                QSqlDatabase::removeDatabase(CVEDBFileName);
            }

            cveDbDatabase = QSqlDatabase::addDatabase("QSQLITE", CVEDBFileName);

            if (!cveDbDatabase.open())
            {
                QMessageBox::critical(nullptr, tr("SQL Database Error"), cveDbDatabase.lastError().text());
                closeConnection();
                return false;
            }
            if (!cveDbDatabase.driver()->open(CVEDBFileName))
            {
                QMessageBox::critical(nullptr, "SQL Database Error", sqlDatabase.lastError().text());
                cveDbDatabase.close();
                closeConnection();
                return false;
            }

            if (sqlDatabase.transaction())
            {
                NVDDAO nvdSource(cveDbDatabase);
                NVDDAO nvdSink(sqlDatabase);
                auto newNVDData = nvdSource.getAllNVDs();
                for (auto&& newNVD : newNVDData)
                {
                    auto&& nvd = nvdSink.readDTO(newNVD.getKey());
                    if (nvd != nullptr)
                    {
                        if (!nvdSink.updateDTO(newNVD))
                        {
                            throw new QException();
                        }
                    }
                    else
                    {
                        if (!nvdSink.createDTO(newNVD))
                        {
                            throw new QException();
                        }
                    }
                }

                ProductDAO productSource(cveDbDatabase);
                ProductDAO productSink(sqlDatabase);
                auto newProductData = productSource.getAllProducts();
                for (auto&& newProduct : newProductData)
                {
                    if (!productSink.existsDTO(newProduct))
                    {
                        productSink.createDTO(newProduct);
                    }
                }
                sqlDatabase.commit();
            }

            cveDbDatabase.driver()->close();
            cveDbDatabase.close();
            closeConnection();
        }
    }
    catch (...)
    {
        if (sqlDatabase.isOpen())
        {
            sqlDatabase.rollback();
            closeConnection();
        }
        if (cveDbDatabase.isValid())
        {
            if (cveDbDatabase.driver()->isOpen())
            {
                cveDbDatabase.driver()->close();
            }
            if (cveDbDatabase.isOpen())
            {
                cveDbDatabase.close();
            }
        }
        return false;
    }

    return true;
}

QStringList QSQLiteManager::getCVEReportsList()
{
    QStringList result;
    QMutexLocker locker(m);
    try
    {
        if (openConnection())
        {
            CVEReportDAO cveReportDAO(sqlDatabase);
            result = cveReportDAO.getCVEReportsList();
            closeConnection();
        }
    }
    catch (...)
    {
        closeConnection();
    }

    return result;
}

AbstractDTO::SharedDTO QSQLiteManager::getFullCVEReport(const QString& reportName)
{
    AbstractDTO::SharedDTO fullCVEReport;
    QMutexLocker locker(m);
    try
    {
        if (openConnection())
        {
            CVEReportDAO cveReportDAO(sqlDatabase);
            fullCVEReport = cveReportDAO.getFullCVEReport(reportName);
            closeConnection();
        }
    }
    catch(...)
    {
        closeConnection();
    }
    return fullCVEReport;
}


QString QSQLiteManager::getPackagesQueryString(const QString& reportName, bool showUnpatchedOnly, int entries, int page, const QString& filter)
{
    QString queryString = QString("SELECT P.*, "
                                  "(SELECT COUNT(NC.ID) "
                                  "FROM NVD NC, Issues I "
                                  "WHERE NC.ID=I.NVDID AND I.PackageID=P.ID ")
                          + (showUnpatchedOnly ? QString("AND I.Status='Unpatched' ") : QString("")) +
                          QString("AND ((CAST(NC.SCOREV3 AS NUMERIC)>=9.0))) Critical, "
                                  "(SELECT COUNT(NH.ID) "
                                  "FROM NVD NH, Issues I "
                                  "WHERE NH.ID=I.NVDID AND I.PackageID=P.ID ")
                          + (showUnpatchedOnly ? QString("AND I.Status='Unpatched' ") : QString("")) +
                          QString("AND CAST(NH.SCOREV3 AS NUMERIC)>=7.0 AND CAST(NH.SCOREV3 AS NUMERIC)<9.0) High, "
                                  "(SELECT COUNT(NM.ID) "
                                  "FROM NVD NM, Issues I "
                                  "WHERE NM.ID=I.NVDID AND I.PackageID=P.ID ")
                          + (showUnpatchedOnly ? QString("AND I.Status='Unpatched' ") : QString("")) +
                          QString("AND CAST(NM.SCOREV3 AS NUMERIC)>=4.0 AND CAST(NM.SCOREV3 AS NUMERIC)<7.0) Medium, "
                                  "(SELECT COUNT(NL.ID) "
                                  "FROM NVD NL, Issues I "
                                  "WHERE NL.ID=I.NVDID AND I.PackageID=P.ID ")
                          + (showUnpatchedOnly ? QString("AND I.Status='Unpatched' ") : QString("")) +
                          QString("AND CAST(NL.SCOREV3 AS NUMERIC)>=0.1 AND CAST(NL.SCOREV3 AS NUMERIC)<4.0) Low, "
                                  "(SELECT COUNT(NN.ID) "
                                  "FROM NVD NN, Issues I "
                                  "WHERE NN.ID=I.NVDID AND I.PackageID=P.ID ")
                          + (showUnpatchedOnly ? QString("AND I.Status='Unpatched' ") : QString("")) +
                          QString("AND CAST(NN.SCOREV3 AS NUMERIC)<0.1) None, "
                                  "(SELECT COUNT(NP.ID) "
                                  "FROM NVD NP, Issues I "
                                  "WHERE NP.ID=I.NVDID AND I.PackageID=P.ID "
                                  "AND I.Status='Unpatched') Unpatched, "
                                  "(SELECT COUNT(NP.ID) "
                                  "FROM NVD NP, Issues I "
                                  "WHERE NP.ID=I.NVDID AND I.PackageID=P.ID "
                                  "AND I.Status='Patched') Patched, "
                                  "(SELECT COUNT(NI.ID) "
                                  "FROM NVD NI, Issues I "
                                  "WHERE NI.ID=I.NVDID AND I.PackageID=P.ID "
                                  "AND I.Status='Ignored') Ignored "
                                  "FROM Packages P "
                                  "INNER JOIN CVEReports C "
                                  "ON C.ID=P.CVEReportID AND C.FileName = '%1' "
                                  "WHERE (Critical != 0 OR High != 0 OR Medium != 0 OR Low != 0 OR None != 0) ").arg(reportName);

    if (!filter.isNull() && !filter.isEmpty())
    {
        queryString += QString(" AND P.Name LIKE '%%1%' ").arg(filter);
    }

    queryString += QString("GROUP BY P.ID ORDER BY Critical DESC, High DESC, Medium DESC, Low DESC, None DESC ");

    if (entries && page > 0)
    {
        queryString += QString("LIMIT %1 OFFSET %2").arg(entries).arg(entries*(page-1));
    }

    return queryString;
}

void QSQLiteManager::setPackagesModelQuery(const QString& reportName, bool showUnpatchedOnly, int entries, int page, const QString& filter)
{
    QMutexLocker locker(m);
    if (!reportName.isNull() && !reportName.isEmpty())
    {
        try
        {
            if (openConnection())
            {
                QString queryString = getPackagesQueryString(reportName, showUnpatchedOnly, entries, page, filter);

                if (packagesModel)
                {
                    packagesModel->setQuery(queryString, sqlDatabase);
                    if (packagesModel->lastError().isValid())
                        qDebug() << packagesModel->lastError();
                }
                closeConnection();
            }
        }
        catch (...)
        {
            closeConnection();
        }
    }
}

QList<QVariantList> QSQLiteManager::getPackagesRecords(const QString& reportName, bool showUnpatchedOnly, int entries, int page, const QString& filter)
{
    QList<QVariantList> result;
    QMutexLocker locker(m);

    if (!reportName.isNull() && !reportName.isEmpty())
    {
        try
        {
            if (openConnection())
            {
                QString queryString = getPackagesQueryString(reportName, showUnpatchedOnly, entries, page, filter);

                QSqlQuery sqlQuery(sqlDatabase);

                if (sqlQuery.exec(queryString))
                {
                    if (sqlQuery.isSelect())
                    {
                        while(sqlQuery.next())
                        {
                            QVariantList values;
                            for (int i = 0; i < 13; i++)
                            {
                                values.push_back(sqlQuery.value(i));
                            }
                            result.push_back(values);
                        }
                    }
                }

                closeConnection();
            }
        }
        catch (...)
        {
            closeConnection();
        }
    }

    return result;
}


qint64 QSQLiteManager::getPackagesRowCount(const QString& reportName, bool showUnpatchedOnly, const QString& filter)
{
    qint64 result = 0;
    QMutexLocker locker(m);
    if (!reportName.isNull() && !reportName.isEmpty())
    {
        try
        {
            if (openConnection())
            {
                QString queryString = QString("SELECT COUNT(*) rows "
                                              "FROM "
                                              "(SELECT P.ID "
                                              "FROM Packages P, CVEReports C, Issues I "
                                              "WHERE P.CVEReportID=C.ID AND C.FileName = '%1' "
                                              "AND I.PackageID = P.ID "
                                              "AND "
                                              "((SELECT COUNT(NC.ID) "
                                              "FROM NVD NC "
                                              "WHERE NC.ID=I.NVDID "
                                              "AND CAST(NC.SCOREV3 AS NUMERIC)>=9.0) != 0 "
                                              "OR (SELECT COUNT(NH.ID) "
                                              "FROM NVD NH "
                                              "WHERE NH.ID=I.NVDID "
                                              "AND CAST(NH.SCOREV3 AS NUMERIC)>=7.0 AND CAST(NH.SCOREV3 AS NUMERIC)<9.0) != 0 "
                                              "OR (SELECT COUNT(NM.ID) "
                                              "FROM NVD NM "
                                              "WHERE NM.ID=I.NVDID "
                                              "AND CAST(NM.SCOREV3 AS NUMERIC)>=4.0 AND CAST(NM.SCOREV3 AS NUMERIC)<7.0) != 0 "
                                              "OR (SELECT COUNT(NL.ID) "
                                              "FROM NVD NL "
                                              "WHERE NL.ID=I.NVDID "
                                              "AND CAST(NL.SCOREV3 AS NUMERIC)>=0.1 AND CAST(NL.SCOREV3 AS NUMERIC)<4.0) != 0 "
                                              "OR (SELECT COUNT(NN.ID) "
                                              "FROM NVD NN "
                                              "WHERE NN.ID=I.NVDID "
                                              "AND CAST(NN.SCOREV3 AS NUMERIC)<0.1) != 0) ").arg(reportName) +
                                      ((showUnpatchedOnly ? QString("AND I.Status='Unpatched' ") : QString(""))) +
                                      ((!filter.isNull() && !filter.isEmpty()) ? QString("AND P.Name LIKE '%%1%' ").arg(filter) : QString("")) +
                                      "GROUP BY P.ID)";

                QSqlQuery sqlQuery(sqlDatabase);
                if (sqlQuery.exec(queryString))
                {
                    if (sqlQuery.next())
                    {
                        result = sqlQuery.value("rows").toLongLong();
                    }
                }
                closeConnection();
            }
        }
        catch (...)
        {
            closeConnection();
        }
    }
    return result;
}

QString QSQLiteManager::getCVEsQueryString(const QString& reportName, qint64 packageID, const QString& status, const QString& vector, double startingCVSS3, double endingCVSS3, int entries, int page, const QString& filter)
{
    QString queryString = QString("SELECT DISTINCT P.ID PID, P.Name, P.Layer, P.Version, I.ID IID, I.Status, I.NVDID, CAST(N.SCOREV3 AS NUMERIC) CVSS3Score, N.VECTOR Vector, I.Link "
                                  "FROM Packages P, CVEReports C, Issues I, NVD N "
                                  "WHERE C.FileName = '%1' "
                                  "AND P.CVEReportID = C.ID "
                                  "AND I.PackageID = P.ID "
                                  "AND I.NVDID = N.ID ").arg(reportName);

    if (packageID)
    {
        queryString += QString("AND PID=%1 ").arg(packageID);
    }

    if (!status.isNull() && !status.isEmpty())
    {
        queryString += QString("AND I.Status='%1' ").arg(status);
    }

    if (!vector.isNull() && !vector.isEmpty())
    {
        queryString += QString("AND Vector='%1' ").arg(vector);
    }

    queryString += QString("AND CVSS3Score >= %1 ").arg(startingCVSS3);

    queryString += QString("AND CVSS3Score <= %1 ").arg(endingCVSS3);

    if (!filter.isNull() && !filter.isEmpty())
    {
        queryString += QString("AND P.Name LIKE '%%1%' ").arg(filter);
    }

    queryString += "ORDER BY P.Name, P.Layer, I.Status, CVSS3Score ";

    if (entries && page > 0)
    {
        queryString += QString("LIMIT %1 OFFSET %2 ").arg(entries).arg(entries*(page-1));
    }

    return queryString;
}


void QSQLiteManager::setCVEsModelQuery(const QString& reportName, qint64 packageID, const QString& status, const QString& vector, double startingCVSS3, double endingCVSS3, int entries, int page, const QString& filter)
{
    QMutexLocker locker(m);
    if (!reportName.isNull() && !reportName.isEmpty())
    {
        try
        {
            if (openConnection())
            {
                QString queryString = getCVEsQueryString(reportName, packageID, status, vector, startingCVSS3, endingCVSS3, entries, page, filter);

                if (cvesModel)
                {
                    cvesModel->setQuery(queryString, sqlDatabase);
                    if (cvesModel->lastError().isValid())
                        qDebug() << cvesModel->lastError();
                }
                closeConnection();
            }
        }
        catch (...)
        {
            closeConnection();
        }
    }
}

QList<QVariantList> QSQLiteManager::getCVEsRecords(const QString& reportName, qint64 packageID, const QString& status, const QString& vector, double startingCVSS3, double endingCVSS3, int entries, int page, const QString& filter)
{
    QList<QVariantList> result;
    QMutexLocker locker(m);

    if (!reportName.isNull() && !reportName.isEmpty())
    {
        try
        {
            if (openConnection())
            {
                QString queryString = getCVEsQueryString(reportName, packageID, status, vector, startingCVSS3, endingCVSS3, entries, page, filter);

                QSqlQuery sqlQuery(sqlDatabase);

                if (sqlQuery.exec(queryString))
                {
                    if (sqlQuery.isSelect())
                    {
                        while(sqlQuery.next())
                        {
                            QVariantList values;
                            for (int i = 0; i < 10; i++)
                            {
                                values.push_back(sqlQuery.value(i));
                            }
                            result.push_back(values);
                        }
                    }
                }

                closeConnection();
            }
        }
        catch (...)
        {
            closeConnection();
        }
    }

    return result;
}

qint64 QSQLiteManager::getCVEsRowCount(const QString& reportName, qint64 packageID, const QString& status, const QString& vector, double startingCVSS3, double endingCVSS3, const QString& filter)
{
    qint64 result = 0;
    QMutexLocker locker(m);
    if (!reportName.isNull() && !reportName.isEmpty())
    {
        try
        {
            if (openConnection())
            {
                QString queryString = QString("SELECT COUNT(*) rows FROM "
                                              "(SELECT DISTINCT P.ID PID, P.Name, P.Layer, P.Version, I.ID IID, I.Status, I.NVDID, CAST(N.SCOREV3 AS NUMERIC) CVSS3Score, N.VECTOR Vector, I.Link "
                                              "FROM Packages P, CVEReports C, Issues I, NVD N "
                                              "WHERE C.FileName = '%1' "
                                              "AND P.CVEReportID = C.ID "
                                              "AND I.PackageID = P.ID "
                                              "AND I.NVDID = N.ID ").arg(reportName);

                if (packageID)
                {
                    queryString += QString("AND PID=%1 ").arg(packageID);
                }

                if (!status.isNull() && !status.isEmpty())
                {
                    queryString += QString("AND I.Status='%1' ").arg(status);
                }

                if (!vector.isNull() && !vector.isEmpty())
                {
                    queryString += QString("AND Vector='%1' ").arg(vector);
                }

                queryString += QString("AND CVSS3Score >= %1 ").arg(startingCVSS3);
                queryString += QString("AND CVSS3Score <= %1 ").arg(endingCVSS3);

                if (!filter.isNull() && !filter.isEmpty())
                {
                    queryString += QString("AND P.Name LIKE '%%1%' ").arg(filter);
                }

                queryString += ")";

                QSqlQuery sqlQuery(sqlDatabase);
                if (sqlQuery.exec(queryString))
                {
                    if (sqlQuery.next())
                    {
                        result = sqlQuery.value("rows").toLongLong();
                    }
                }
                closeConnection();
            }
        } catch (...) {
            closeConnection();
        }
    }
    return result;
}

QString QSQLiteManager::getIgnoredCVEsQueryString(const QString& reportName, int entries, int page, const QString &filter)
{
    QString queryString = QString("SELECT DISTINCT P.ID PID, P.Name, P.Layer, P.Version, I.ID IID, I.Status, I.NVDID, CAST(N.SCOREV3 AS NUMERIC) CVSS3Score, N.VECTOR Vector, I.Link "
                                  "FROM Packages P, CVEReports C, Issues I, NVD N "
                                  "WHERE C.FileName = '%1' "
                                  "AND P.CVEReportID = C.ID "
                                  "AND I.PackageID = P.ID "
                                  "AND I.NVDID = N.ID "
                                  "AND I.Status='Ignored' ").arg(reportName) +
                          ((!filter.isNull() && !filter.isEmpty()) ? QString("AND P.Name LIKE '%%1%' ").arg(filter) : QString(" "));

    queryString += QString("ORDER BY P.Name, P.Layer, I.Status, CVSS3Score DESC ");

    if (entries && page > 0)
    {
        queryString += QString("LIMIT %1 OFFSET %2 ").arg(entries).arg(entries*(page-1));
    }

    return queryString;
}

void QSQLiteManager::setIgnoredCVEsModelQuery(const QString& reportName, int entries, int page, const QString &filter)
{
    QMutexLocker locker(m);
    if (!reportName.isNull() && !reportName.isEmpty())
    {
        try
        {
            if (openConnection())
            {
                QString queryString = getIgnoredCVEsQueryString(reportName, entries, page, filter);

                if (ignoredCVEsModel)
                {
                    ignoredCVEsModel->setQuery(queryString, sqlDatabase);
                    if (ignoredCVEsModel->lastError().isValid())
                        qDebug() << ignoredCVEsModel->lastError();
                }
                closeConnection();
            }
        } catch (...) {
            closeConnection();
        }
    }
}

QList<QVariantList> QSQLiteManager::getIgnoredCVEsRecords(const QString& reportName, int entries, int page, const QString &filter)
{
    QList<QVariantList> result;
    QMutexLocker locker(m);

    if (!reportName.isNull() && !reportName.isEmpty())
    {
        try
        {
            if (openConnection())
            {
                QString queryString = getIgnoredCVEsQueryString(reportName, entries, page, filter);

                QSqlQuery sqlQuery(sqlDatabase);

                if (sqlQuery.exec(queryString))
                {
                    if (sqlQuery.isSelect())
                    {
                        while(sqlQuery.next())
                        {
                            QVariantList values;
                            for (int i = 0; i < 10; i++)
                            {
                                values.push_back(sqlQuery.value(i));
                            }
                            result.push_back(values);
                        }
                    }
                }

                closeConnection();
            }
        }
        catch (...)
        {
            closeConnection();
        }
    }

    return result;
}

qint64 QSQLiteManager::getIgnoredCVEsRowCount(const QString &reportName, const QString &filter)
{
    qint64 result = 0;
    QMutexLocker locker(m);
    if (!reportName.isNull() && !reportName.isEmpty())
    {        
        try
        {
            if (openConnection())
            {
                QString queryString = QString("SELECT COUNT(*) rows FROM "
                                              "(SELECT DISTINCT P.ID PID, P.Name, P.Layer, P.Version, I.ID IID, I.Status, I.NVDID, CAST(N.SCOREV3 AS NUMERIC) CVSS3Score, N.VECTOR Vector, I.Link "
                                              "FROM Packages P, CVEReports C, Issues I, NVD N "
                                              "WHERE C.FileName = '%1' "
                                              "AND P.CVEReportID = C.ID "
                                              "AND I.PackageID = P.ID "
                                              "AND I.NVDID = N.ID "
                                              "AND I.Status='Ignored' ").arg(reportName) +
                                      ((!filter.isNull() && !filter.isEmpty()) ? QString("AND P.Name LIKE '%%1%' )").arg(filter) : QString(")"));

                QSqlQuery sqlQuery(sqlDatabase);
                if (sqlQuery.exec(queryString))
                {
                    if (sqlQuery.next())
                    {
                        result = sqlQuery.value("rows").toLongLong();
                    }
                }
                closeConnection();
            }
        } catch (...) {
            closeConnection();
        }
    }
    return result;
}



void QSQLiteManager::setNVDDataNVDsModelQuery(const QString& product, const QString& vector, double cvss3score, int entries, int page, const QString& filter)
{
    QMutexLocker locker(m);
    try
    {
        if (openConnection())
        {
            QString queryString = QString("SELECT DISTINCT N.ID, N.SUMMARY, N.SCOREV2, N.SCOREV3, N.MODIFIED, N.VECTOR "
                                          "FROM NVD N, PRODUCTS P "
                                          "WHERE N.ID = P.ID "
                                          "AND CAST(N.SCOREV3 AS NUMERIC) > %1 ").arg(cvss3score);

            bool existVectorString = AbstractDAO::fieldExist(sqlDatabase, "NVD", "VECTORSTRING");

            if (existVectorString)
            {
                queryString = QString("SELECT DISTINCT N.ID, N.SUMMARY, N.SCOREV2, N.SCOREV3, N.MODIFIED, N.VECTOR, N.VECTORSTRING "
                                      "FROM NVD N, PRODUCTS P "
                                      "WHERE N.ID = P.ID "
                                      "AND CAST(N.SCOREV3 AS NUMERIC) > %1 ").arg(cvss3score);
            }

            if (!product.isNull() && !product.isEmpty())
            {
                queryString += QString("AND P.PRODUCT='%1' ").arg(product);
            }

            if (!vector.isNull() && !vector.isEmpty())
            {
                queryString += QString("AND N.VECTOR='%1' ").arg(vector);
            }

            if (!filter.isNull() && !filter.isEmpty())
            {
                queryString += QString("AND (N.ID LIKE '%%1%' OR N.SUMMARY LIKE '%%1%') ").arg(filter);
            }

            queryString += "ORDER BY N.ID ";

            if (entries && page > 0)
            {
                queryString += QString("LIMIT %1 OFFSET %2 ").arg(entries).arg(entries*(page-1));
            }

            if (nvdDataNVDsModel)
            {
                nvdDataNVDsModel->setQuery(queryString, sqlDatabase);
                if (nvdDataNVDsModel->lastError().isValid())
                    qDebug() << nvdDataNVDsModel->lastError();
            }

            closeConnection();
        }
    } catch (...) {
        closeConnection();
    }
}

qint64 QSQLiteManager::getNVDDataNVDsRowCount(const QString& product, const QString& vector, double cvss3score, const QString& filter)
{
    qint64 result = 0;
    QMutexLocker locker(m);
    try
    {
        if (openConnection())
        {
            QString queryString = QString("SELECT COUNT(*) rows FROM "
                                          "(SELECT DISTINCT N.ID, N.SUMMARY, N.SCOREV2, N.SCOREV3, N.MODIFIED, N.VECTOR  "
                                          "FROM NVD N, PRODUCTS P "
                                          "WHERE P.ID = N.ID AND CAST(N.SCOREV3 AS NUMERIC) > %1 ").arg(cvss3score);

            bool existVectorString = AbstractDAO::fieldExist(sqlDatabase, "NVD", "VECTORSTRING");

            if (existVectorString)
            {
                QString queryString = QString("SELECT COUNT(*) rows FROM "
                                              "(SELECT DISTINCT N.ID, N.SUMMARY, N.SCOREV2, N.SCOREV3, N.MODIFIED, N.VECTOR, N.VECTORSTRING "
                                              "FROM NVD N, PRODUCTS P "
                                              "WHERE P.ID = N.ID AND CAST(N.SCOREV3 AS NUMERIC) > %1 ").arg(cvss3score);
            }

            if (!product.isNull() && !product.isEmpty())
            {
                queryString += QString("AND P.PRODUCT='%1' ").arg(product);
            }

            if (!vector.isNull() && !vector.isEmpty())
            {
                queryString += QString("AND N.VECTOR='%1' ").arg(vector);
            }

            if (!filter.isNull() && !filter.isEmpty())
            {
                queryString += QString("AND (N.ID LIKE '%%1%' OR N.SUMMARY LIKE '%%1%') ").arg(filter);
            }

            queryString += ")";

            QSqlQuery sqlQuery(sqlDatabase);
            if (sqlQuery.exec(queryString))
            {
                if (sqlQuery.next())
                {
                    result = sqlQuery.value("rows").toLongLong();
                }
            }
            closeConnection();
        }
    } catch (...) {
        closeConnection();
    }
    return result;
}

void QSQLiteManager::setNVDDataProductsModelQuery(const QString& productID, int entries, int page, const QString& filter)
{
    QMutexLocker locker(m);
    try
    {
        if (openConnection())
        {
            QString queryString = QString("SELECT DISTINCT P.* "
                                          "FROM PRODUCTS P "
                                          "WHERE P.ID = '%1' ").arg(productID);

            if (!filter.isNull() && !filter.isEmpty())
            {
                queryString += QString(" AND (P.ID LIKE '%%1%' OR P.VENDOR LIKE '%%1%' OR P.PRODUCT LIKE '%%1%') ").arg(filter);
            }

            queryString += QString("ORDER BY VENDOR, PRODUCT, VERSION_START, VERSION_END ");

            if (entries && page > 0)
            {
                queryString += QString("LIMIT %1 OFFSET %2").arg(entries).arg(entries*(page-1));
            }

            if (nvdDataProductsModel)
            {
                nvdDataProductsModel->setQuery(queryString, sqlDatabase);
                if (nvdDataProductsModel->lastError().isValid())
                    qDebug() << nvdDataProductsModel->lastError();
            }

            closeConnection();
        }
    } catch (...) {
        closeConnection();
    }
}

qint64 QSQLiteManager::getNVDDataProductsRowCount(const QString& productID, const QString& filter)
{
    qint64 result = 0;
    QMutexLocker locker(m);
    try
    {
        if (openConnection())
        {
            QString queryString = QString("SELECT COUNT(*) rows "
                                          "FROM "
                                          "(SELECT DISTINCT P.* "
                                          "FROM PRODUCTS P "
                                          "WHERE P.ID = '%1' ").arg(productID);

            if (!filter.isNull() && !filter.isEmpty())
            {
                queryString += QString("AND (P.ID LIKE '%%1%' OR P.VENDOR LIKE '%%1%' OR P.PRODUCT LIKE '%%1%') ").arg(filter);
            }

            queryString += QString("ORDER BY VENDOR, PRODUCT, VERSION_START, VERSION_END) ");

            QSqlQuery sqlQuery(sqlDatabase);
            if (sqlQuery.exec(queryString))
            {
                if (sqlQuery.next())
                {
                    result = sqlQuery.value("rows").toLongLong();
                }
            }
            closeConnection();
        }
    } catch (...) {
        closeConnection();
    }
    return result;
}

QStringList QSQLiteManager::getAllProductsNames()
{
    QStringList result;
    QMutexLocker locker(m);
    try
    {
        if (openConnection())
        {
            ProductDAO dao(sqlDatabase);
            result = dao.getAllProductsNames();
            closeConnection();
        }
    }
    catch (...)
    {
        closeConnection();
    }
    return result;
}
