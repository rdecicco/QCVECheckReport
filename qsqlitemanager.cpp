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
#include <iostream>

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
            QMessageBox::critical(nullptr, tr("SQL Database Error"), sqlDatabase.lastError().text());
            return false;
        }
        if (!sqlDatabase.driver()->open(CVEReportsDBFile))
        {
            QMessageBox::critical(nullptr, tr("SQL Database Error"), sqlDatabase.lastError().text());
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

bool QSQLiteManager::importCVEJsonReport(const QString &FileName, const QJsonDocument &jsonDocument)
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
                            else if (packageProductKey == "cpes")
                            {
                                QJsonValue cpes = packageObject.value("cpes");
                                if (!cpes.isArray())
                                {
                                    throw new QException();
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

bool QSQLiteManager::importNVDDb(const QString& NVDDBFileName)
{
    QMutexLocker locker(m);
    QSqlDatabase nvdDbDatabase;
    try
    {
        //ATTACH DATABASE filename AS databasename

        if (openConnection())
        {
            if (QSqlDatabase::contains(NVDDBFileName))
            {
                QSqlDatabase::removeDatabase(NVDDBFileName);
            }

            nvdDbDatabase = QSqlDatabase::addDatabase("QSQLITE", NVDDBFileName);

            if (!nvdDbDatabase.open())
            {
                QMessageBox::critical(nullptr, tr("SQL Database Error"), nvdDbDatabase.lastError().text());
                closeConnection();
                return false;
            }
            if (!nvdDbDatabase.driver()->open(NVDDBFileName))
            {
                QMessageBox::critical(nullptr, tr("SQL Database Error"), sqlDatabase.lastError().text());
                nvdDbDatabase.close();
                closeConnection();
                return false;
            }

            if (sqlDatabase.transaction())
            {
                NVDDAO nvdSource(nvdDbDatabase);
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

                ProductDAO productSource(nvdDbDatabase);
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

            nvdDbDatabase.driver()->close();
            nvdDbDatabase.close();
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
        if (nvdDbDatabase.isValid())
        {
            if (nvdDbDatabase.driver()->isOpen())
            {
                nvdDbDatabase.driver()->close();
            }
            if (nvdDbDatabase.isOpen())
            {
                nvdDbDatabase.close();
            }
        }
        return false;
    }

    return true;
}

bool QSQLiteManager::importSBOMCVEJsonReport(const QString &FileName, const QJsonDocument &jsonDocument) {
    return importCVEJsonReport(FileName, jsonDocument);
}

bool QSQLiteManager::importNVDJsonRepo(const QString &NVDJsonRepoPath) {    
    return true;
}

bool QSQLiteManager::importCVEJsonRepo(const QString &CVEJsonRepoPath) {
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
                          QString("AND ((CAST(NC.SCOREV4 AS NUMERIC)>=9.0) OR "
                                       "(CAST(NC.SCOREV4 AS NUMERIC)<0.1 AND CAST(NC.SCOREV3 AS NUMERIC)>=9.0) OR "
                                       "(CAST(NC.SCOREV4 AS NUMERIC)<0.1 AND CAST(NC.SCOREV3 AS NUMERIC)<0.1 AND CAST(NC.SCOREV2 AS NUMERIC)>=9.0))) Critical, "
                                  "(SELECT COUNT(NH.ID) "
                                  "FROM NVD NH, Issues I "
                                  "WHERE NH.ID=I.NVDID AND I.PackageID=P.ID ")
                          + (showUnpatchedOnly ? QString("AND I.Status='Unpatched' ") : QString("")) +
                          QString("AND ((CAST(NH.SCOREV4 AS NUMERIC)>=7.0 AND CAST(NH.SCOREV4 AS NUMERIC)<9.0) OR"
                                  "     (CAST(NH.SCOREV4 AS NUMERIC)<0.1 AND CAST(NH.SCOREV3 AS NUMERIC)>=7.0 AND CAST(NH.SCOREV3 AS NUMERIC)<9.0) OR"
                                  "     (CAST(NH.SCOREV4 AS NUMERIC)<0.1 AND CAST(NH.SCOREV3 AS NUMERIC)<0.1 AND CAST(NH.SCOREV2 AS NUMERIC)>=7.0 AND CAST(NH.SCOREV2 AS NUMERIC)<9.0))) High, "
                                  "(SELECT COUNT(NM.ID) "
                                  "FROM NVD NM, Issues I "
                                  "WHERE NM.ID=I.NVDID AND I.PackageID=P.ID ")
                          + (showUnpatchedOnly ? QString("AND I.Status='Unpatched' ") : QString("")) +
                          QString("AND ((CAST(NM.SCOREV4 AS NUMERIC)>=4.0 AND CAST(NM.SCOREV4 AS NUMERIC)<7.0) OR"
                                  "     (CAST(NM.SCOREV4 AS NUMERIC)<0.1 AND CAST(NM.SCOREV3 AS NUMERIC)>=4.0 AND CAST(NM.SCOREV3 AS NUMERIC)<7.0) OR"
                                  "     (CAST(NM.SCOREV4 AS NUMERIC)<0.1 AND CAST(NM.SCOREV3 AS NUMERIC)<0.1 AND CAST(NM.SCOREV2 AS NUMERIC)>=4.0 AND CAST(NM.SCOREV2 AS NUMERIC)<7.0))) Medium, "
                                  "(SELECT COUNT(NL.ID) "
                                  "FROM NVD NL, Issues I "
                                  "WHERE NL.ID=I.NVDID AND I.PackageID=P.ID ")
                          + (showUnpatchedOnly ? QString("AND I.Status='Unpatched' ") : QString("")) +
                          QString("AND ((CAST(NL.SCOREV4 AS NUMERIC)>=0.1 AND CAST(NL.SCOREV4 AS NUMERIC)<4.0) OR"
                                  "     (CAST(NL.SCOREV4 AS NUMERIC)<0.1 AND CAST(NL.SCOREV3 AS NUMERIC)>=0.1 AND CAST(NL.SCOREV3 AS NUMERIC)<4.0) OR"
                                  "     (CAST(NL.SCOREV4 AS NUMERIC)<0.1 AND CAST(NL.SCOREV3 AS NUMERIC)<0.1 AND CAST(NL.SCOREV2 AS NUMERIC)>=0.1 AND CAST(NL.SCOREV2 AS NUMERIC)<4.0))) Low, "
                                  "(SELECT COUNT(NN.ID) "
                                  "FROM NVD NN, Issues I "
                                  "WHERE NN.ID=I.NVDID AND I.PackageID=P.ID ")
                          + (showUnpatchedOnly ? QString("AND I.Status='Unpatched' ") : QString("")) +
                          QString("AND (CAST(NN.SCOREV4 AS NUMERIC)<0.1 AND "
                                       "CAST(NN.SCOREV3 AS NUMERIC)<0.1 AND "
                                       "CAST(NN.SCOREV2 AS NUMERIC)<0.1)) None, "
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
    if (!reportName.isNull() && !reportName.isEmpty())    {
        try
        {
            if (openConnection())
            {
                QString queryString = getPackagesQueryString(reportName, showUnpatchedOnly, entries, page, filter);
#ifdef QT_DEBUG
                std::cout << "setPackagesModelQuery: " << std::endl << queryString.toStdString() << std::endl;
#endif
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

#ifdef QT_DEBUG
                std::cout << std::endl << "getPackagesRecords: " << std::endl << queryString.toStdString() << std::endl;
#endif
                QSqlQuery sqlQuery(sqlDatabase);

                if (sqlQuery.exec(queryString))
                {
                    if (sqlQuery.isSelect())
                    {
                        while(sqlQuery.next())
                        {
                            QVariantList values;
                            for (int i = 0; i < numOfCVEColumns; i++)
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
                                              "(SELECT P.ID FROM Packages P, CVEReports C, Issues I "
                                              "WHERE P.CVEReportID=C.ID AND C.FileName = '%1' AND I.PackageID = P.ID ")
                                          .arg(reportName) +
                                      ((showUnpatchedOnly ? QString("AND I.Status='Unpatched' ") : QString(""))) +
                                      ((!filter.isNull() && !filter.isEmpty()) ? QString("AND P.Name LIKE '%%1%' ").arg(filter) : QString("")) +
                                      "GROUP BY P.ID)";
#ifdef QT_DEBUG
                std::cout << std::endl << "getPackagesRowCount: " << std::endl << queryString.toStdString() << std::endl;
#endif
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

QString QSQLiteManager::getCVEsQueryString(const QString& reportName, qint64 packageID, const QString& status, const QString& vector, double startingCVSS4, double endingCVSS4, double startingCVSS3, double endingCVSS3, double startingCVSS2, double endingCVSS2, int entries, int page, const QString& filter)
{
    QString queryString = QString("SELECT DISTINCT P.ID PID, P.Name, P.Layer, P.Version, I.ID IID, I.Status, I.NVDID, CAST(N.SCOREV4 AS NUMERIC) CVSS4Score, CAST(N.SCOREV3 AS NUMERIC) CVSS3Score, CAST(N.SCOREV2 AS NUMERIC) CVSS2Score, N.VECTOR Vector, I.Link "
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

    queryString += QString("AND ((CVSS4Score >= %1 AND CVSS4Score <= %2) OR ").arg(startingCVSS4).arg(endingCVSS4);
    queryString += QString("     (CVSS4Score < 0.1 AND CVSS3Score >= %1 AND CVSS3Score <= %2) OR ").arg(startingCVSS3).arg(endingCVSS3);
    queryString += QString("     (CVSS4Score < 0.1 AND CVSS3Score < 0.1 AND CVSS2Score >= %1 AND CVSS2Score <= %2)) ").arg(startingCVSS2).arg(endingCVSS2);

    if (!filter.isNull() && !filter.isEmpty())
    {
        queryString += QString("AND P.Name LIKE '%%1%' ").arg(filter);
    }

    queryString += "ORDER BY P.Name, P.Layer, I.Status, CVSS4Score DESC, CVSS3Score DESC, CVSS2Score DESC ";

    if (entries && page > 0)
    {
        queryString += QString("LIMIT %1 OFFSET %2 ").arg(entries).arg(entries*(page-1));
    }

    return queryString;
}


void QSQLiteManager::setCVEsModelQuery(const QString& reportName, qint64 packageID, const QString& status, const QString& vector, double startingCVSS4, double endingCVSS4, double startingCVSS3, double endingCVSS3, double startingCVSS2, double endingCVSS2, int entries, int page, const QString& filter)
{
    QMutexLocker locker(m);
    if (!reportName.isNull() && !reportName.isEmpty())
    {
        try
        {
            if (openConnection())
            {
                QString queryString;
                if (startingCVSS4 != 0 || endingCVSS4 != 0 || startingCVSS3 != 0 || endingCVSS3 != 0 || startingCVSS2 != 0 || endingCVSS2 != 0)
                    queryString = getCVEsQueryString(reportName, packageID, status, vector, startingCVSS4, endingCVSS4, startingCVSS3, endingCVSS3, startingCVSS2, endingCVSS2, entries, page, filter);
                else
                    queryString = getNoneCVEsQueryString(reportName, packageID, status, vector, entries, page, filter);
#ifdef QT_DEBUG
                std::cout << std::endl << "setCVEsModelQuery: " << std::endl <<  queryString.toStdString() << std::endl;
#endif
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

QList<QVariantList> QSQLiteManager::getCVEsRecords(const QString& reportName, qint64 packageID, const QString& status, const QString& vector, double startingCVSS4, double endingCVSS4, double startingCVSS3, double endingCVSS3, double startingCVSS2, double endingCVSS2, int entries, int page, const QString& filter)
{
    QList<QVariantList> result;
    QMutexLocker locker(m);

    if (!reportName.isNull() && !reportName.isEmpty())
    {
        try
        {
            if (openConnection())
            {
                QString queryString;
                if (startingCVSS4 != 0 || endingCVSS4 != 0 || startingCVSS3 != 0 || endingCVSS3 != 0 || startingCVSS2 != 0 || endingCVSS2 != 0)
                    queryString = getCVEsQueryString(reportName, packageID, status, vector, startingCVSS4, endingCVSS4, startingCVSS3, endingCVSS3, startingCVSS2, endingCVSS2, entries, page, filter);
                else
                    queryString = getNoneCVEsQueryString(reportName, packageID, status, vector, entries, page, filter);

                QSqlQuery sqlQuery(sqlDatabase);
#ifdef QT_DEBUG
                std::cout << std::endl << "getCVEsRecords: " << std::endl << queryString.toStdString() << std::endl;
#endif
                if (sqlQuery.exec(queryString))
                {
                    if (sqlQuery.isSelect())
                    {
                        while(sqlQuery.next())
                        {
                            QVariantList values;
                            for (int i = 0; i < numOfCVEColumns; i++)
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

QString QSQLiteManager::getCVEsRowCountQueryString(const QString& reportName, qint64 packageID, const QString& status, const QString& vector, double startingCVSS4, double endingCVSS4, double startingCVSS3, double endingCVSS3, double startingCVSS2, double endingCVSS2, const QString& filter)
{
    QString queryString;
    if (!reportName.isNull() && !reportName.isEmpty())
    {
        queryString = QString("SELECT COUNT(*) rows FROM "
                                      "(SELECT DISTINCT P.ID PID, P.Name, P.Layer, P.Version, I.ID IID, I.Status, I.NVDID, CAST(N.SCOREV4 AS NUMERIC) CVSS4Score, CAST(N.SCOREV3 AS NUMERIC) CVSS3Score, CAST(N.SCOREV2 AS NUMERIC) CVSS2Score, N.VECTOR Vector, I.Link "
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

        queryString += QString("AND ((CVSS4Score >= %1 AND CVSS4Score <= %2) OR ").arg(startingCVSS4).arg(endingCVSS4);
        queryString += QString("     (CVSS4Score < 0.1 AND CVSS3Score >= %1 AND CVSS3Score <= %2) OR ").arg(startingCVSS3).arg(endingCVSS3);
        queryString += QString("     (CVSS4Score < 0.1 AND CVSS3Score < 0.1 AND CVSS2Score >= %1 AND CVSS2Score <= %2)) ").arg(startingCVSS2).arg(endingCVSS2);

        if (!filter.isNull() && !filter.isEmpty())
        {
            queryString += QString("AND P.Name LIKE '%%1%' ").arg(filter);
        }

        queryString += ")";
    }
    return queryString;
}


qint64 QSQLiteManager::getCVEsRowCount(const QString& reportName, qint64 packageID, const QString& status, const QString& vector, double startingCVSS4, double endingCVSS4, double startingCVSS3, double endingCVSS3, double startingCVSS2, double endingCVSS2, const QString& filter)
{
    qint64 result = 0;
    QMutexLocker locker(m);
    if (!reportName.isNull() && !reportName.isEmpty())
    {
        try
        {
            if (openConnection())
            {
                QString queryString;
                if (startingCVSS4 != 0 || endingCVSS4 != 0 || startingCVSS3 != 0 || endingCVSS3 != 0 || startingCVSS2 != 0 || endingCVSS2 != 0)
                    queryString = getCVEsRowCountQueryString(reportName, packageID, status, vector, startingCVSS4, endingCVSS4, startingCVSS3, endingCVSS3, startingCVSS2, endingCVSS2, filter);
                else
                    queryString = getNoneCVEsRowCountQueryString(reportName, packageID, status, vector, filter);
#ifdef QT_DEBUG
                std::cout << std::endl << "getCVEsRowCount: " << std::endl << queryString.toStdString() << std::endl;
#endif
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

void QSQLiteManager::setNoneCVEsModelQuery(const QString& reportName, qint64 packageID, const QString& status, const QString& vector, int entries, int page, const QString& filter)
{
    QMutexLocker locker(m);
    if (!reportName.isNull() && !reportName.isEmpty())
    {
        try
        {
            if (openConnection())
            {
                QString queryString = getNoneCVEsQueryString(reportName, packageID, status, vector, entries, page, filter);
#ifdef QT_DEBUG
                std::cout << std::endl << "setNoneCVEsModelQuery: " << std::endl <<  queryString.toStdString() << std::endl;
#endif
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

QString QSQLiteManager::getNoneCVEsQueryString(const QString& reportName, qint64 packageID, const QString& status, const QString& vector, int entries, int page, const QString& filter)
{
    QString queryString = QString("SELECT DISTINCT P.ID PID, P.Name, P.Layer, P.Version, I.ID IID, I.Status, I.NVDID, CAST(N.SCOREV4 AS NUMERIC) CVSS4Score, CAST(N.SCOREV3 AS NUMERIC) CVSS3Score, CAST(N.SCOREV2 AS NUMERIC) CVSS2Score, N.VECTOR Vector, I.Link "
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

    queryString += QString("AND CVSS4Score < 0.1 AND CVSS3Score < 0.1 AND CVSS2Score < 0.1 ");

    if (!filter.isNull() && !filter.isEmpty())
    {
        queryString += QString("AND P.Name LIKE '%%1%' ").arg(filter);
    }

    queryString += "ORDER BY P.Name, P.Layer, I.Status";

    if (entries && page > 0)
    {
        queryString += QString("LIMIT %1 OFFSET %2 ").arg(entries).arg(entries*(page-1));
    }

    return queryString;
}

QList<QVariantList> QSQLiteManager::getNoneCVEsRecords(const QString& reportName, qint64 packageID, const QString& status, const QString& vector, int entries, int page, const QString& filter)
{
    QList<QVariantList> result;
    QMutexLocker locker(m);

    if (!reportName.isNull() && !reportName.isEmpty())
    {
        try
        {
            if (openConnection())
            {
                QString queryString = getNoneCVEsQueryString(reportName, packageID, status, vector, entries, page, filter);
                QSqlQuery sqlQuery(sqlDatabase);
#ifdef QT_DEBUG
                std::cout << std::endl << "getNoneCVEsRecords: " << std::endl << queryString.toStdString() << std::endl;
#endif
                if (sqlQuery.exec(queryString))
                {
                    if (sqlQuery.isSelect())
                    {
                        while(sqlQuery.next())
                        {
                            QVariantList values;
                            for (int i = 0; i < numOfCVEColumns; i++)
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

QString QSQLiteManager::getNoneCVEsRowCountQueryString(const QString& reportName, qint64 packageID, const QString& status, const QString& vector, const QString& filter)
{
    QString queryString;
    if (!reportName.isNull() && !reportName.isEmpty())
    {
        queryString = QString("SELECT COUNT(*) rows FROM "
                              "(SELECT DISTINCT P.ID PID, P.Name, P.Layer, P.Version, I.ID IID, I.Status, I.NVDID, CAST(N.SCOREV4 AS NUMERIC) CVSS4Score, CAST(N.SCOREV3 AS NUMERIC) CVSS3Score, CAST(N.SCOREV2 AS NUMERIC) CVSS2Score, N.VECTOR Vector, I.Link "
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

        queryString += QString("AND CVSS4Score < 0.1 AND CVSS3Score < 0.1 AND CVSS2Score < 0.1 ");

        if (!filter.isNull() && !filter.isEmpty())
        {
            queryString += QString("AND P.Name LIKE '%%1%' ").arg(filter);
        }

        queryString += ")";
    }
    return queryString;
}

qint64 QSQLiteManager::getNoneCVEsRowCount(const QString& reportName, qint64 packageID, const QString& status, const QString& vector, const QString& filter)
{
    qint64 result = 0;
    QMutexLocker locker(m);
    if (!reportName.isNull() && !reportName.isEmpty())
    {
        try
        {
            if (openConnection())
            {
                QString queryString = getNoneCVEsRowCountQueryString(reportName, packageID, status, vector, filter);
#ifdef QT_DEBUG
                std::cout << std::endl << "getNoneCVEsRowCount: " << std::endl << queryString.toStdString() << std::endl;
#endif
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
    QString queryString = QString("SELECT DISTINCT P.ID PID, P.Name, P.Layer, P.Version, I.ID IID, I.Status, I.NVDID, CAST(N.SCOREV4 AS NUMERIC) CVSS4Score, CAST(N.SCOREV3 AS NUMERIC) CVSS3Score, CAST(N.SCOREV2 AS NUMERIC) CVSS2Score, N.VECTOR Vector, I.Link "
                                  "FROM Packages P, CVEReports C, Issues I, NVD N "
                                  "WHERE C.FileName = '%1' "
                                  "AND P.CVEReportID = C.ID "
                                  "AND I.PackageID = P.ID "
                                  "AND I.NVDID = N.ID "
                                  "AND I.Status='Ignored' ").arg(reportName) +
                          ((!filter.isNull() && !filter.isEmpty()) ? QString("AND P.Name LIKE '%%1%' ").arg(filter) : QString(" "));

    queryString += QString("ORDER BY P.Name, P.Layer, I.Status, CVSS4Score, CVSS3Score, CVSS2Score DESC ");

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
#ifdef QT_DEBUG
                std::cout << std::endl << "setIgnoredCVEsModelQuery: " << std::endl << queryString.toStdString() << std::endl;
#endif
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
#ifdef QT_DEBUG
                std::cout << std::endl << "getIgnoredCVEsRecords: " << std::endl << queryString.toStdString() << std::endl;
#endif
                QSqlQuery sqlQuery(sqlDatabase);
                if (sqlQuery.exec(queryString))
                {
                    if (sqlQuery.isSelect())
                    {
                        while(sqlQuery.next())
                        {
                            QVariantList values;
                            for (int i = 0; i < numOfCVEColumns; i++)
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
                                              "(SELECT DISTINCT P.ID PID, P.Name, P.Layer, P.Version, I.ID IID, I.Status, I.NVDID, CAST(N.SCOREV4 AS NUMERIC) CVSS4Score, CAST(N.SCOREV3 AS NUMERIC) CVSS3Score, CAST(N.SCOREV2 AS NUMERIC) CVSS2Score, N.VECTOR Vector, I.Link "
                                              "FROM Packages P, CVEReports C, Issues I, NVD N "
                                              "WHERE C.FileName = '%1' "
                                              "AND P.CVEReportID = C.ID "
                                              "AND I.PackageID = P.ID "
                                              "AND I.NVDID = N.ID "
                                              "AND I.Status='Ignored' ").arg(reportName) +
                                      ((!filter.isNull() && !filter.isEmpty()) ? QString("AND P.Name LIKE '%%1%' )").arg(filter) : QString(")"));
#ifdef QT_DEBUG
                std::cout << std::endl << "getIgnoredCVEsRowCount: " << std::endl << queryString.toStdString() << std::endl;
#endif
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



void QSQLiteManager::setNVDDataNVDsModelQuery(const QString& product, const QString& vector, double cvss4score, double cvss3score, double cvss2score , int entries, int page, const QString& filter)
{
    QMutexLocker locker(m);
    try
    {
        if (openConnection())
        {
            QString queryString = QString("SELECT DISTINCT N.ID, N.SUMMARY, N.SCOREV3, N.SCOREV2, N.MODIFIED, N.VECTOR "
                                          "FROM NVD N, PRODUCTS P "
                                          "WHERE N.ID = P.ID "
                                          "AND "
                                          "((CAST(N.SCOREV3 AS NUMERIC) > %1) OR "
                                          " (CAST(N.SCOREV3 AS NUMERIC) < 0.1 AND CAST(N.SCOREV2 AS NUMERIC) > %2)) ")
                .arg(cvss3score)
                .arg(cvss2score);

            bool existVectorString = AbstractDAO::fieldExist(sqlDatabase, "NVD", "VECTORSTRING");

            if (existVectorString)
            {
                queryString = QString("SELECT DISTINCT N.ID, N.SUMMARY, N.SCOREV3, N.SCOREV2, N.MODIFIED, N.VECTOR, N.VECTORSTRING "
                                      "FROM NVD N, PRODUCTS P "
                                      "WHERE N.ID = P.ID "
                                      "AND "
                                      "((CAST(N.SCOREV3 AS NUMERIC) > %1) OR "
                                      " (CAST(N.SCOREV3 AS NUMERIC) < 0.1 AND CAST(N.SCOREV2 AS NUMERIC) > %2)) ")
                                  .arg(cvss3score)
                                  .arg(cvss2score);
            }

            bool existScoreV4 = AbstractDAO::fieldExist(sqlDatabase, "NVD", "SCOREV4");

            if (existScoreV4)
            {
                queryString = QString("SELECT DISTINCT N.ID, N.SUMMARY, N.SCOREV4, N.SCOREV3, N.SCOREV2, N.MODIFIED, N.VECTOR, N.VECTORSTRING "
                                      "FROM NVD N, PRODUCTS P "
                                      "WHERE N.ID = P.ID "
                                      "AND "
                                      "((CAST(N.SCOREV4 AS NUMERIC) > %1) OR "
                                      " (CAST(N.SCOREV4 AS NUMERIC) < 0.1 AND CAST(N.SCOREV3 AS NUMERIC) > %2) OR "
                                      " (CAST(N.SCOREV4 AS NUMERIC) < 0.1 AND CAST(N.SCOREV3 AS NUMERIC) < 0.1 AND CAST(N.SCOREV2 AS NUMERIC) > %3)) ")
                                  .arg(cvss4score)
                                  .arg(cvss3score)
                                  .arg(cvss2score);
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
#ifdef QT_DEBUG
            std::cout << std::endl << "setNVDDataNVDsModelQuery: " << std::endl << queryString.toStdString() << std::endl;
#endif
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

qint64 QSQLiteManager::getNVDDataNVDsRowCount(const QString& product, const QString& vector, double cvss4score, double cvss3score, double cvss2score, const QString& filter)
{
    qint64 result = 0;
    QMutexLocker locker(m);
    try
    {
        if (openConnection())
        {
            QString queryString = QString("SELECT COUNT(*) rows FROM "
                                          "(SELECT DISTINCT N.ID, N.SUMMARY, N.SCOREV3, N.SCOREV2, N.MODIFIED, N.VECTOR  "
                                          "FROM NVD N, PRODUCTS P "
                                          "WHERE P.ID = N.ID "
                                          "AND "
                                          "((CAST(N.SCOREV3 AS NUMERIC) > %1) OR "
                                          " (CAST(N.SCOREV3 AS NUMERIC) < 0.1 AND CAST(N.SCOREV2 AS NUMERIC) > %2)) ")
                                      .arg(cvss3score)
                                      .arg(cvss2score);

            bool existVectorString = AbstractDAO::fieldExist(sqlDatabase, "NVD", "VECTORSTRING");

            if (existVectorString)
            {
                queryString = QString("SELECT COUNT(*) rows FROM "
                                      "(SELECT DISTINCT N.ID, N.SUMMARY, N.SCOREV3, N.SCOREV2, N.MODIFIED, N.VECTOR, N.VECTORSTRING "
                                      "FROM NVD N, PRODUCTS P "
                                      "WHERE P.ID = N.ID "
                                      "AND "
                                      "((CAST(N.SCOREV3 AS NUMERIC) > %1) OR "
                                      " (CAST(N.SCOREV3 AS NUMERIC) < 0.1 AND CAST(N.SCOREV2 AS NUMERIC) > %2)) ")
                                    .arg(cvss3score)
                                    .arg(cvss2score);
            }

            bool existScoreV4 = AbstractDAO::fieldExist(sqlDatabase, "NVD", "SCOREV4");

            if (existScoreV4)
            {
                queryString = QString("SELECT COUNT(*) rows FROM "
                                      "(SELECT DISTINCT N.ID, N.SUMMARY, N.SCOREV4, N.SCOREV3, N.SCOREV2, N.MODIFIED, N.VECTOR, N.VECTORSTRING "
                                      "FROM NVD N, PRODUCTS P "
                                      "WHERE P.ID = N.ID "
                                      "AND ((CAST(N.SCOREV4 AS NUMERIC) > %1) OR "
                                      "     (CAST(N.SCOREV4 AS NUMERIC) < 0.1 AND CAST(N.SCOREV3 AS NUMERIC) > %2) OR "
                                      "     (CAST(N.SCOREV4 AS NUMERIC) < 0.1 AND CAST(N.SCOREV3 AS NUMERIC) < 0.1 AND CAST(N.SCOREV2 AS NUMERIC) > %3)) ")
                                  .arg(cvss4score)
                                  .arg(cvss3score)
                                  .arg(cvss2score);
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
                queryString += QString("AND (N.ID LIKE '%1' OR N.SUMMARY LIKE '%1') ").arg(filter);
            }

            queryString += ")";
#ifdef QT_DEBUG
            std::cout << std::endl << "getNVDDataNVDsRowCount: " << std::endl << queryString.toStdString() << std::endl;
#endif
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
#ifdef QT_DEBUG
            std::cout << std::endl << "setNVDDataProductsModelQuery: " << std::endl << queryString.toStdString() << std::endl;
#endif
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
#ifdef QT_DEBUG
            std::cout << std::endl << "getNVDDataProductsRowCount: " << std::endl << queryString.toStdString() << std::endl;
#endif
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
