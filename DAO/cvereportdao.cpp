#include "DAO/cvereportdao.h"
#include "DAO/packagedao.h"
#include "DTO/cvereportdto.h"
#include "qsqlquery.h"
#include <QFileInfo>

CVEReportDAO::CVEReportDAO(const QSqlDatabase &database): AbstractDAO(database) {}

const AbstractDTO::SharedKey CVEReportDAO::createDTO(AbstractDTO& dto)
{
    const CVEReportDTO& cveReportDTO = static_cast<const CVEReportDTO&>(dto);

    QSqlQuery cveReportQuery(sqlDatabase);
    QString cveReportQueryString = QString("INSERT INTO CVEReports ( FileName, Version, Date, Owner ) VALUES ( '%1', %2, '%3', '%4' )")
                                       .arg(QFileInfo(cveReportDTO.getFileName()).fileName())
                                       .arg(cveReportDTO.getVersion())
                                       .arg(cveReportDTO.getDate().toUTC().toString(Qt::ISODate))
                                       .arg(cveReportDTO.getOwner());
    if (!cveReportQuery.exec(cveReportQueryString))
    {
        throw new std::exception();
    }
    dto.setKey(std::make_shared<CVEReportDTO::CVEReportKey>(cveReportQuery.lastInsertId().toLongLong()));
    return dto.getKey();
}

AbstractDTO::SharedDTO CVEReportDAO::readDTO(const AbstractDTO::SharedKey &id)
{
    const CVEReportDTO::CVEReportKey* cveReportKey = static_cast<const CVEReportDTO::CVEReportKey*>(id.get());

    if (cveReportKey)
    {
        QSqlQuery cveReportQuery(sqlDatabase);
        QString cveReportQueryString = QString("SELECT FileName, Version, Date, Owner FROM CVEReports WHERE ID = %1")
                                           .arg(cveReportKey->getID());

        if (!cveReportQuery.exec(cveReportQueryString))
        {
            throw new std::exception();
        }
        if (cveReportQuery.next())
        {
            CVEReportDTO::SharedCVEReportDTO cveReportDTO = std::make_shared<CVEReportDTO>();
            cveReportDTO->setKey(id);
            cveReportDTO->setFileName(cveReportQuery.value("FileName").toString());
            cveReportDTO->setVersion(cveReportQuery.value("Version").toInt());
            cveReportDTO->setDate(cveReportQuery.value("Date").toDateTime());
            cveReportDTO->setOwner(cveReportQuery.value("Owner").toString());
            return cveReportDTO;
        }
    }
    return nullptr;
}

bool CVEReportDAO::updateDTO(const AbstractDTO& dto)
{
    const CVEReportDTO& cveReportDTO = static_cast<const CVEReportDTO&>(dto);
    const CVEReportDTO::CVEReportKey* cveReportKey = static_cast<const CVEReportDTO::CVEReportKey*>(cveReportDTO.getKey().get());
    if (cveReportKey)
    {
        QSqlQuery cveReportQuery(sqlDatabase);
        QString cveReportQueryString = QString("UPDATE CVEReports SET FileName = '%1', Version = %2, Date = '%3', Owner = '%4' WHERE ID = %5")
                                           .arg(QFileInfo(cveReportDTO.getFileName()).fileName())
                                           .arg(cveReportDTO.getVersion())
                                           .arg(cveReportDTO.getDate().toUTC().toString(Qt::ISODate))
                                           .arg(cveReportDTO.getOwner())
                                           .arg(cveReportKey->getID());

        if (cveReportQuery.exec(cveReportQueryString))
        {
            return true;
        }
    }
    return false;
}

bool CVEReportDAO::deleteDTO(const AbstractDTO& dto)
{
    const CVEReportDTO& cveReportDTO = static_cast<const CVEReportDTO&>(dto);
    return deleteDTO(cveReportDTO.getKey());
}

bool CVEReportDAO::deleteDTO(const AbstractDTO::SharedKey &id)
{
    const CVEReportDTO::CVEReportKey* cveReportKey = static_cast<const CVEReportDTO::CVEReportKey*>(id.get());

    if (cveReportKey && cveReportKey->getID() > 0)
    {
        QSqlQuery cveReportQuery(sqlDatabase);
        QString cveReportQueryString = QString("DELETE FROM CVEReports WHERE ID = %1")
                                           .arg(cveReportKey->getID());

        if (cveReportQuery.exec(cveReportQueryString))
        {
            return true;
        }
    }
    return false;
}

bool CVEReportDAO::isNewReport(QString jsonReportFileName)
{
    try
    {
        QSqlQuery cveReportQuery(sqlDatabase);
        QString cveReportQueryString = QString("SELECT FileName FROM CVEReports WHERE FileName='%1'")
                                           .arg(QFileInfo(jsonReportFileName).fileName());

        if (!cveReportQuery.exec(cveReportQueryString))
        {
            return false;
        }

        if (cveReportQuery.isSelect() && cveReportQuery.next())
        {
            return false;
        }
    }
    catch (...)
    {
        return false;
    }
    return true;
}

QStringList CVEReportDAO::getCVEReportsList()
{
    QStringList cveReportsList;
    QSqlQuery cveReportQuery(sqlDatabase);
    QString cveReportQueryString = QString("SELECT FileName FROM CVEReports ORDER BY Date");
    if (!cveReportQuery.exec(cveReportQueryString))
    {
        return cveReportsList;
    }
    cveReportsList.append(QString());
    while (cveReportQuery.next())
    {
        cveReportsList.append(cveReportQuery.value("FileName").toString());
    }
    return cveReportsList;
}

AbstractDTO::SharedDTO CVEReportDAO::getFullCVEReport(const QString& reportName)
{
    QSqlQuery cveReportQuery(sqlDatabase);
    QString cveReportQueryString = QString("SELECT ID, FileName, Version, Date, Owner FROM CVEReports WHERE FileName = '%1'")
                                       .arg(reportName);

    if (cveReportQuery.exec(cveReportQueryString))
    {
        while (cveReportQuery.next())
        {
            CVEReportDAO cveReportDAO(sqlDatabase);
            CVEReportDTO::SharedCVEReportDTO cveReportDTO = std::make_shared<CVEReportDTO>();
            cveReportDTO->setKey(std::make_shared<CVEReportDTO::CVEReportKey>(cveReportQuery.value("ID").toLongLong()));
            cveReportDTO->setFileName(cveReportQuery.value("FileName").toString());
            cveReportDTO->setVersion(cveReportQuery.value("Version").toInt());
            cveReportDTO->setDate(cveReportQuery.value("Date").toDateTime());
            cveReportDTO->setOwner(cveReportQuery.value("Owner").toString());
            PackageDAO packageDAO(sqlDatabase);
            cveReportDTO->setPackages(packageDAO.getPackagesOfReport(cveReportDTO));
            return cveReportDTO;
        }
    }
    return nullptr;
}
