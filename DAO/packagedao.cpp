/*!
   QCVECheckReport project

   @file: packagedao.cpp

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

#include "DAO/cvereportdao.h"
#include "DAO/issuedao.h"
#include "DAO/packageproductdao.h"
#include "DTO/cvereportdto.h"
#include "DTO/abstractdto.h"
#include "DTO/packagedto.h"
#include "DAO/packagedao.h"
#include "qsqlquery.h"
#include <QFileInfo>

PackageDAO::PackageDAO(const QSqlDatabase &database): AbstractDAO(database) {}

const AbstractDTO::SharedKey PackageDAO::createDTO(AbstractDTO& dto)
{
    const PackageDTO& packageDTO = static_cast<const PackageDTO&>(dto);
    const CVEReportDTO::CVEReportKey* cveReportKey = packageDTO.getCVEReport() ? static_cast<const CVEReportDTO::CVEReportKey*>(packageDTO.getCVEReport()->getKey().get()) : nullptr;
    qint64 CVEReportID = cveReportKey ? cveReportKey->getID() : 0;
    QSqlQuery packageQuery(sqlDatabase);
    QString packageQueryString = QString("INSERT INTO Packages (Name, Layer, Version, CVEReportID) VALUES ( '%1', '%2', '%3', %4 )")
                                     .arg(packageDTO.getName())
                                     .arg(packageDTO.getLayer())
                                     .arg(packageDTO.getVersion())
                                     .arg(CVEReportID);

    if (!packageQuery.exec(packageQueryString))
    {
        throw new std::exception();
    }
    dto.setKey(std::make_shared<PackageDTO::PackageKey>(packageQuery.lastInsertId().toLongLong()));
    return dto.getKey();
}

AbstractDTO::SharedDTO PackageDAO::readDTO(const AbstractDTO::SharedKey& id)
{
    const PackageDTO::PackageKey* packageKey = static_cast<const PackageDTO::PackageKey*>(id.get());
    if (packageKey)
    {
        QSqlQuery packageQuery(sqlDatabase);
        QString packageQueryString = QString("SELECT Name, Layer, Version, CVEReportID FROM Packages WHERE ID = %1")
                                         .arg(packageKey->getID());

        if (!packageQuery.exec(packageQueryString))
        {
            throw new std::exception();
        }
        if (packageQuery.next())
        {
            PackageDTO::SharedPackageDTO packageDTO = std::make_shared<PackageDTO>();
            packageDTO->setKey(id);
            packageDTO->setName(packageQuery.value("Name").toString());
            packageDTO->setLayer(packageQuery.value("Layer").toString());
            packageDTO->setVersion(packageQuery.value("Version").toString());
            CVEReportDAO cveReportDAO(sqlDatabase);
            packageDTO->setCVEReport(cveReportDAO.readDTO(std::make_shared<CVEReportDTO::CVEReportKey>(packageQuery.value("CVEReportID").toLongLong())));
            return packageDTO;
        }
    }
    return nullptr;
}

bool PackageDAO::updateDTO(const AbstractDTO& dto)
{
    const PackageDTO& packageDTO = static_cast<const PackageDTO&>(dto);
    const PackageDTO::PackageKey* packageKey = static_cast<const PackageDTO::PackageKey*>(packageDTO.getKey().get());
    if (packageKey)
    {
        const CVEReportDTO::CVEReportKey* cveReportKey = packageDTO.getCVEReport() ? static_cast<const CVEReportDTO::CVEReportKey*>(packageDTO.getCVEReport()->getKey().get()) : nullptr;
        qint64 CVEReportID = cveReportKey ? cveReportKey->getID() : 0;
        QSqlQuery packageQuery(sqlDatabase);
        QString packageQueryString = QString("UPDATE Packages SET Name = '%1', Layer = '%2', Version = '%3', CVEReportID = %4 WHERE ID = %5")
                                         .arg(packageDTO.getName())
                                         .arg(packageDTO.getLayer())
                                         .arg(packageDTO.getVersion())
                                         .arg(CVEReportID)
                                         .arg(packageKey->getID());

        if (packageQuery.exec(packageQueryString))
        {
            return true;
        }
    }
    return false;
}

bool PackageDAO::deleteDTO(const AbstractDTO& dto)
{
    const PackageDTO& packageDTO = static_cast<const PackageDTO&>(dto);
    return deleteDTO(packageDTO.getKey());
}

bool PackageDAO::deleteDTO(const AbstractDTO::SharedKey& id)
{
    const PackageDTO::PackageKey* packageKey = static_cast<const PackageDTO::PackageKey*>(id.get());

    if (packageKey && packageKey->getID() > 0)
    {
        QSqlQuery packageQuery(sqlDatabase);
        QString packageQueryString = QString("DELETE FROM Packages WHERE ID = %1")
                                         .arg(packageKey->getID());

        if (packageQuery.exec(packageQueryString))
        {
            return true;
        }
    }
    return false;
}

AbstractDTO::SharedIntMap PackageDAO::getPackagesOfReport(const AbstractDTO::SharedDTO &cveReport)
{
    AbstractDTO::SharedIntMap packagesMap;
    const CVEReportDTO::CVEReportKey& cveReportKey = static_cast<const CVEReportDTO::CVEReportKey&>(*cveReport->getKey());

    QSqlQuery packageQuery(sqlDatabase);
    QString packageQueryString = QString("SELECT ID, Name, Layer, Version, CVEReportID FROM Packages WHERE CVEReportID = %1")
                                     .arg(cveReportKey.getID());

    if (!packageQuery.exec(packageQueryString))
    {
        throw new std::exception();
    }
    while (packageQuery.next())
    {
        PackageDTO::SharedPackageDTO packageDTO = std::make_shared<PackageDTO>();
        packageDTO->setKey(std::make_shared<PackageDTO::PackageKey>(packageQuery.value("ID").toLongLong()));
        packageDTO->setName(packageQuery.value("Name").toString());
        packageDTO->setLayer(packageQuery.value("Layer").toString());
        packageDTO->setVersion(packageQuery.value("Version").toString());
        packageDTO->setCVEReport(cveReport);
        PackageProductDAO packageProductDAO(sqlDatabase);
        packageDTO->setPackageProducts(packageProductDAO.getPackageProducts(packageDTO));
        IssueDAO issueDAO(sqlDatabase);
        packageDTO->setIssues(issueDAO.getIssues(packageDTO));
        packagesMap.insert(static_cast<const PackageDTO::PackageKey&>(*packageDTO->getKey()).getID(), packageDTO);
    }
    return packagesMap;
}
