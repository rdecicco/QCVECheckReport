/*!
   QCVECheckReport project

   @file: issuedao.cpp

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

#include "DAO/nvddao.h"
#include "DAO/packagedao.h"
#include "DTO/packagedto.h"
#include "DTO/abstractdto.h"
#include "DTO/issuedto.h"
#include "DAO/issuedao.h"
#include "qsqlquery.h"
#include <QFileInfo>

IssueDAO::IssueDAO(const QSqlDatabase &database): AbstractDAO(database) {}

const AbstractDTO::SharedKey IssueDAO::createDTO(AbstractDTO& dto)
{
    const IssueDTO& issueDTO = static_cast<const IssueDTO&>(dto);
    const PackageDTO::PackageKey* packageKey = issueDTO.getPackage() ? static_cast<const PackageDTO::PackageKey*>(issueDTO.getPackage()->getKey().get()) : nullptr;
    qint64 packageId = packageKey ? packageKey->getID() : 0;
    const NVDDTO::NVDKey* nvdKey = issueDTO.getNVD() ? static_cast<const NVDDTO::NVDKey*>(issueDTO.getNVD()->getKey().get()) : nullptr;
    QString NVDId = nvdKey ? nvdKey->getID() : "";

    QSqlQuery issueQuery(sqlDatabase);
    QString issueQueryString = QString("INSERT INTO Issues (Status, Link, PackageID, NVDID) VALUES ( '%1', '%2', %3, '%4' )")
                                   .arg(issueDTO.getStatus())
                                   .arg(issueDTO.getLink())
                                   .arg(packageId)
                                   .arg(NVDId);

    if (!issueQuery.exec(issueQueryString))
    {
        throw new std::exception();
    }
    dto.setKey(std::make_shared<IssueDTO::IssueKey>(issueQuery.lastInsertId().toLongLong()));
    return dto.getKey();
}

AbstractDTO::SharedDTO IssueDAO::readDTO(const AbstractDTO::SharedKey &id)
{
    const IssueDTO::IssueKey* issueKey = static_cast<const IssueDTO::IssueKey*>(id.get());
    if (issueKey)
    {
        QSqlQuery issueQuery(sqlDatabase);
        QString issueQueryString = QString("SELECT Status, Link, PackageID, NVDID FROM Issues WHERE ID = %1")
                                       .arg(issueKey->getID());

        if (!issueQuery.exec(issueQueryString))
        {
            throw new std::exception();
        }
        if (issueQuery.next())
        {
            IssueDTO::SharedIssueDTO issueDTO = std::make_shared<IssueDTO>();
            issueDTO->setKey(id);
            issueDTO->setStatus(issueQuery.value("Status").toString());
            PackageDAO packageDAO(sqlDatabase);
            issueDTO->setPackage(packageDAO.readDTO(std::make_shared<PackageDTO::PackageKey>(issueQuery.value("PackageID").toLongLong())));
            NVDDAO nvdDAO(sqlDatabase);
            issueDTO->setNVD(nvdDAO.readDTO(std::make_shared<NVDDTO::NVDKey>(issueQuery.value("NVDID").toString())));
            return issueDTO;
        }
    }
    return nullptr;
}

bool IssueDAO::updateDTO(const AbstractDTO& dto)
{
    const IssueDTO& issueDTO = static_cast<const IssueDTO&>(dto);
    const IssueDTO::IssueKey* issueKey = static_cast<const IssueDTO::IssueKey*>(issueDTO.getKey().get());
    if (issueKey && issueKey->getID() > 0)
    {
        const PackageDTO::PackageKey* packageKey = issueDTO.getPackage() ? static_cast<const PackageDTO::PackageKey*>(issueDTO.getPackage()->getKey().get()) : nullptr;
        qint64 packageId = packageKey ? packageKey->getID() : 0;
        const NVDDTO::NVDKey* nvdKey = issueDTO.getNVD() ? static_cast<const NVDDTO::NVDKey*>(issueDTO.getNVD()->getKey().get()) : nullptr;
        QString NVDId = nvdKey ? nvdKey->getID() : "";

        QSqlQuery issueQuery(sqlDatabase);
        QString issueQueryString = QString("UPDATE Issues SET Status = '%1', Link = '%2', PackageID = %3, NVDID = %4 WHERE ID = %5")
                                       .arg(issueDTO.getStatus())
                                       .arg(issueDTO.getLink())
                                       .arg(packageId)
                                       .arg(NVDId)
                                       .arg(issueKey->getID());

        if (issueQuery.exec(issueQueryString))
        {
            return true;
        }
    }
    return false;
}

bool IssueDAO::deleteDTO(const AbstractDTO& dto)
{
    const IssueDTO& issueDTO = static_cast<const IssueDTO&>(dto);
    return deleteDTO(issueDTO.getKey());
}

bool IssueDAO::deleteDTO(const AbstractDTO::SharedKey &id)
{
    const IssueDTO::IssueKey* issueKey = static_cast<const IssueDTO::IssueKey*>(id.get());

    if (issueKey && issueKey->getID() > 0)
    {
        QSqlQuery issueQuery(sqlDatabase);
        QString issueQueryString = QString("DELETE FROM Issues WHERE ID = %1")
                                       .arg(issueKey->getID());

        if (issueQuery.exec(issueQueryString))
        {
            return true;
        }
    }
    return false;
}

AbstractDTO::SharedIntMap IssueDAO::getIssues(const AbstractDTO::SharedDTO& package)
{
    AbstractDTO::SharedIntMap issuesMap;
    const PackageDTO::PackageKey& packageKey = static_cast<const PackageDTO::PackageKey&>(*package->getKey());

    QSqlQuery issueQuery(sqlDatabase);
    QString issueString = QString("SELECT ID, Status, Link, PackageID, NVDID FROM Issues WHERE PackageID = %1")
                              .arg(packageKey.getID());

    if (!issueQuery.exec(issueString))
    {
        throw new std::exception();
    }
    while (issueQuery.next())
    {
        IssueDTO::SharedIssueDTO issueDTO = std::make_shared<IssueDTO>();
        issueDTO->setKey(std::make_shared<IssueDTO::IssueKey>(issueQuery.value("ID").toLongLong()));
        issueDTO->setStatus(issueQuery.value("Status").toString());
        issueDTO->setLink(issueQuery.value("Link").toString());
        issueDTO->setPackage(package);
        NVDDAO nvdDAO(sqlDatabase);
        issueDTO->setNVD(nvdDAO.readDTO(std::make_shared<NVDDTO::NVDKey>(issueQuery.value("NVDID").toString())));
        issuesMap.insert(static_cast<const IssueDTO::IssueKey&>(*issueDTO->getKey()).getID(), issueDTO);
    }
    return issuesMap;
}
