/*!
   QCVECheckReport project

   @file: packageproductdao.cpp

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

#include "DAO/packagedao.h"
#include "DTO/abstractdto.h"
#include "DTO/packageproductdto.h"
#include "DAO/packageproductdao.h"
#include "qsqlquery.h"
#include <QFileInfo>
#include "DTO/packagedto.h"

PackageProductDAO::PackageProductDAO(const QSqlDatabase &database): AbstractDAO(database) {}

const AbstractDTO::SharedKey PackageProductDAO::createDTO(AbstractDTO& dto)
{
    const PackageProductDTO& packageProductDTO = static_cast<const PackageProductDTO&>(dto);
    const PackageDTO::PackageKey* packageKey = packageProductDTO.getPackage() ? static_cast<const PackageDTO::PackageKey*>(packageProductDTO.getPackage()->getKey().get()) : nullptr;
    qint64 packageId = packageKey ? packageKey->getID() : 0;

    QSqlQuery packageProductQuery(sqlDatabase);
    QString packageProductQueryString = QString("INSERT INTO PackageProducts (Product, cvesInRecord, PackageID) VALUES ( '%1', %2, %3 )")
                                            .arg(packageProductDTO.getProduct())
                                            .arg(packageProductDTO.getCVEsInrecord())
                                            .arg(packageId);

    if (!packageProductQuery.exec(packageProductQueryString))
    {
        throw new std::exception();
    }
    dto.setKey(std::make_shared<PackageProductDTO::PackageProductKey>(packageProductQuery.lastInsertId().toLongLong()));
    return dto.getKey();
}

AbstractDTO::SharedDTO PackageProductDAO::readDTO(const AbstractDTO::SharedKey &id)
{
    const PackageProductDTO::PackageProductKey* packageProductKey = static_cast<const PackageProductDTO::PackageProductKey*>(id.get());
    if (packageProductKey)
    {
        QSqlQuery packageProductQuery(sqlDatabase);
        QString packageProductQueryString = QString("SELECT Product, cvesInRecord, PackageID FROM PackageProducts WHERE ID = %1")
                                                .arg(packageProductKey->getID());

        if (!packageProductQuery.exec(packageProductQueryString))
        {
            throw new std::exception();
        }
        if (packageProductQuery.next())
        {
            std::shared_ptr<PackageProductDTO> packageProductDTO = std::make_shared<PackageProductDTO>();
            packageProductDTO->setKey(id);
            packageProductDTO->setCVEsInrecord(packageProductQuery.value("cvesInRecord").toBool());
            PackageDAO packageDAO(sqlDatabase);
            packageProductDTO->setPackage(packageDAO.readDTO(std::make_shared<PackageDTO::PackageKey>(packageProductQuery.value("PackageID").toLongLong())));
            return packageProductDTO;
        }
    }
    return nullptr;
}

bool PackageProductDAO::updateDTO(const AbstractDTO& dto)
{
    const PackageProductDTO& packageProductDTO = static_cast<const PackageProductDTO&>(dto);
    const PackageProductDTO::PackageProductKey* packageProductKey = static_cast<const PackageProductDTO::PackageProductKey*>(packageProductDTO.getKey().get());
    if (packageProductKey)
    {
        const PackageDTO::PackageKey* packageKey = packageProductDTO.getPackage() ? static_cast<const PackageDTO::PackageKey*>(packageProductDTO.getPackage()->getKey().get()) : nullptr;
        qint64 packageId = packageKey ? packageKey->getID() : 0;
        QSqlQuery packageProductQuery(sqlDatabase);
        QString packageProductQueryString = QString("UPDATE PackageProducts SET Product = '%1', cvesInRecord = %2, PackageID = %3 WHERE ID = %4")
                                                .arg(packageProductDTO.getProduct())
                                                .arg(packageProductDTO.getCVEsInrecord())
                                                .arg(packageId)
                                                .arg(packageProductKey->getID());

        if (packageProductQuery.exec(packageProductQueryString))
        {
            return true;
        }
    }
    return false;
}

bool PackageProductDAO::deleteDTO(const AbstractDTO& dto)
{
    const PackageProductDTO& packageProductDTO = static_cast<const PackageProductDTO&>(dto);
    return deleteDTO(packageProductDTO.getKey());
}

bool PackageProductDAO::deleteDTO(const AbstractDTO::SharedKey &id)
{
    const PackageProductDTO::PackageProductKey* packageProductKey = static_cast<const PackageProductDTO::PackageProductKey*>(id.get());

    if (packageProductKey && packageProductKey->getID() > 0)
    {
        QSqlQuery packageProductQuery(sqlDatabase);
        QString packageProductQueryString = QString("DELETE FROM PackageProducts WHERE ID = %1")
                                                .arg(packageProductKey->getID());

        if (packageProductQuery.exec(packageProductQueryString))
        {
            return true;
        }
    }
    return false;
}

AbstractDTO::SharedIntMap PackageProductDAO::getPackageProducts(const AbstractDTO::SharedDTO& package)
{
    AbstractDTO::SharedIntMap packageProductsMap;
    const PackageDTO::PackageKey& packageKey = static_cast<const PackageDTO::PackageKey&>(*package->getKey());

    QSqlQuery packageProductQuery(sqlDatabase);
    QString packageProductQueryString = QString("SELECT ID, Product, cvesInRecord, PackageID FROM PackageProducts WHERE PackageID = %1")
                                     .arg(packageKey.getID());

    if (!packageProductQuery.exec(packageProductQueryString))
    {
        throw new std::exception();
    }
    while (packageProductQuery.next())
    {
        PackageProductDTO::SharedPackageProductDTO packageProductDTO = std::make_shared<PackageProductDTO>();
        packageProductDTO->setKey(std::make_shared<PackageProductDTO::PackageProductKey>(packageProductQuery.value("ID").toLongLong()));
        packageProductDTO->setProduct(packageProductQuery.value("Product").toString());
        packageProductDTO->setCVEsInrecord(packageProductQuery.value("cvesInRecord").toBool());
        packageProductDTO->setPackage(package);
        packageProductsMap.insert(static_cast<const PackageProductDTO::PackageProductKey&>(*packageProductDTO->getKey()).getID(), packageProductDTO);
    }
    return packageProductsMap;
}
