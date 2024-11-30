/*!
   QCVECheckReport project

   @file: productdao.cpp

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

#include "DTO/abstractdto.h"
#include "DTO/productdto.h"
#include "DAO/productdao.h"
#include "DTO/nvddto.h"
#include "qsqlquery.h"
#include <QFileInfo>

ProductDAO::ProductDAO(const QSqlDatabase &database): AbstractDAO(database) {}

int ProductDAO::versionComparator(QString version1, QString version2)
{
    int returnValue = 0;

    if (version1.isNull() || version1.isEmpty())
    {
        if (version2.isNull() || version2.isEmpty())
        {
            return 0;
        }
        else
        {
            return 1;
        }
    }
    else
    {
        if (version2.isNull() || version2.isEmpty())
        {
            return -1;
        }

        QStringList splittedVersion1 = version1.split(".");
        QStringList splittedVersion2 = version2.split(".");

        int maxCount = splittedVersion1.count() < splittedVersion2.count() ? splittedVersion1.count() : splittedVersion2.count();

        for (int i = 0; i < maxCount; i++)
        {
            bool conversion1 = false, conversion2 = false;
            QString version1Value = splittedVersion1.value(i);
            QString version2Value = splittedVersion2.value(i);
            int version1intValue = version1Value.toInt(&conversion1);
            int version2intValue = version2Value.toInt(&conversion2);

            if (conversion1)
            {
                if (conversion2)
                {
                    if (returnValue == 0)
                    {
                        if (version1intValue < version2intValue)
                            returnValue = 1;
                        else if (version1intValue > version2intValue)
                            returnValue = -1;

                        return returnValue;
                    }
                }
                else
                {
                    if (returnValue == 0)
                    {
                        if (splittedVersion1.count() > maxCount)
                        {
                            return -1;
                        }
                        else if (splittedVersion2.count() > maxCount)
                        {
                            return 1;
                        }
                        else return 0;
                    }
                }
            }
            else if (conversion2)
            {
                if (returnValue == 0)
                {
                    return 1;
                }
            }
            else
            {
                if (returnValue == 0)
                {
                    if (version1Value > version2Value)
                        return -1;
                    else if (version1Value < version2Value)
                        return 1;

                    return 0;
                }
            }

        }
    }
    return returnValue;
}

const AbstractDTO::SharedKey ProductDAO::createDTO(AbstractDTO& dto)
{
    const ProductDTO& productDTO = static_cast<const ProductDTO&>(dto);
    const ProductDTO::ProductKey* productKey = static_cast<const ProductDTO::ProductKey*>(productDTO.getKey().get());
    if (productKey && !productKey->getID().isNull() && !productKey->getID().isEmpty())
    {
        QSqlQuery productQuery(sqlDatabase);
        QString productQueryString = QString("INSERT INTO PRODUCTS (ID, VENDOR, PRODUCT, VERSION_START, OPERATOR_START, VERSION_END, OPERATOR_END) VALUES ( '%1', '%2', '%3', '%4', '%5', '%6', '%7' )")
                                         .arg(productKey->getID())
                                         .arg(productDTO.getVendor().replace("'", "''"))
                                         .arg(productDTO.getProduct().replace("'", "''"))
                                         .arg(productDTO.getVersionStart().replace("'", "''"))
                                         .arg(productDTO.getOperatorStart())
                                         .arg(productDTO.getVersionEnd().replace("'", "''"))
                                         .arg(productDTO.getOperatorEnd());

        if (!productQuery.exec(productQueryString))
        {
            throw new std::exception();
        }
    }
    return dto.getKey();
}

AbstractDTO::SharedDTO ProductDAO::readDTO(const AbstractDTO::SharedKey& id)
{
    const ProductDTO::ProductKey* productKey = static_cast<const ProductDTO::ProductKey*>(id.get());
    if (productKey)
    {
        QSqlQuery productQuery(sqlDatabase);
        QString productQueryString = QString("SELECT VENDOR, PRODUCT, VERSION_START, OPERATOR_START, VERSION_END, OPERATOR_END FROM PRODUCTS WHERE ID = '%1'")
                                         .arg(productKey->getID());

        if (!productQuery.exec(productQueryString))
        {
            throw new std::exception();
        }
        if (productQuery.next())
        {
            std::shared_ptr<ProductDTO> productDTO = std::make_shared<ProductDTO>();
            productDTO->setKey(id);
            productDTO->setVendor(productQuery.value("VENDOR").toString());
            productDTO->setProduct(productQuery.value("PRODUCT").toString());
            productDTO->setVersionStart(productQuery.value("VERSION_START").toString());
            productDTO->setOperatorStart(productQuery.value("OPERATOR_START").toString());
            productDTO->setVersionEnd(productQuery.value("VERSION_END").toString());
            productDTO->setOperatorEnd(productQuery.value("OPERATOR_END").toString());
            return productDTO;
        }
    }
    return nullptr;
}

bool ProductDAO::updateDTO(const AbstractDTO& dto)
{
    const ProductDTO& productDTO = static_cast<const ProductDTO&>(dto);
    const ProductDTO::ProductKey* productKey = static_cast<const ProductDTO::ProductKey*>(productDTO.getKey().get());
    if (productKey)
    {
        QSqlQuery productQuery(sqlDatabase);
        QString productQueryString = QString("UPDATE PRODUCTS SET VENDOR = '%1', PRODUCT = '%2', VERSION_START = '%3', OPERATOR_START = '%4', VERSION_END = '%5', OPERATOR_END = '%6' WHERE ID = '%7'")
                                         .arg(productDTO.getVendor().replace("'", "''"))
                                         .arg(productDTO.getProduct().replace("'", "''"))
                                         .arg(productDTO.getVersionStart().replace("'", "''"))
                                         .arg(productDTO.getOperatorStart())
                                         .arg(productDTO.getVersionEnd().replace("'", "''"))
                                         .arg(productDTO.getOperatorEnd())
                                         .arg(productKey->getID());

        if (productQuery.exec(productQueryString))
        {
            return true;
        }
    }
    return false;
}

bool ProductDAO::deleteDTO(const AbstractDTO& dto)
{
    const ProductDTO& productDTO = static_cast<const ProductDTO&>(dto);
    return deleteDTO(productDTO.getKey());
}

bool ProductDAO::deleteDTO(const AbstractDTO::SharedKey &id)
{
    const ProductDTO::ProductKey* productKey = static_cast<const ProductDTO::ProductKey*>(id.get());
    if (productKey && !productKey->getID().isNull() && !productKey->getID().isEmpty())
    {
        QSqlQuery productQuery(sqlDatabase);
        QString productQueryString = QString("DELETE FROM PRODUCTS WHERE ID = '%1'")
                                         .arg(productKey->getID());

        if (productQuery.exec(productQueryString))
        {
            return true;
        }
    }
    return false;
}

QList<ProductDTO> ProductDAO::getAllProducts()
{
    QList<ProductDTO> result;
    QSqlQuery productQuery = QSqlQuery(sqlDatabase);
    QString productQueryString = QString("SELECT ID, VENDOR, PRODUCT, VERSION_START, OPERATOR_START, VERSION_END, OPERATOR_END FROM PRODUCTS");

    if (productQuery.exec(productQueryString))
    {
        if (productQuery.isSelect())
        {
            while (productQuery.next())
            {
                ProductDTO productDTO;
                productDTO.setKey(std::make_shared<ProductDTO::ProductKey>(productQuery.value("ID").toString()));
                productDTO.setVendor(productQuery.value("VENDOR").toString());
                productDTO.setProduct(productQuery.value("PRODUCT").toString());
                productDTO.setVersionStart(productQuery.value("VERSION_START").toString());
                productDTO.setOperatorStart(productQuery.value("OPERATOR_START").toString());
                productDTO.setVersionEnd(productQuery.value("VERSION_END").toString());
                productDTO.setOperatorEnd(productQuery.value("OPERATOR_END").toString());
                result.push_back(productDTO);
            }
        }
    }
    return result;
}

QStringList ProductDAO::getAllProductsNames()
{
    QStringList result;
    QSqlQuery productQuery = QSqlQuery(sqlDatabase);
    QString productQueryString = QString("SELECT DISTINCT P.PRODUCT "
                                         "FROM PRODUCTS P, NVD N "
                                         "WHERE P.ID = N.ID "
                                         "ORDER BY P.PRODUCT ");

    if (productQuery.exec(productQueryString))
    {
        if (productQuery.isSelect())
        {
            while (productQuery.next())
            {
                result.push_back(productQuery.value("PRODUCT").toString());
            }
        }
    }
    return result;
}

bool ProductDAO::existsDTO(const AbstractDTO &dto)
{
    const ProductDTO& productDTO = static_cast<const ProductDTO&>(dto);
    const ProductDTO::ProductKey* productKey = static_cast<const ProductDTO::ProductKey*>(productDTO.getKey().get());
    if (productKey)
    {
        QSqlQuery productQuery(sqlDatabase);
        QString productQueryString = QString("SELECT ID FROM PRODUCTS WHERE ID = '%1' AND VENDOR = '%2' AND PRODUCT = '%3' AND VERSION_START = '%4' AND OPERATOR_START = '%5' AND VERSION_END = '%6' AND OPERATOR_END = '%7'")
                                         .arg(productKey->getID())
                                         .arg(productDTO.getVendor().replace("'", "''"))
                                         .arg(productDTO.getProduct().replace("'", "''"))
                                         .arg(productDTO.getVersionStart().replace("'", "''"))
                                         .arg(productDTO.getOperatorStart())
                                         .arg(productDTO.getVersionEnd().replace("'", "''"))
                                         .arg(productDTO.getOperatorEnd());

        if (productQuery.exec(productQueryString))
        {
            if (productQuery.next())
            {
                return true;
            }
        }
    }
    return false;
}

AbstractDTO::SharedList ProductDAO::getProducts(const AbstractDTO::SharedDTO& nvd)
{
    AbstractDTO::SharedList productsList;
    const NVDDTO::NVDKey& nvdKey = static_cast<const NVDDTO::NVDKey&>(*nvd->getKey());

    QSqlQuery productQuery(sqlDatabase);
    QString productQueryString = QString("SELECT ID, VENDOR, PRODUCT, VERSION_START, OPERATOR_START, VERSION_END, OPERATOR_END FROM PRODUCTS WHERE ID = %1")
                                            .arg(nvdKey.getID());

    if (!productQuery.exec(productQueryString))
    {
        throw new std::exception();
    }
    while (productQuery.next())
    {
        ProductDTO::SharedProductDTO productDTO = std::make_shared<ProductDTO>();
        productDTO->setKey(std::make_shared<ProductDTO::ProductKey>(productQuery.value("ID").toString()));
        productDTO->setVendor(productQuery.value("VENDOR").toString());
        productDTO->setProduct(productQuery.value("PRODUCT").toString());
        productDTO->setVersionStart(productQuery.value("VERSION_START").toString());
        productDTO->setOperatorStart(productQuery.value("OPERATOR_START").toString());
        productDTO->setVersionEnd(productQuery.value("OPERATOR_END").toString());
        productDTO->setOperatorEnd(productQuery.value("PRODUCT").toString());
        productDTO->setNVD(nvd);
        productsList.push_back(productDTO);
    }
    return productsList;
}
