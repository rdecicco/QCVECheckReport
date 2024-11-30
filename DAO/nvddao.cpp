/*!
   QCVECheckReport project

   @file: nvddao.cpp

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

#include "DAO/productdao.h"
#include "DTO/abstractdto.h"
#include "DAO/nvddao.h"
#include "DTO/nvddto.h"
#include "DTO/issuedto.h"
#include "qsqlquery.h"
#include <QFileInfo>

NVDDAO::NVDDAO(const QSqlDatabase& database): AbstractDAO(database) {}

const AbstractDTO::SharedKey NVDDAO::createDTO(AbstractDTO& dto)
{
    const NVDDTO& nvdDTO = static_cast<const NVDDTO&>(dto);
    const NVDDTO::NVDKey* nvdKey = static_cast<const NVDDTO::NVDKey*>(nvdDTO.getKey().get());
    if (nvdKey)
    {
        QSqlQuery nvdQuery(sqlDatabase);
        QString nvdQueryString = QString("INSERT INTO NVD (ID, SUMMARY, SCOREV2, SCOREV3, MODIFIED, VECTOR) VALUES ( '%1', '%2', '%3', '%4', '%5', '%6')")
                                     .arg(nvdKey->getID())
                                     .arg(nvdDTO.getSummary().isNull() ? QString("") : nvdDTO.getSummary().replace("'", "''").replace("%", "&#37;"))
                                     .arg(nvdDTO.getScoreV2().isNull() ? "0.0" : nvdDTO.getScoreV2())
                                     .arg(nvdDTO.getScoreV3().isNull() ? "0.0" : nvdDTO.getScoreV3())
                                     .arg(nvdDTO.getModified().isNull() ? QDateTime().toUTC().toString(Qt::ISODate) : nvdDTO.getModified().toUTC().toString(Qt::ISODate))
                                     .arg(nvdDTO.getVector());

        if (fieldExist(sqlDatabase, "NVD", "VECTORSTRING"))
        {
            nvdQueryString = QString("INSERT INTO NVD (ID, SUMMARY, SCOREV2, SCOREV3, MODIFIED, VECTOR, VECTORSTRING) VALUES ( '%1', '%2', '%3', '%4', '%5', '%6', '%7')")
                                 .arg(nvdKey->getID())
                                 .arg(nvdDTO.getSummary().isNull() ? QString("") : nvdDTO.getSummary().replace("'", "''").replace("%", "&#37;"))
                                 .arg(nvdDTO.getScoreV2().isNull() ? "0.0" : nvdDTO.getScoreV2())
                                 .arg(nvdDTO.getScoreV3().isNull() ? "0.0" : nvdDTO.getScoreV3())
                                 .arg(nvdDTO.getModified().isNull() ? QDateTime().toUTC().toString(Qt::ISODate) : nvdDTO.getModified().toUTC().toString(Qt::ISODate))
                                 .arg(nvdDTO.getVector())
                                 .arg(nvdDTO.getVectorString());
        }

        nvdQueryString.replace("&#37;", "%");

        if (!nvdQuery.exec(nvdQueryString))
        {
            throw new std::exception();
        }
        dto.setKey(std::make_shared<NVDDTO::NVDKey>(nvdQuery.lastInsertId().toString()));
        return dto.getKey();
    }
    return nullptr;
}

AbstractDTO::SharedDTO NVDDAO::readDTO(const AbstractDTO::SharedKey &id)
{
    const NVDDTO::NVDKey* nvdKey = static_cast<const NVDDTO::NVDKey*>(id.get());

    if (nvdKey)
    {
        QSqlQuery nvdQuery(sqlDatabase);

        QString nvdQueryString = QString("SELECT SUMMARY, SCOREV2, SCOREV3, MODIFIED, VECTOR FROM NVD WHERE ID = '%1'")
                                     .arg(nvdKey->getID());

        bool existVectorString = fieldExist(sqlDatabase, "NVD", "VECTORSTRING");

        if (existVectorString)
        {
            nvdQueryString = QString("SELECT SUMMARY, SCOREV2, SCOREV3, MODIFIED, VECTOR, VECTORSTRING FROM NVD WHERE ID = '%1'")
                                 .arg(nvdKey->getID());
        }

        if (!nvdQuery.exec(nvdQueryString))
        {
            throw new std::exception();
        }
        if (nvdQuery.next())
        {
            NVDDTO::SharedNVDDTO nvdDTO = std::make_shared<NVDDTO>();
            nvdDTO->setKey(id);
            nvdDTO->setSummary(nvdQuery.value("SUMMARY").toString());
            nvdDTO->setScoreV2(nvdQuery.value("SCOREV2").toString());
            nvdDTO->setScoreV3(nvdQuery.value("SCOREV3").toString());
            nvdDTO->setModified(nvdQuery.value("MODIFIED").toDateTime());
            nvdDTO->setVector(nvdQuery.value("VECTOR").toString());
            if (existVectorString)
            {
                nvdDTO->setVectorString(nvdQuery.value("VECTORSTRING").toString());
            }
            return nvdDTO;
        }
    }
    return nullptr;
}

bool NVDDAO::updateDTO(const AbstractDTO& dto)
{
    const NVDDTO& nvdDTO = static_cast<const NVDDTO&>(dto);
    const NVDDTO::NVDKey* nvdKey = static_cast<const NVDDTO::NVDKey*>(nvdDTO.getKey().get());

    if (nvdKey)
    {
        QSqlQuery nvdQuery(sqlDatabase);
        QString nvdQueryString = QString("UPDATE NVD SET SUMMARY = '%1', SCOREV2 = '%2', SCOREV3 = '%3', MODIFIED = '%4', VECTOR = '%5' WHERE ID = '%6' AND MODIFIED <= '%4'")
                                     .arg(nvdDTO.getSummary().isNull() ? QString("") : nvdDTO.getSummary().replace("'", "''").replace("%", "&#37;"))
                                     .arg(nvdDTO.getScoreV2().isNull() ? "0.0" : nvdDTO.getScoreV2())
                                     .arg(nvdDTO.getScoreV3().isNull() ? "0.0" : nvdDTO.getScoreV3())
                                     .arg(nvdDTO.getModified().isNull() ? QDateTime().toUTC().toString(Qt::ISODate) : nvdDTO.getModified().toUTC().toString(Qt::ISODate))
                                     .arg(nvdDTO.getVector())
                                     .arg(nvdKey->getID());

        bool existVectorString = fieldExist(sqlDatabase, "NVD", "VECTORSTRING");

        if (existVectorString)
        {
            nvdQueryString = QString("UPDATE NVD SET SUMMARY = '%1', SCOREV2 = '%2', SCOREV3 = '%3', MODIFIED = '%4', VECTOR = '%5', VECTORSTRING = '%6' WHERE ID = '%7' AND MODIFIED <= '%4'")
                                 .arg(nvdDTO.getSummary().isNull() ? QString("") : nvdDTO.getSummary().replace("'", "''").replace("%", "&#37;"))
                                 .arg(nvdDTO.getScoreV2().isNull() ? "0.0" : nvdDTO.getScoreV2())
                                 .arg(nvdDTO.getScoreV3().isNull() ? "0.0" : nvdDTO.getScoreV3())
                                 .arg(nvdDTO.getModified().isNull() ? QDateTime().toUTC().toString(Qt::ISODate) : nvdDTO.getModified().toUTC().toString(Qt::ISODate))
                                 .arg(nvdDTO.getVector())
                                 .arg(nvdDTO.getVectorString())
                                 .arg(nvdKey->getID());
        }

        nvdQueryString.replace("&#37;", "%");

        if (nvdQuery.exec(nvdQueryString))
        {
            return true;
        }
    }
    return false;
}

bool NVDDAO::deleteDTO(const AbstractDTO& dto)
{
    const NVDDTO& nvdDTO = static_cast<const NVDDTO&>(dto);
    return deleteDTO(nvdDTO.getKey());
}

bool NVDDAO::deleteDTO(const AbstractDTO::SharedKey& id)
{
    const NVDDTO::NVDKey* nvdKey = static_cast<const NVDDTO::NVDKey*>(id.get());
    if (nvdKey)
    {
        if (!nvdKey->getID().isNull() && !nvdKey->getID().isEmpty())
        {
            QSqlQuery nvdQuery(sqlDatabase);
            QString nvdQueryString = QString("DELETE FROM NVD WHERE ID = '%1'")
                                         .arg(nvdKey->getID());

            if (nvdQuery.exec(nvdQueryString))
            {
                return true;
            }
        }
    }
    return false;
}

QList<NVDDTO> NVDDAO::getAllNVDs()
{
    QList<NVDDTO> result;
    QSqlQuery nvdQuery = QSqlQuery(sqlDatabase);
    QString nvdQueryString = QString("SELECT ID, SUMMARY, SCOREV2, SCOREV3, MODIFIED, VECTOR FROM NVD");

    bool existVectorString = fieldExist(sqlDatabase, "NVD", "VECTORSTRING");

    if (existVectorString)
    {
        nvdQueryString = QString("SELECT ID, SUMMARY, SCOREV2, SCOREV3, MODIFIED, VECTOR, VECTORSTRING FROM NVD");
    }

    if (nvdQuery.exec(nvdQueryString))
    {
        if (nvdQuery.isSelect())
        {
            while (nvdQuery.next())
            {
                NVDDTO nvdDTO;
                nvdDTO.setKey(std::make_shared<NVDDTO::NVDKey>(nvdQuery.value("ID").toString()));
                nvdDTO.setSummary(nvdQuery.value("SUMMARY").toString());
                nvdDTO.setScoreV2(nvdQuery.value("SCOREV2").toString());
                nvdDTO.setScoreV3(nvdQuery.value("SCOREV3").toString());
                nvdDTO.setModified(nvdQuery.value("MODIFIED").toDateTime());
                nvdDTO.setVector(nvdQuery.value("VECTOR").toString());

                if (existVectorString)
                {
                    nvdDTO.setVectorString(nvdQuery.value("VECTORSTRING").toString());
                }

                result.push_back(nvdDTO);
            }
        }
    }
    return result;
}


AbstractDTO::SharedDTO NVDDAO::getNVD(const AbstractDTO::SharedDTO& issue)
{
    const IssueDTO::IssueKey& issueKey = static_cast<const IssueDTO::IssueKey&>(*issue->getKey());

    QSqlQuery nvdQuery(sqlDatabase);
    QString nvdQueryString = QString("SELECT ID, SUMMARY, SCOREV2, SCOREV3, MODIFIED, VECTOR FROM NVD WHERE ID = '%1'")
                              .arg(issueKey.getID());

    bool existVectorString = fieldExist(sqlDatabase, "NVD", "VECTORSTRING");

    if (existVectorString)
    {
        nvdQueryString = QString("SELECT ID, SUMMARY, SCOREV2, SCOREV3, MODIFIED, VECTOR, VECTORSTRING FROM NVD WHERE ID = '%1'")
                             .arg(issueKey.getID());
    }

    if (!nvdQuery.exec(nvdQueryString))
    {
        throw new std::exception();
    }
    if (nvdQuery.next())
    {
        NVDDTO::SharedNVDDTO nvdDTO = std::make_shared<NVDDTO>();
        nvdDTO->setKey(std::make_shared<IssueDTO::IssueKey>(nvdQuery.value("ID").toLongLong()));
        nvdDTO->setSummary(nvdQuery.value("SUMMARY").toString());
        nvdDTO->setScoreV2(nvdQuery.value("SCOREV2").toString());
        nvdDTO->setScoreV3(nvdQuery.value("SCOREV3").toString());
        nvdDTO->setModified(nvdQuery.value("MODIFIED").toDateTime());
        nvdDTO->setVector(nvdQuery.value("VECTOR").toString());
        if (existVectorString)
        {
            nvdDTO->setVectorString(nvdQuery.value("VECTORSTRING").toString());
        }
        ProductDAO productDAO(sqlDatabase);
        nvdDTO->setProducts(productDAO.getProducts(nvdDTO));
        return nvdDTO;

    }
    return nullptr;
}
