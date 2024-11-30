/*!
   QCVECheckReport project

   @file: abstractdao.h

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

#ifndef ABSTRACTDAO_H
#define ABSTRACTDAO_H

#include "DTO/abstractdto.h"
#include <QSqlDatabase>
#include <QSqlQuery>

class AbstractDAO
{
public:
    AbstractDAO(const QSqlDatabase& database): sqlDatabase(database) {};
    virtual ~AbstractDAO() { };

    virtual const AbstractDTO::SharedKey createDTO(AbstractDTO& dto) { return dto.getKey(); };
    virtual AbstractDTO::SharedDTO readDTO(const AbstractDTO::SharedKey& id) { return nullptr; };
    virtual bool updateDTO(const AbstractDTO& dto) { return false; };
    virtual bool deleteDTO(const AbstractDTO& dto) { return false; };
    virtual bool deleteDTO(const AbstractDTO::SharedKey& id) { return false; };

    static bool fieldExist(QSqlDatabase db, QString tableName, QString fieldName)
    {
        bool exist = false;

        try
        {
            if (db.isOpen())
            {
                QSqlQuery query(db);
                QString queryString = QString("SELECT %1 FROM %2 LIMIT 1").arg(fieldName).arg(tableName);

                if (query.exec(queryString))
                {
                    exist = true;
                }
            }
        }
        catch (...)
        {

        }

        return exist;
    }

protected:
    const QSqlDatabase& sqlDatabase;
};

#endif // ABSTRACTDAO_H
