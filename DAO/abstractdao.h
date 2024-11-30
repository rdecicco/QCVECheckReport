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
