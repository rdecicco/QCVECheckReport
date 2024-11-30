#ifndef ISSUEDAO_H
#define ISSUEDAO_H

#include "abstractdao.h"

class IssueDAO : public AbstractDAO
{
public:
    IssueDAO(const QSqlDatabase& database);
    ~IssueDAO() override {};

    // AbstractDAO interface
public:
    const AbstractDTO::SharedKey createDTO(AbstractDTO &dto) override;
    AbstractDTO::SharedDTO readDTO(const AbstractDTO::SharedKey &id) override;
    bool updateDTO(const AbstractDTO &dto) override;
    bool deleteDTO(const AbstractDTO &dto) override;
    bool deleteDTO(const AbstractDTO::SharedKey &id) override;

    AbstractDTO::SharedIntMap getIssues(const AbstractDTO::SharedDTO& package);
};

#endif // ISSUEDAO_H
