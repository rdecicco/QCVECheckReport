#ifndef PACKAGEDAO_H
#define PACKAGEDAO_H

#include "abstractdao.h"

class PackageDAO : public AbstractDAO
{
public:
    PackageDAO(const QSqlDatabase& database);
    ~PackageDAO() override {};

    // AbstractDAO interface
public:
    const AbstractDTO::SharedKey createDTO(AbstractDTO &dto) override;
    AbstractDTO::SharedDTO readDTO(const AbstractDTO::SharedKey& id) override;
    bool updateDTO(const AbstractDTO &dto) override;
    bool deleteDTO(const AbstractDTO &dto) override;
    bool deleteDTO(const AbstractDTO::SharedKey& id) override;

    AbstractDTO::SharedIntMap getPackagesOfReport(const AbstractDTO::SharedDTO &cveReport);
};

#endif // PACKAGEDAO_H
