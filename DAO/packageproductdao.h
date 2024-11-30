#ifndef PACKAGEPRODUCTDAO_H
#define PACKAGEPRODUCTDAO_H

#include "abstractdao.h"

class PackageProductDAO : public AbstractDAO
{
public:
    PackageProductDAO(const QSqlDatabase& database);
    ~PackageProductDAO() override {};

    // AbstractDAO interface
public:
    const AbstractDTO::SharedKey createDTO(AbstractDTO &dto) override;
    AbstractDTO::SharedDTO readDTO(const AbstractDTO::SharedKey& id) override;
    bool updateDTO(const AbstractDTO &dto) override;
    bool deleteDTO(const AbstractDTO &dto) override;
    bool deleteDTO(const AbstractDTO::SharedKey& id) override;

    AbstractDTO::SharedIntMap getPackageProducts(const AbstractDTO::SharedDTO& package);
};

#endif // PACKAGEPRODUCTDAO_H
