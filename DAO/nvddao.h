#ifndef NVDDAO_H
#define NVDDAO_H

#include "abstractdao.h"
#include "DTO/nvddto.h"

class NVDDAO : public AbstractDAO
{
public:
    NVDDAO(const QSqlDatabase& database);
    ~NVDDAO() override {};

    // AbstractDAO interface
public:
    const AbstractDTO::SharedKey createDTO(AbstractDTO &dto) override;
    AbstractDTO::SharedDTO readDTO(const AbstractDTO::SharedKey& id) override;
    bool updateDTO(const AbstractDTO &dto) override;
    bool deleteDTO(const AbstractDTO &dto) override;
    bool deleteDTO(const AbstractDTO::SharedKey& id) override;

    QList<NVDDTO> getAllNVDs();

    AbstractDTO::SharedDTO getNVD(const AbstractDTO::SharedDTO& issue);
};

#endif // NVDDAO_H
