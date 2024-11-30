#ifndef PRODUCTDAO_H
#define PRODUCTDAO_H

#include "abstractdao.h"
#include "DTO/productdto.h"

class ProductDAO : public AbstractDAO
{
public:
    ProductDAO(const QSqlDatabase& database);
    ~ProductDAO() override {};

    // AbstractDAO interface
public:
    const AbstractDTO::SharedKey createDTO(AbstractDTO &dto) override;
    AbstractDTO::SharedDTO readDTO(const AbstractDTO::SharedKey&  id) override;
    bool updateDTO(const AbstractDTO &dto) override;
    bool deleteDTO(const AbstractDTO &dto) override;
    bool deleteDTO(const AbstractDTO::SharedKey &id) override;

    int versionComparator(QString version1, QString version2);
    QList<ProductDTO> getAllProducts();
    bool existsDTO(const AbstractDTO &dto);

    AbstractDTO::SharedList getProducts(const AbstractDTO::SharedDTO& nvd);
    QStringList getAllProductsNames();
};

#endif // PRODUCTDAO_H
