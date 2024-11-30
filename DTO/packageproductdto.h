#ifndef PACKAGEPRODUCTDTO_H
#define PACKAGEPRODUCTDTO_H

#include "abstractdto.h"
#include <QString>

class PackageProductDTO : public AbstractDTO
{
public:
    class PackageProductKey: public AbstractDTO::Key
    {
    public:
        PackageProductKey(): ID(0) {};
        PackageProductKey(const PackageProductKey& key): ID(key.ID)  {};
        PackageProductKey(PackageProductKey&& key) noexcept: ID(key.ID) {};
        PackageProductKey(const int id): ID(id) {};
        ~PackageProductKey() {};
        Key& operator=(const Key& key) noexcept override { ID = static_cast<const PackageProductKey&>(key).ID; return *this; };
        Key& operator=(Key&& key) noexcept override { ID = static_cast<const PackageProductKey&>(key).ID; return *this; };
        bool operator<(const Key& key) const override { return ID < static_cast<const PackageProductKey&>(key).ID; };

        qint64 getID() const { return ID; };
        void setID(const qint64 id) { ID = id; };

    protected:
        qint64 ID;
    };

    PackageProductDTO() noexcept: AbstractDTO() {};
    PackageProductDTO(const SharedKey& id, const QString& product, const bool cvesInRecord, const SharedDTO& package) noexcept:
        AbstractDTO(id), Product(product), CVEsInRecord(cvesInRecord), Package(package) {};
    ~PackageProductDTO() noexcept {};

    using SharedPackageProductKey = std::shared_ptr<PackageProductKey>;
    using SharedPackageProductDTO = std::shared_ptr<PackageProductDTO>;

protected:
    QString Product;
    bool CVEsInRecord;
    SharedDTO Package;

public:
    QString getProduct() const { return Product; };
    void setProduct(const QString& product) { Product = std::move(product); };
    bool getCVEsInrecord() const { return CVEsInRecord; };
    void setCVEsInrecord(const bool cvesInrecord) { CVEsInRecord = cvesInrecord; };
    const SharedDTO& getPackage() const { return Package; };
    void setPackage(const SharedDTO& package) { Package = package; };
};

#endif // PACKAGEPRODUCTDTO_H
