/*!
   QCVECheckReport project

   @file: packageproductdto.h

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
