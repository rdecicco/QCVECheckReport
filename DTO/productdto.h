/*!
   QCVECheckReport project

   @file: productdto.h

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

#ifndef PRODUCTDTO_H
#define PRODUCTDTO_H

#include "abstractdto.h"
#include <QString>
#include <QList>

class ProductDTO : public AbstractDTO
{
public:
    class ProductKey: public AbstractDTO::Key
    {
    public:
        ProductKey() noexcept: ID() {};
        ProductKey(const ProductKey& key) noexcept: ID(key.ID) {};
        ProductKey(ProductKey&& key) noexcept: ID(key.ID) {};
        ProductKey(const QString& id) noexcept: ID(id) {};
        ~ProductKey() noexcept {};
        Key& operator=(const Key& key) noexcept override { ID = static_cast<const ProductKey&>(key).ID; return *this; };
        Key& operator=(Key&& key) noexcept override { ID = static_cast<const ProductKey&>(key).ID; return *this; };
        bool operator<(const Key& key) const override  { return ID < static_cast<const ProductKey&>(key).ID; };

        QString getID() const { return ID; };
        void setID(const QString id) { ID = id; };

    protected:
        QString ID;
    };

    using SharedProductKey = std::shared_ptr<ProductKey>;
    using SharedProductDTO = std::shared_ptr<ProductDTO>;

    ProductDTO() noexcept: AbstractDTO() {};
    ProductDTO(const SharedKey id, const QString& vendor, const QString& product, const QString& versionStart, const QString& operatorStart,const QString& versionEnd,const QString& operatorEnd) noexcept:
        AbstractDTO(id), Vendor(vendor), Product(product), VersionStart(versionStart), OperatorStart(operatorStart), VersionEnd(versionEnd), OperatorEnd(operatorEnd) {};
    ~ProductDTO() noexcept {};

protected:
    QString Vendor;
    QString Product;
    QString VersionStart;
    QString OperatorStart;
    QString VersionEnd;
    QString OperatorEnd;
    SharedDTO NVD;

public:
    QString getVendor() const { return Vendor; };
    void setVendor(const QString& vendor) { Vendor = std::move(vendor); };
    QString getProduct() const { return Product; };
    void setProduct(const QString& product) { Product = std::move(product); };
    QString getVersionStart() const { return VersionStart; };
    void setVersionStart(const QString& versionStart) { VersionStart = std::move(versionStart); };
    QString getOperatorStart() const { return OperatorStart; };
    void setOperatorStart(const QString& operatorStart) { OperatorStart = std::move(operatorStart); };
    QString getVersionEnd() const { return VersionEnd; };
    void setVersionEnd(const QString& versionEnd) { VersionEnd = std::move(versionEnd); };
    QString getOperatorEnd() const { return OperatorEnd; };
    void setOperatorEnd(const QString& operatorEnd) { OperatorEnd = std::move(operatorEnd); };
    const SharedDTO& getNVD() const { return NVD; };
    void setNVD(const SharedDTO& nvd) { NVD = nvd; };
};

#endif // PRODUCTDTO_H
