/*!
   QCVECheckReport project

   @file: productdao.h

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
