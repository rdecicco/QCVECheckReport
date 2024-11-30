/*!
   QCVECheckReport project

   @file: packagedto.h

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

#ifndef PACKAGEDTO_H
#define PACKAGEDTO_H

#include "abstractdto.h"
#include <QString>
#include <QMap>

class PackageDTO : public AbstractDTO
{
public:
    class PackageKey: public AbstractDTO::Key
    {
    public:
        PackageKey(): ID(0) {};
        PackageKey(const PackageKey& key): ID(key.ID)  {};
        PackageKey(PackageKey&& key): ID(key.ID) {};
        PackageKey(const int id): ID(id) {};
        ~PackageKey() {};
        Key& operator=(const Key& key) noexcept override { ID = static_cast<const PackageKey&>(key).ID; return *this; };
        Key& operator=(Key&& key) noexcept override { ID = static_cast<const PackageKey&>(key).ID; return *this; };
        bool operator<(const Key& key) const override { return ID < static_cast<const PackageKey&>(key).ID; };

        qint64 getID() const { return ID; };
        void setID(const qint64 id) { ID = id; };

    protected:
        qint64 ID;
    };

    using SharedPackageKey = std::shared_ptr<PackageKey>;
    using SharedPackageDTO = std::shared_ptr<PackageDTO>;

    PackageDTO() noexcept: AbstractDTO()  {};
    PackageDTO(const std::shared_ptr<AbstractDTO::Key>& id, const QString& name, const QString& layer, const QString& version, const std::shared_ptr<AbstractDTO> report) noexcept:
        AbstractDTO(id), Name(name), Layer(layer), Version(version), cveReport(report) {};
    ~PackageDTO() noexcept {};

protected:
    QString Name;
    QString Layer;
    QString Version;
    std::shared_ptr<AbstractDTO> cveReport;
    SharedIntMap PackageProducts;
    SharedIntMap Issues;

public:
    QString getName() const { return Name; };
    void setName(const QString& name) { Name = std::move(name); };
    QString getLayer() const { return Layer; };
    void setLayer(const QString& layer) { Layer = std::move(layer); };
    QString getVersion() const { return Version; };
    void setVersion(const QString& version) { Version = std::move(version); };
    std::shared_ptr<AbstractDTO> getCVEReport() const { return cveReport; };
    void setCVEReport(const std::shared_ptr<AbstractDTO> report) { cveReport = report; };
    const SharedIntMap& getPackageProducts() const { return PackageProducts; };
    void setPackageProducts(const SharedIntMap& packageProducts) { PackageProducts = packageProducts; };
    const SharedIntMap& getIssues() const { return Issues; };
    void setIssues(const SharedIntMap& issues) { Issues = issues; };
};

#endif // PACKAGEDTO_H
