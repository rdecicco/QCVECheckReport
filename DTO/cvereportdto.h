/*!
   QCVECheckReport project

   @file: cvereportdto.h

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

#ifndef CVEREPORTDTO_H
#define CVEREPORTDTO_H

#include "abstractdto.h"
#include <QDateTime>
#include <QString>

class CVEReportDTO : public AbstractDTO
{
public:
    class CVEReportKey: public AbstractDTO::Key
    {
    public:
        CVEReportKey() noexcept : ID(0) {};
        CVEReportKey(const CVEReportKey& key) noexcept : ID(key.ID)  {};
        CVEReportKey(CVEReportKey&& key) noexcept : ID(key.ID)  {};
        CVEReportKey(const int id) noexcept : ID(id) {};
        ~CVEReportKey() noexcept {};
        Key& operator=(const Key& key) noexcept override { ID = static_cast<const CVEReportKey&>(key).ID; return *this; };
        Key& operator=(Key&& key) noexcept override { ID = static_cast<const CVEReportKey&>(key).ID; return *this; };
        bool operator<(const Key& key) const override { return ID < static_cast<const CVEReportKey&>(key).ID; };

        qint64 getID() const { return ID; };
        void setID(const qint64 id) { ID = id; };

    protected:
        qint64 ID;
    };

    using SharedCVEReportKey = std::shared_ptr<CVEReportKey>;
    using SharedCVEReportDTO = std::shared_ptr<CVEReportDTO>;

    CVEReportDTO() noexcept: AbstractDTO() {};
    CVEReportDTO(const SharedKey& id, const QString& filename, const int version, const QDateTime& date, const QString& owner) noexcept:
        AbstractDTO(id), FileName(filename), Version(version), Date(date), Owner(owner) { };
    ~CVEReportDTO() noexcept {};

protected:
    QString FileName;
    int Version;
    QDateTime Date;
    QString Owner;
    SharedIntMap Packages;

public:
    QString getFileName() const { return FileName; };
    void setFileName(const QString& filename) { FileName = std::move(filename); };
    int getVersion() const { return Version; };
    void setVersion(const int version) { Version = version; };
    QDateTime getDate() const { return Date; };
    void setDate(const QDateTime& date) { Date = std::move(date); };
    QString getOwner() const { return Owner; };
    void setOwner(const QString& owner) { Owner = std::move(owner); };
    const SharedIntMap& getPackages() const { return Packages; };
    void setPackages(const SharedIntMap& packages) { Packages = packages; };
};

#endif // CVEREPORTDTO_H
