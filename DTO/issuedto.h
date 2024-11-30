/*!
   QCVECheckReport project

   @file: issuedto.h

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

#ifndef ISSUEDTO_H
#define ISSUEDTO_H

#include "abstractdto.h"
#include <QDateTime>
#include <QString>

class IssueDTO : public AbstractDTO
{
public:
    class IssueKey: public AbstractDTO::Key
    {
    public:
        IssueKey() noexcept: ID(0) {};
        IssueKey(const IssueKey& key) noexcept: ID(key.ID) {};
        IssueKey(IssueKey&& key) noexcept: ID(key.ID) {};
        IssueKey(const int id) noexcept: ID(id) {};
        ~IssueKey() {};
        Key& operator=(const Key& key) noexcept override { ID = static_cast<const IssueKey&>(key).ID; return *this; };
        Key& operator=(Key&& key) noexcept override { ID = static_cast<const IssueKey&>(key).ID; return *this; };
        bool operator<(const Key& key) const override { return ID < static_cast<const IssueKey&>(key).ID; };

        qint64 getID() const { return ID; };
        void setID(const qint64 id) { ID = id; };

    protected:
        qint64 ID;
    };

    using SharedIssueKey = std::shared_ptr<IssueKey>;
    using SharedIssueDTO = std::shared_ptr<IssueDTO>;

    IssueDTO() noexcept: AbstractDTO() {};
    IssueDTO(const SharedKey& id, const QString& status, const QString& link, const SharedDTO& package, const SharedDTO& nvd) noexcept:
        AbstractDTO(id), Status(status), Link(link), Package(package), NVD(nvd) {};
    ~IssueDTO() noexcept {};

protected:
    QString Status;
    QString Link;
    SharedDTO Package;
    SharedDTO NVD;

public:
    QString getStatus() const { return Status; };
    void setStatus(const QString& status) { Status = std::move(status); };
    QString getLink() const { return Link; };
    void setLink(const QString& link) { Link = std::move(link); };
    SharedDTO getPackage() const { return Package; };
    void setPackage(const SharedDTO package) { Package = package; };
    const SharedDTO& getNVD() const { return NVD; };
    void setNVD(const SharedDTO& nvd) { NVD = nvd; };
};

#endif // ISSUEDTO_H
