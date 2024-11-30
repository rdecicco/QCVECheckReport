/*!
   QCVECheckReport project

   @file: abstractdto.h

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

#ifndef ABSTRACTDTO_H
#define ABSTRACTDTO_H

#include "qvariant.h"
#include <memory>
#include <QMap>

class AbstractDTO
{
public:
    class Key
    {
    public:
        Key() = default;
        Key(const Key& key) = default;
        virtual Key& operator=(const Key& key) = default;
        Key(Key&& key) = default;
        virtual Key& operator=(Key&& key) = default;
        virtual ~Key() = default;
        virtual bool operator<(const Key& key) const { return true; };
    };

    using SharedKey = std::shared_ptr<AbstractDTO::Key>;
    using SharedDTO = std::shared_ptr<AbstractDTO>;
    using SharedStringMap = QMap<QString, SharedDTO>;
    using SharedIntMap = QMap<qint64, SharedDTO>;
    using SharedList = QList<SharedDTO>;

    AbstractDTO(): key(nullptr) {};
    AbstractDTO(const SharedKey& id): key(id) {};
    virtual ~AbstractDTO() {};
    virtual void setKey(const SharedKey& id) { key = id; };
    virtual const SharedKey& getKey() const { return key; };
    virtual bool operator<(const Key& key) { return true; };

protected:
    SharedKey key;
};

#endif // ABSTRACTDTO_H
