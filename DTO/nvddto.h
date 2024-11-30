/*!
   QCVECheckReport project

   @file: nvddto.h

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

#ifndef NVDDTO_H
#define NVDDTO_H

#include "abstractdto.h"
#include "qdatetime.h"
#include <QString>

class NVDDTO : public AbstractDTO
{
public:
    class NVDKey: public AbstractDTO::Key
    {
    public:
        NVDKey(): ID() {};
        NVDKey(const NVDKey& key): ID(key.ID)  {};
        NVDKey(NVDKey&& key): ID(key.ID)  {};
        NVDKey(const QString& id): ID(id) {};
        ~NVDKey() {};
        Key& operator=(const Key& key) noexcept override { ID = static_cast<const NVDKey&>(key).ID; return *this; };
        Key& operator=(Key&& key) noexcept override { ID = static_cast<const NVDKey&>(key).ID; return *this; };
        bool operator<(const Key& key) const override { return ID < static_cast<const NVDKey&>(key).ID; };

        QString getID() const { return ID; };
        void setID(const QString& id) { ID = id; };

    protected:
        QString ID;
    };

    using SharedNVDKey = std::shared_ptr<NVDKey>;
    using SharedNVDDTO = std::shared_ptr<NVDDTO>;

    NVDDTO(): AbstractDTO() {};
    NVDDTO(const SharedKey& id, const QString& summary, const QString& scoreV2, const QString& scoreV3, const QDateTime& modified, const QString& vector):
        AbstractDTO(id), Summary(summary), ScoreV2(scoreV2), ScoreV3(scoreV3), Modified(modified), Vector(vector) {};
    ~NVDDTO() {};

protected:
    QString Summary;
    QString ScoreV2;
    QString ScoreV3;
    QDateTime Modified;
    QString Vector;
    QString VectorString;
    SharedList Products;

public:
    QString getSummary() const { return Summary; };
    void setSummary(const QString& summary) { Summary = std::move(summary); };
    QString getScoreV2() const { return ScoreV2; };
    void setScoreV2(const QString& scoreV2) { ScoreV2 = std::move(scoreV2); };
    QString getScoreV3() const { return ScoreV3; };
    void setScoreV3(const QString& scoreV3) { ScoreV3 = std::move(scoreV3); };
    QDateTime getModified() const { return Modified; };
    void setModified(const QDateTime& modified) { Modified = modified; };
    QString getVector() const { return Vector; };
    void setVector(const QString& vector) { Vector = std::move(vector); };
    QString getVectorString() const { return VectorString; };
    void setVectorString(const QString& vectorstring) { VectorString = std::move(vectorstring); };
    const SharedList& getProducts() const { return Products; };
    void setProducts(const SharedList& products) { Products = products; };
};

#endif // NVDDTO_H
