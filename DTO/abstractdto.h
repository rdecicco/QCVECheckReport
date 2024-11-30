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
