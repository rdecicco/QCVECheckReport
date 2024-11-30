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
