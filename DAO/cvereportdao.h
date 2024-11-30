#ifndef CVEREPORTDAO_H
#define CVEREPORTDAO_H

#include "abstractdao.h"

class CVEReportDAO : public AbstractDAO
{
public:
    CVEReportDAO(const QSqlDatabase& database);
    ~CVEReportDAO() override {};

    // AbstractDAO interface
public:
    const AbstractDTO::SharedKey createDTO(AbstractDTO &dto) override;
    AbstractDTO::SharedDTO readDTO(const AbstractDTO::SharedKey& id) override;
    bool updateDTO(const AbstractDTO &dto) override;
    bool deleteDTO(const AbstractDTO &dto) override;
    bool deleteDTO(const AbstractDTO::SharedKey& id) override;
    bool isNewReport(QString jsonReportFileName);
    QStringList getCVEReportsList();

    AbstractDTO::SharedDTO getFullCVEReport(const QString &reportName);
};

#endif // CVEREPORTDAO_H
