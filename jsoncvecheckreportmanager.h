#ifndef JSONCVECHECKREPORTMANAGER_H
#define JSONCVECHECKREPORTMANAGER_H

#include <QObject>
#include <QJsonDocument>
#include <qexception.h>

class JsonCVECheckReportManager : public QObject
{
    Q_OBJECT

public:
    explicit JsonCVECheckReportManager(QObject *parent = nullptr);
    bool open(const QString &jsonReportFileName);
    QJsonDocument getJsonDocument() { return jsonDocument; };
    bool isValidDocument() { return isValid; };

signals:

protected:
    bool isValidCVEReport();

private:
    QJsonDocument jsonDocument;
    bool isValid = false;
};

#endif // JSONCVECHECKREPORTMANAGER_H
