#include "jsoncvecheckreportmanager.h"
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QException>
#include <QMessageBox>
#include <QIcon>

JsonCVECheckReportManager::JsonCVECheckReportManager(QObject *parent)
    : QObject{parent}
{}

bool JsonCVECheckReportManager::open(const QString& jsonReportFileName)
{
    isValid = false;
    QFile jsonReportFile = QFile(jsonReportFileName);
    if (jsonReportFile.open(QFile::OpenModeFlag::ReadOnly))
    {
        QJsonParseError jsonParseError;
        jsonDocument = QJsonDocument::fromJson(jsonReportFile.readAll(), &jsonParseError);
        if (jsonParseError.error == QJsonParseError::NoError)
        {
            isValid = isValidCVEReport();
            return isValid;
        }
    }
    return false;
}

bool JsonCVECheckReportManager::isValidCVEReport()
{
    if (jsonDocument.isObject())
    {
        QJsonObject CVEReport = jsonDocument.object();
        QJsonValue version = CVEReport.value("version");
        if (version.isNull() || !version.isString())
        {
            return false;
        }
        QJsonValue packages = CVEReport.value("package");
        if (!packages.isArray())
        {
            return false;
        }
        for (auto&& package : packages.toArray())
        {
            if (!package.isObject())
            {
                return false;
            }
            QJsonObject packageObject = package.toObject();
            for (auto&& packageKey : packageObject.keys())
            {
                QJsonValue packageValue = packageObject.value(packageKey);
                if (packageKey == "name" ||
                    packageKey == "layer" ||
                    packageKey == "version")
                {
                    if (packageValue.isNull() || !packageValue.isString())
                    {
                        return false;
                    }
                }
                else if (packageKey == "products")
                {
                    QJsonValue products = packageObject.value("products");
                    if (!products.isArray())
                    {
                        return false;
                    }
                    for (auto&& product : products.toArray())
                    {
                        if (!product.isObject())
                        {
                            return false;
                        }
                        QJsonObject productObject = product.toObject();
                        for (auto&& productKey : productObject.keys())
                        {
                            QJsonValue productValue = productObject.value(productKey);
                            if (productKey == "product" ||
                                productKey == "cvesInRecord")
                            {
                                if (productValue.isNull() || !productValue.isString())
                                {
                                    return false;
                                }
                            }
                            else
                            {
                                return false;
                            }
                        }
                    }
                }
                else if (packageKey == "issue")
                {
                    QJsonValue issues = packageObject.value("issue");
                    if (!issues.isArray())
                    {
                        return false;
                    }
                    for (auto&& issue : issues.toArray())
                    {
                        if (!issue.isObject())
                        {
                            return false;
                        }
                        QJsonObject issueObject = issue.toObject();
                        for (auto&& issueKey : issueObject.keys())
                        {
                            QJsonValue issueValue = issueObject.value(issueKey);
                            if (issueKey == "id" ||
                                issueKey == "summary" ||
                                issueKey == "scorev2" ||
                                issueKey == "scorev3" ||
                                issueKey == "vector" ||
                                issueKey == "vectorString" ||
                                issueKey == "status" ||
                                issueKey == "link" ||
                                issueKey == "detail" ||
                                issueKey == "description")
                            {
                                if (issueValue.isNull() || !issueValue.isString())
                                {
                                    return false;
                                }
                            }
                            else
                            {
                                return false;
                            }
                        }
                    }
                }
                else
                {
                    return false;
                }
            }
        }
    }
    else
    {
        return false;
    }
    return true;
}
