/*!
   QCVECheckReport project

   @file: jsoncvecheckreportmanager.cpp

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
