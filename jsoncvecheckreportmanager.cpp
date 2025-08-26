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
            QMessageBox::critical(nullptr, tr("Import Json Report Error"), tr("Import of CSV Report Failed: Not valid json report version"));
            return false;
        }
        QJsonValue packages = CVEReport.value("package");
        if (!packages.isArray())
        {
            QMessageBox::critical(nullptr, tr("Import Json Report Error"), tr("Import of CSV Report Failed: Not valid json report"));
            return false;
        }
        for (auto&& package : packages.toArray())
        {
            QString packageName;
            QString packageLayer;
            QString packageVersion;
            if (!package.isObject())
            {
                QMessageBox::critical(nullptr, tr("Import Json Report Error"), tr("Import of CSV Report Failed: Not valid package"));
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
                        QMessageBox::critical(nullptr, tr("Import Json Report Error"), tr("Import of CSV Report Failed: Not valid package key value:") + packageName + ": " + packageKey);
                        return false;
                    }
                    else
                    {
                        if (packageKey == "name")
                            packageName = packageValue.toString();
                        else if (packageKey == "layer")
                            packageLayer = packageValue.toString();
                        else if (packageKey == "version")
                            packageVersion = packageValue.toString();
                    }
                }
                else if (packageKey == "products")
                {
                    QJsonValue products = packageObject.value("products");
                    if (!products.isArray())
                    {
                        QMessageBox::critical(nullptr, tr("Import Json Report Error"), tr("Import of CSV Report Failed: Not valid products: ") + packageName + ": " + packageKey);
                        return false;
                    }
                    for (auto&& product : products.toArray())
                    {
                        if (!product.isObject())
                        {
                            QMessageBox::critical(nullptr, tr("Import Json Report Error"), tr("Import of CSV Report Failed: Not valid product of package:") + packageName + ": " + product.toString());
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
                                    QMessageBox::critical(nullptr, tr("Import Json Report Error"), tr("Import of CSV Report Failed: Not valid product value of package:") + packageName + " - " + productKey);
                                    return false;
                                }
                            }
                            else
                            {
                                QMessageBox::critical(nullptr, tr("Import Json Report Error"), tr("Import of CSV Report Failed: Not valid product key of package:") + packageName + ": " + productKey);
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
                        QMessageBox::critical(nullptr, tr("Import Json Report Error"), tr("Import of CSV Report Failed: Not valid issues of package: ") + packageName);
                        return false;
                    }
                    for (auto&& issue : issues.toArray())
                    {
                        if (!issue.isObject())
                        {
                            QMessageBox::critical(nullptr, tr("Import Json Report Error"), tr("Import of CSV Report Failed: Not valid issue of package:") + packageName);
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
                                issueKey == "scorev4" ||
                                issueKey == "vector" ||
                                issueKey == "vectorString" ||
                                issueKey == "status" ||
                                issueKey == "link" ||
                                issueKey == "detail" ||
                                issueKey == "description" ||
                                issueKey == "modified" ||
                                issueKey == "patch-file")
                            {
                                if (issueKey == "vectorString")
                                    continue;
                                else if (issueKey == "patch-file" && issueValue.isArray() && !issueValue.toArray().isEmpty())
                                {
                                    continue;
                                }
                                else if (!issueValue.isNull() && issueValue.isString())
                                {
                                    continue;
                                }
                                else
                                {
                                    QMessageBox::critical(nullptr, tr("Import Json Report Error"), tr("Import of CSV Report Failed: Not valid issue value of package:") + packageName + ": " + issueKey);
                                    return false;
                                }
                            }
                            else
                            {
                                QMessageBox::critical(nullptr, tr("Import Json Report Error"), tr("Import of CSV Report Failed: Not valid issueKey of package:") + packageName + ": " + issueKey);
                                return false;
                            }
                        }
                    }
                }
                else
                {
                    QMessageBox::critical(nullptr, tr("Import Json Report Error"), tr("Import of CSV Report Failed: Not valid packageKey of package:") + packageName + ": " + packageKey);
                    return false;
                }
            }
        }
    }
    else
    {
        QMessageBox::critical(nullptr, tr("Import Json Report Error"), tr("Import of CSV Report Failed: Not valid json document"));
        return false;
    }
    return true;
}
