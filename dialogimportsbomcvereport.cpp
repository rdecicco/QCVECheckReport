/*!
   QCVECheckReport project

   @file: dialogimportsboncvereport.cpp

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

#include "dialogimportsbomcvereport.h"
#include "ui_dialogimportsbomcvereport.h"

#include <QFileDialog>
#include <QMessageBox>

DialogImportSBOMCVEReport::DialogImportSBOMCVEReport(QWidget *parent)
    : QDialog(parent)
    , ui(new Ui::DialogImportSBOMCVEReport)
{
    ui->setupUi(this);
}

DialogImportSBOMCVEReport::~DialogImportSBOMCVEReport()
{
    delete ui;
}

void DialogImportSBOMCVEReport::on_pushButtonOpenJsonReportFileName_clicked()
{
    ui->lineEditJsonReportFileName->setText(QFileDialog::getOpenFileName(this, tr("Open Json Report File"), QDir::currentPath(), "Json (*.json)"));
}

void DialogImportSBOMCVEReport::on_pushButtonOpenNVDJsonRepoPath_clicked()
{
    ui->lineEditNVDJsonRepositoryPath->setText(QFileDialog::getExistingDirectory(this, tr("Open NVD Json Repository Folder"), QDir::currentPath()));
}

void DialogImportSBOMCVEReport::on_pushButtonOpenCVEJsonRepoPath_clicked()
{
    ui->lineEditCVEJsonRepositoryPath->setText(QFileDialog::getExistingDirectory(this, tr("Open CVE Json Repository Folder"), QDir::currentPath()));
}

void DialogImportSBOMCVEReport::accept()
{
    jsonReportFileName = ui->lineEditJsonReportFileName->text();
    NVDJsonRepoPath = ui->lineEditNVDJsonRepositoryPath->text();
    CVEJsonRepoPath = ui->lineEditCVEJsonRepositoryPath->text();
    if (jsonReportFileName.isEmpty() || !QFile::exists(jsonReportFileName) || (NVDJsonRepoPath.isEmpty() && CVEJsonRepoPath.isEmpty()) )
    {
        QMessageBox::critical(this, tr("File error"), tr("Please select a valid file or path"));
        return;
    }

    done(DialogCode::Accepted);
    close();
}