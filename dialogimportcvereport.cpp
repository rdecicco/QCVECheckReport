/*!
   QCVECheckReport project

   @file: dialogimportcvereport.cpp

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

#include "dialogimportcvereport.h"
#include "ui_dialogimportcvereport.h"

#include <QFileDialog>
#include <QMessageBox>

DialogImportCVEReport::DialogImportCVEReport(QWidget *parent)
    : QDialog(parent)
    , ui(new Ui::DialogImportCVEReport)
{
    ui->setupUi(this);
}

DialogImportCVEReport::~DialogImportCVEReport()
{
    delete ui;
}

void DialogImportCVEReport::on_pushButtonOpenJsonFileName_clicked()
{
    ui->lineEditJsonFileName->setText(QFileDialog::getOpenFileName(this, tr("Open JSon Report File"), QDir::currentPath(), "JSon (*.json)"));
}

void DialogImportCVEReport::on_pushButtonOpenCVEDbFileName_clicked()
{
    ui->lineEditCVEDBFileName->setText(QFileDialog::getOpenFileName(this, tr("Open CVE DB File"), QDir::currentPath(), "Sqlite (*.db)"));
}

void DialogImportCVEReport::accept()
{
    CVEDBFileName = ui->lineEditCVEDBFileName->text();
    jsonReportFileName = ui->lineEditJsonFileName->text();
    if (!QFile::exists(CVEDBFileName) || !QFile::exists(jsonReportFileName))
    {
        QMessageBox::critical(this, tr("File error"), tr("Please select a valid file"));
    }

    done(DialogCode::Accepted);
    close();
}