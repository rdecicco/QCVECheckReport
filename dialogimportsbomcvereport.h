/*!
   QCVECheckReport project

   @file: dialogimportsbomcvereport.h

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

#ifndef DIALOGIMPORTSBOMCVEREPORT_H
#define DIALOGIMPORTSBOMCVEREPORT_H

#include <QDialog>

namespace Ui {
class DialogImportSBOMCVEReport;
}

class DialogImportSBOMCVEReport : public QDialog
{
    Q_OBJECT

public:
    explicit DialogImportSBOMCVEReport(QWidget *parent = nullptr);
    ~DialogImportSBOMCVEReport();
    QString getJsonReportFileName() { return jsonReportFileName; };
    QString getNVDJsonRepoPath() { return NVDJsonRepoPath; };
    QString getCVEJsonRepoPath() { return CVEJsonRepoPath; };

protected slots:
    void accept() override;

private slots:
    void on_pushButtonOpenJsonReportFileName_clicked();
    void on_pushButtonOpenNVDJsonRepoPath_clicked();
    void on_pushButtonOpenCVEJsonRepoPath_clicked();

private:
    Ui::DialogImportSBOMCVEReport *ui;
    QString jsonReportFileName;
    QString NVDJsonRepoPath;
    QString CVEJsonRepoPath;
};

#endif // DIALOGIMPORTSBOMCVEREPORT_H
