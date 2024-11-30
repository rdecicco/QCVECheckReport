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
