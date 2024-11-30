#include "dialogimportcvedb.h"
#include "ui_dialogimportcvedb.h"

#include <QFileDialog>
#include <QMessageBox>

DialogImportCVEDB::DialogImportCVEDB(QWidget *parent)
    : QDialog(parent)
    , ui(new Ui::DialogImportCVEDB)
{
    ui->setupUi(this);
}

DialogImportCVEDB::~DialogImportCVEDB()
{
    delete ui;
}

void DialogImportCVEDB::on_pushButtonOpenCVEDbFileName_clicked()
{
    ui->lineEditCVEDBFileName->setText(QFileDialog::getOpenFileName(this, tr("Open CVE DB File"), QDir::currentPath(), "Sqlite (*.db)"));
}

void DialogImportCVEDB::accept()
{
    CVEDBFileName = ui->lineEditCVEDBFileName->text();
    if (!QFile::exists(CVEDBFileName))
    {
        QMessageBox::critical(this, tr("File error"), tr("Please select a valid file"));
    }

    done(DialogCode::Accepted);
    close();
}
