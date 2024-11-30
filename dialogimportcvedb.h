#ifndef DIALOGIMPORTCVEDB_H
#define DIALOGIMPORTCVEDB_H

#include <QDialog>

namespace Ui {
class DialogImportCVEDB;
}

class DialogImportCVEDB : public QDialog
{
    Q_OBJECT

public:
    explicit DialogImportCVEDB(QWidget *parent = nullptr);
    ~DialogImportCVEDB();
    QString getCVEDbFileName() { return CVEDBFileName; };

protected slots:
    void accept() override;

private slots:
    void on_pushButtonOpenCVEDbFileName_clicked();

private:
    Ui::DialogImportCVEDB *ui;
    QString CVEDBFileName;
};

#endif // DIALOGIMPORTCVEDB_H
