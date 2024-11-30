#ifndef DIALOGIMPORTCVEREPORT_H
#define DIALOGIMPORTCVEREPORT_H

#include <QDialog>

namespace Ui {
class DialogImportCVEReport;
}

class DialogImportCVEReport : public QDialog
{
    Q_OBJECT

public:
    explicit DialogImportCVEReport(QWidget *parent = nullptr);
    ~DialogImportCVEReport();
    QString getJsonReportFileName() { return jsonReportFileName; };
    QString getCVEDbFileName() { return CVEDBFileName; };

protected slots:
    void accept() override;

private slots:
    void on_pushButtonOpenJsonFileName_clicked();
    void on_pushButtonOpenCVEDbFileName_clicked();

private:
    Ui::DialogImportCVEReport *ui;
    QString jsonReportFileName;
    QString CVEDBFileName;
};

#endif // DIALOGIMPORTCVEREPORT_H
