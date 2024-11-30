#ifndef MDISUBWINDOWAREA_H
#define MDISUBWINDOWAREA_H

#include <QMdiArea>

namespace Ui {
class MdiSubWindowArea;
}

class MdiSubWindowArea : public QMdiArea
{
    Q_OBJECT

public:
    explicit MdiSubWindowArea(QWidget *parent = nullptr);
    ~MdiSubWindowArea();

private:
    Ui::MdiSubWindowArea *ui;
};

#endif // MDISUBWINDOWAREA_H
