#include "mdisubwindowarea.h"
#include "ui_mdisubwindowarea.h"

MdiSubWindowArea::MdiSubWindowArea(QWidget *parent)
    : QMdiArea(parent)
    , ui(new Ui::MdiSubWindowArea)
{
    ui->setupUi(this);
}

MdiSubWindowArea::~MdiSubWindowArea()
{
    delete ui;
}
