/*!
 * QCVECheckReport
 *
 * @file: main.cpp
 *
 * @author: Raffaele de Cicco <decicco.raffaele@gmail.com>
 *
 * @abstract:
 * This tool is able to create a report to analyze CVE of a yocto build image using CVECheck json report and
 * NVD CVE DB of NIST created by the same tool retriving information by https://www.nist.gov/
 */

#include "qcvecheckapp.h"

#include <QApplication>
#include <QLocale>
#include <QTranslator>

#include <initializer_list>
#include <signal.h>
#include <unistd.h>

void ignoreUnixSignals(std::initializer_list<int> ignoreSignals) {
    // all these signals will be ignored.
    for (int sig : ignoreSignals)
        signal(sig, SIG_IGN);
}

void catchUnixSignals(std::initializer_list<int> quitSignals) {
    auto handler = [](int sig) -> void {
        // blocking and not aysnc-signal-safe func are valid
        printf("\nquit the application by signal(%d).\n", sig);
        QApplication::quit();
    };

    sigset_t blocking_mask;
    sigemptyset(&blocking_mask);
    for (auto sig : quitSignals)
        sigaddset(&blocking_mask, sig);

    struct sigaction sa;
    sa.sa_handler = handler;
    sa.sa_mask    = blocking_mask;
    sa.sa_flags   = 0;

    for (auto sig : quitSignals)
        sigaction(sig, &sa, nullptr);
}

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    QApplication::setWindowIcon(QIcon(QPixmap("://CVE.png")));
    catchUnixSignals({SIGQUIT, SIGINT, SIGTERM, SIGHUP});

    QTranslator translator;
    const QStringList uiLanguages = QLocale::system().uiLanguages();
    for (const QString &locale : uiLanguages) {
        const QString baseName = "QCVECheckReport_" + QLocale(locale).name();
        if (translator.load(":/i18n/" + baseName)) {
            a.installTranslator(&translator);
            break;
        }
    }

    QCVECheckApp w;
    w.show();
    return a.exec();
}
