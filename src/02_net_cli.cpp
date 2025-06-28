#include <QApplication>
#include <QDir>
#include <QFile>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMainWindow>
#include <QMessageBox>
#include <QProcess>
#include <QPushButton>
#include <QRegExp>
#include <QScrollBar>
#include <QTextEdit>
#include <QTextStream>
#include <QTimer>
#include <QVBoxLayout>
#include <QCloseEvent>
#include <unistd.h>

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr) : QMainWindow(parent) {
        if (geteuid() != 0) {
            QMessageBox::critical(
                nullptr, "错误",
                "请使用管理员权限运行此程序！\n建议使用: sudo ./hx_net_gui");
            QTimer::singleShot(0, qApp, &QApplication::quit);
            return;
        }
        setupUI();
        loadConfig();
        setupLogWatcher();
    }

protected:
    void closeEvent(QCloseEvent *event) override {
        if (isModuleLoaded()) {
            QMessageBox::StandardButton reply;
            reply = QMessageBox::question(this, "确认退出", 
                "内核模块仍在运行，是否卸载模块并退出？",
                QMessageBox::Yes | QMessageBox::No);
            
            if (reply == QMessageBox::Yes) {
                unloadKernelModule(false);
            }
        }
        event->accept();
    }

private:
    QLineEdit *ipEdit;
    QLineEdit *timeEdit;
    QListWidget *ipList;
    QListWidget *timeList;
    QTextEdit *logView;
    QString lastLog;

    bool isModuleLoaded() {
        QProcess process;
        process.start("lsmod");
        process.waitForFinished();
        QString output = process.readAllStandardOutput();
        return output.contains("hx_net");
    }

    // 时间格式校验和解析
    static bool parseTime(QString const &timeStr, int &minutes) {
        QRegExp rx("^(\\d{2}):(\\d{2})$");
        if (!rx.exactMatch(timeStr)) {
            return false;
        }
        int h = rx.cap(1).toInt();
        int m = rx.cap(2).toInt();
        if (h < 0 || h > 24 || m < 0 || m > 59) {
            return false;
        }
        if (h == 24 && m != 0) {
            return false;
        }
        minutes = (h == 24) ? 0 : h * 60 + m; // 关键：24:00转换成0分钟
        return true;
    }

    static bool compareTimeRange(QString const &a, QString const &b) {
        // 格式: HH:MM~HH:MM
        QStringList partsA = a.split('~');
        QStringList partsB = b.split('~');
        int startA = 0, startB = 0;
        parseTime(partsA[0], startA);
        parseTime(partsB[0], startB);
        return startA < startB;
    }

    // 检查时间段格式和合理性
    bool validateAndMaybeSplit(QString const &input, QStringList &outSegments) {
        QStringList segments = input.split(',', QString::SkipEmptyParts);
        for (auto seg: segments) {
            seg = seg.trimmed();
            QRegExp rx("^(\\d{2}:\\d{2})~(\\d{2}:\\d{2})$");
            if (!rx.exactMatch(seg)) {
                QMessageBox::warning(this, "格式错误",
                                     "时间段格式必须是 HH:MM~HH:MM");
                return false;
            }
            int startMin = 0, endMin = 0;
            if (!parseTime(rx.cap(1), startMin) ||
                !parseTime(rx.cap(2), endMin)) {
                QMessageBox::warning(this, "格式错误", "时间段内时间格式错误");
                return false;
            }
            if (startMin == endMin) {
                QMessageBox::warning(this, "时间错误",
                                     "开始时间不能等于结束时间");
                return false;
            }
            if (startMin > endMin) {
                // 跨天提示拆分
                int ret = QMessageBox::question(
                    this, "跨天时间段",
                    QString("时间段 %1 跨天，是否拆分为两段？\n（%2~24:00 和 "
                            "00:00~%3）")
                        .arg(seg)
                        .arg(rx.cap(1))
                        .arg(rx.cap(2)),
                    QMessageBox::Yes | QMessageBox::No);
                if (ret == QMessageBox::Yes) {
                    // 起始时间如果是24:00，不拆分第一段（24:00~24:00没意义）
                    if (rx.cap(1) == "24:00") {
                        outSegments.append(QString("00:00~%1").arg(rx.cap(2)));
                    } else {
                        outSegments.append(QString("%1~24:00").arg(rx.cap(1)));
                        outSegments.append(QString("00:00~%1").arg(rx.cap(2)));
                    }
                } else {
                    return false;
                }
            } else {
                seg.replace("24:00", "00:00");
                outSegments.append(seg);
            }
        }
        return true;
    }

    void setupUI() {
        QWidget *central = new QWidget(this);
        QVBoxLayout *layout = new QVBoxLayout(central);

        // 上班时间输入区域放顶部
        layout->addWidget(
            new QLabel("上班时间段 (格式: HH:MM~HH:MM, 多段用英文逗号分隔)："));
        QHBoxLayout *timeLayout = new QHBoxLayout();
        timeEdit = new QLineEdit();
        QPushButton *timeAdd = new QPushButton("添加");
        QPushButton *timeDel = new QPushButton("删除");
        timeLayout->addWidget(timeEdit);
        timeLayout->addWidget(timeAdd);
        timeLayout->addWidget(timeDel);
        timeList = new QListWidget();
        timeList->setSelectionMode(QAbstractItemView::ExtendedSelection);
        layout->addLayout(timeLayout);
        layout->addWidget(timeList);

        // 黑名单输入区域放下面
        layout->addWidget(new QLabel("黑名单 IP(:端口)："));
        QHBoxLayout *ipLayout = new QHBoxLayout();
        ipEdit = new QLineEdit();
        QPushButton *ipAdd = new QPushButton("添加");
        QPushButton *ipDel = new QPushButton("删除");
        ipLayout->addWidget(ipEdit);
        ipLayout->addWidget(ipAdd);
        ipLayout->addWidget(ipDel);
        ipList = new QListWidget();
        ipList->setSelectionMode(QAbstractItemView::ExtendedSelection);
        layout->addLayout(ipLayout);
        layout->addWidget(ipList);

        // 模块控制
        QHBoxLayout *btnLayout = new QHBoxLayout();
        QPushButton *saveBtn = new QPushButton("保存配置");
        QPushButton *loadBtn = new QPushButton("加载模块");
        QPushButton *unloadBtn = new QPushButton("卸载模块");
        btnLayout->addWidget(saveBtn);
        btnLayout->addWidget(loadBtn);
        btnLayout->addWidget(unloadBtn);
        layout->addLayout(btnLayout);

        // 日志输出
        logView = new QTextEdit();
        logView->setReadOnly(true);
        layout->addWidget(new QLabel("日志输出："));
        layout->addWidget(logView);

        setCentralWidget(central);
        setWindowTitle("HX Net 管理工具");
        resize(800, 600);

        // 信号槽
        connect(timeAdd, &QPushButton::clicked, this, [=]() {
            QString input = timeEdit->text().trimmed();
            if (input.isEmpty()) {
                return;
            }
            QStringList segments;
            if (!validateAndMaybeSplit(input, segments)) {
                return;
            }

            // 插入所有拆分后的段，且不重复
            bool changed = false;
            for (auto seg: segments) {
                if (timeList->findItems(seg, Qt::MatchExactly).isEmpty()) {
                    timeList->addItem(seg);
                    changed = true;
                }
            }
            if (changed) {
                sortTimeList();
            }
            timeEdit->clear();
        });
        connect(timeDel, &QPushButton::clicked, this, [=]() {
            for (auto item: timeList->selectedItems()) {
                delete timeList->takeItem(timeList->row(item));
            }
        });

        connect(ipAdd, &QPushButton::clicked, this, [=]() {
            QString ip = ipEdit->text().trimmed();
            QRegExp reg("^\\d{1,3}(\\.\\d{1,3}){3}(:\\d+)?$");
            if (!reg.exactMatch(ip)) {
                QMessageBox::warning(this, "输入错误",
                                     "请输入合法 IP(:端口) 格式");
                return;
            }
            if (ipList->findItems(ip, Qt::MatchExactly).isEmpty()) {
                ipList->addItem(ip);
                ipEdit->clear();
            }
        });
        connect(ipDel, &QPushButton::clicked, this, [=]() {
            for (auto item: ipList->selectedItems()) {
                delete ipList->takeItem(ipList->row(item));
            }
        });

        connect(saveBtn, &QPushButton::clicked, this, &MainWindow::saveConfig);
        connect(loadBtn, &QPushButton::clicked, this, [=]() {
            QProcess::execute(
                "insmod hx_net.ko");
            logView->append("[操作] 模块加载命令已执行");
        });
        connect(unloadBtn, &QPushButton::clicked, this, &MainWindow::unloadKernelModule);
    }

    void unloadKernelModule(bool manual = true) {
        if (!isModuleLoaded()) {
            if (manual) {
                QMessageBox::information(this, "提示", "模块未加载");
            }
            return;
        }
        
        QProcess process;
        process.start("rmmod", QStringList() << "hx_net.ko");
        process.waitForFinished();
        
        if (process.exitCode() != 0) {
            logView->append("卸载内核模块失败: " + process.readAllStandardError());
        } else {
            logView->append("内核模块 hx_net.ko 已卸载");
        }
    }

    void sortTimeList() {
        // 简单按起始时间排序
        QList<QString> items;
        for (int i = 0; i < timeList->count(); ++i) {
            items.append(timeList->item(i)->text());
        }
        std::sort(items.begin(), items.end(), compareTimeRange);
        timeList->clear();
        for (auto const &it: items) {
            timeList->addItem(it);
        }
    }

    void saveConfig() {
        QDir().mkpath("/hx/config");
        QFile f1("/hx/config/hx_net_url.config");
        if (f1.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream out(&f1);
            for (int i = 0; i < ipList->count(); ++i) {
                out << ipList->item(i)->text() << "\n";
            }
        }
        QFile f2("/hx/config/hx_net_time.config");
        if (f2.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream out(&f2);
            for (int i = 0; i < timeList->count(); ++i) {
                out << timeList->item(i)->text() << "\n";
            }
        }
        logView->append("[操作] 配置文件已保存");
    }

    void loadConfig() {
        QFile f1("/hx/config/hx_net_url.config");
        if (f1.open(QIODevice::ReadOnly | QIODevice::Text)) {
            while (!f1.atEnd()) {
                QString line = f1.readLine().trimmed();
                if (!line.isEmpty()) {
                    ipList->addItem(line);
                }
            }
        }
        QFile f2("/hx/config/hx_net_time.config");
        if (f2.open(QIODevice::ReadOnly | QIODevice::Text)) {
            while (!f2.atEnd()) {
                QString line = f2.readLine().trimmed();
                if (!line.isEmpty()) {
                    timeList->addItem(line);
                }
            }
            sortTimeList();
        }
    }

    void setupLogWatcher() {
        QTimer *t = new QTimer(this);
        connect(t, &QTimer::timeout, this, &MainWindow::checkLog);
        t->start(1000);
    }

    void checkLog() {
        QFile logFile("/hx/log/hx_net.log");
        if (logFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
            QString content = QTextStream(&logFile).readAll();
            if (content != lastLog) {
                logView->append(content.mid(lastLog.length()));
                lastLog = content;
                logView->verticalScrollBar()->setValue(
                    logView->verticalScrollBar()->maximum());
            }
        }
    }
};

#include "02_net_cli.moc"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    MainWindow w;
    w.show();
    return app.exec();
}
