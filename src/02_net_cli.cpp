#include <QApplication>
#include <QMainWindow>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTextEdit>
#include <QListWidget>
#include <QFile>
#include <QDir>
#include <QMessageBox>
#include <QProcess>
#include <QTimer>
#include <QFileSystemWatcher>
#include <QScrollBar>
#include <QTextStream>
#include <QRegExp>
#include <QInputDialog>
#include <QDialog>
#include <QDialogButtonBox>
#include <QCloseEvent>
#include <unistd.h>  

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr) : QMainWindow(parent) {
        // 检查是否以root权限运行
        if (geteuid() != 0) {
            QMessageBox::critical(nullptr, "错误", "请使用管理员权限运行此程序！\n"
                                           "可以使用: sudo ./程序名 或 pkexec ./程序名");
            QTimer::singleShot(0, qApp, &QApplication::quit);
            return;
        }

        setupUI();
        setupConnections();
        setupLogWatcher();
        loadConfig();
    }

    ~MainWindow() {
        // 清理资源
        if (logWatcher) {
            delete logWatcher;
        }
    }

protected:
    void closeEvent(QCloseEvent *event) override {
        // 检查模块是否加载
        if (isModuleLoaded()) {
            QMessageBox::StandardButton reply;
            reply = QMessageBox::question(this, "确认退出", 
                "内核模块仍在运行，是否卸载模块并退出？",
                QMessageBox::Yes | QMessageBox::No);
            
            if (reply == QMessageBox::Yes) {
                unloadKernelModule(false);  // 尝试卸载但不强制
            }
        }
        event->accept();
    }

private slots:
    void addEntry() {
        QString input = ipPortEdit->text().trimmed();
        
        if (!isValidInput(input)) {
            QMessageBox::warning(this, "输入错误", "请输入有效的 IP(:端口) 格式\n例如: 1.1.1.1:123 或 1.2.3.4");
            return;
        }
        
        if (entryList->findItems(input, Qt::MatchExactly).isEmpty()) {
            entryList->addItem(input);
            ipPortEdit->clear();
            saveConfig();
        } else {
            QMessageBox::information(this, "提示", "该条目已存在");
        }
    }
    
    void removeEntry() {
        QList<QListWidgetItem*> selected = entryList->selectedItems();
        if (selected.isEmpty()) {
            QMessageBox::warning(this, "警告", "请先选择要删除的条目");
            return;
        }
        
        for (QListWidgetItem *item : selected) {
            delete entryList->takeItem(entryList->row(item));
        }
        saveConfig();
    }
    
    void saveConfig() {
        // 确保配置目录存在
        QDir configDir("/hx/config");
        if (!configDir.exists()) {
            if (!configDir.mkpath(".")) {
                QMessageBox::critical(this, "错误", "无法创建配置目录");
                return;
            }
        }
        
        // 写入配置文件
        QFile configFile(configDir.filePath("hx_net.config"));
        if (configFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream out(&configFile);
            for (int i = 0; i < entryList->count(); ++i) {
                out << entryList->item(i)->text() << "\n";
            }
            configFile.close();
            logOutput->append("配置已保存");
        } else {
            QMessageBox::critical(this, "错误", QString("无法写入配置文件: %1").arg(configFile.errorString()));
        }
    }
    
    void loadKernelModule() {
        // 获取当前用户的主目录路径
        QString configPath = "/hx/config/hx_net.config";
        
        QProcess process;
        process.start("insmod", QStringList() << "hx_net.ko" << QString("config_path=%1").arg(configPath));
        process.waitForFinished();
        
        if (process.exitCode() != 0) {
            logOutput->append("加载内核模块失败: " + process.readAllStandardError());
        } else {
            logOutput->append("内核模块 hx_net.ko 已加载");
            moduleLoaded = true;
        }
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
            logOutput->append("卸载内核模块失败: " + process.readAllStandardError());
        } else {
            logOutput->append("内核模块 hx_net.ko 已卸载");
            moduleLoaded = false;
        }
    }
    
    void checkLogChanges() {
        // 尝试读取应用日志
        QString logPath = "/hx/log/hx_net.log";
        QFile appLogFile(logPath);
        if (appLogFile.exists()) {
            if (appLogFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
                QTextStream in(&appLogFile);
                QString newContent = in.readAll();
                appLogFile.close();
                
                if (newContent != lastLogContent) {
                    logOutput->append(newContent.mid(lastLogContent.length()));
                    lastLogContent = newContent;
                    
                    // 自动滚动到底部
                    QScrollBar *sb = logOutput->verticalScrollBar();
                    sb->setValue(sb->maximum());
                }
            }
            return;
        }
        
        // 如果应用日志不存在，尝试读取内核日志
        QProcess dmesg;
        dmesg.start("dmesg");
        if (dmesg.waitForFinished()) {
            QString newContent = dmesg.readAllStandardOutput();
            if (newContent != lastLogContent) {
                logOutput->append(newContent.mid(lastLogContent.length()));
                lastLogContent = newContent;
                
                // 自动滚动到底部
                QScrollBar *sb = logOutput->verticalScrollBar();
                sb->setValue(sb->maximum());
            }
        }
    }

private:
    QLineEdit *ipPortEdit;
    QListWidget *entryList;
    QPushButton *addButton;
    QPushButton *removeButton;
    QPushButton *loadModuleButton;
    QPushButton *unloadModuleButton;
    QTextEdit *logOutput;
    QString lastLogContent;
    QFileSystemWatcher *logWatcher;
    bool moduleLoaded = false;

    void setupUI() {
        QWidget *centralWidget = new QWidget(this);
        QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);
        
        // 输入区域
        QHBoxLayout *inputLayout = new QHBoxLayout();
        inputLayout->addWidget(new QLabel("IP(:端口):"));
        
        ipPortEdit = new QLineEdit();
        inputLayout->addWidget(ipPortEdit);
        
        addButton = new QPushButton("添加");
        inputLayout->addWidget(addButton);
        
        removeButton = new QPushButton("删除");
        inputLayout->addWidget(removeButton);
        
        mainLayout->addLayout(inputLayout);
        
        // 条目列表
        entryList = new QListWidget();
        entryList->setSelectionMode(QAbstractItemView::ExtendedSelection);
        mainLayout->addWidget(entryList);
        
        // 模块控制按钮
        QHBoxLayout *moduleLayout = new QHBoxLayout();
        loadModuleButton = new QPushButton("加载内核模块");
        unloadModuleButton = new QPushButton("卸载内核模块");
        moduleLayout->addWidget(loadModuleButton);
        moduleLayout->addWidget(unloadModuleButton);
        mainLayout->addLayout(moduleLayout);
        
        // 日志输出区域
        logOutput = new QTextEdit();
        logOutput->setReadOnly(true);
        logOutput->setWordWrapMode(QTextOption::NoWrap);
        mainLayout->addWidget(new QLabel("日志输出:"));
        mainLayout->addWidget(logOutput);
        
        setCentralWidget(centralWidget);
        setWindowTitle("HX Net 配置工具 (管理员模式)");
        resize(800, 600);
    }
    
    void setupConnections() {
        connect(addButton, &QPushButton::clicked, this, &MainWindow::addEntry);
        connect(removeButton, &QPushButton::clicked, this, &MainWindow::removeEntry);
        connect(loadModuleButton, &QPushButton::clicked, this, &MainWindow::loadKernelModule);
        connect(unloadModuleButton, &QPushButton::clicked, this, &MainWindow::unloadKernelModule);
    }
    
    void setupLogWatcher() {
        // 创建日志目录（如果不存在）
        QDir logDir("/hx/log");
        if (!logDir.exists()) {
            if (!logDir.mkpath(".")) {
                QMessageBox::critical(this, "错误", "无法创建日志目录");
                return;
            }
        }
        
        // 设置日志文件监视器
        logWatcher = new QFileSystemWatcher(this);
        QString logPath = logDir.filePath("hx_net.log");
        
        // 如果日志文件不存在，创建一个空文件
        if (!QFile::exists(logPath)) {
            QFile file(logPath);
            if (!file.open(QIODevice::WriteOnly)) {
                QMessageBox::warning(this, "警告", "无法创建日志文件");
                return;
            }
            file.close();
        }
        
        logWatcher->addPath(logPath);
        connect(logWatcher, &QFileSystemWatcher::fileChanged, this, &MainWindow::checkLogChanges);
        
        // 设置定时器定期检查日志更新
        QTimer *logTimer = new QTimer(this);
        connect(logTimer, &QTimer::timeout, this, &MainWindow::checkLogChanges);
        logTimer->start(1000); // 每秒检查一次
        
        // 初始读取日志
        checkLogChanges();
    }
    
    void loadConfig() {
        QFile configFile("/hx/config/hx_net.config");
        if (configFile.exists() && configFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
            QTextStream in(&configFile);
            while (!in.atEnd()) {
                QString line = in.readLine().trimmed();
                if (!line.isEmpty() && isValidInput(line)) {
                    entryList->addItem(line);
                }
            }
            configFile.close();
            logOutput->append("已加载配置");
        }
    }
    
    bool isValidInput(const QString &input) {
        // 简单的IP(:端口)格式验证
        QRegExp ipPortRegex("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}(:\\d+)?$");
        return ipPortRegex.exactMatch(input);
    }
    
    bool isModuleLoaded() {
        QProcess process;
        process.start("lsmod");
        process.waitForFinished();
        QString output = process.readAllStandardOutput();
        return output.contains("hx_net");
    }
};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    
    MainWindow mainWindow;
    mainWindow.show();
    
    return app.exec();
}

#include "02_net_cli.moc"