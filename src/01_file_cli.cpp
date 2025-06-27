#include <QApplication>
#include <QMainWindow>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
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
#include <QFileDialog>
#include <QGroupBox>
#include <QEvent>
#include <QCloseEvent>
#include <unistd.h>

class FileSelectorWindow : public QMainWindow {
    Q_OBJECT

public:
    FileSelectorWindow(QWidget *parent = nullptr) : QMainWindow(parent) {
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

    ~FileSelectorWindow() {
        if (logWatcher) {
            delete logWatcher;
        }
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

private slots:
    void addFileEntry() {
        QStringList files = QFileDialog::getOpenFileNames(this, "选择白名单文件", "/");
        
        if (files.isEmpty()) {
            return;
        }
        
        bool added = false;
        for (const QString &file : files) {
            if (!fileList->findItems(file, Qt::MatchExactly).isEmpty()) {
                continue; // 跳过已存在的文件
            }
            
            fileList->addItem(file);
            added = true;
        }
        
        if (added) {
            saveConfig();
        } else {
            QMessageBox::information(this, "提示", "所有选择的文件已在列表中");
        }
    }
    
    void removeFileEntry() {
        QList<QListWidgetItem*> selected = fileList->selectedItems();
        if (selected.isEmpty()) {
            QMessageBox::warning(this, "警告", "请先选择要删除的文件");
            return;
        }
        
        for (QListWidgetItem *item : selected) {
            delete fileList->takeItem(fileList->row(item));
        }
        saveConfig();
    }
    
    void addProcessEntry() {
        QStringList files = QFileDialog::getOpenFileNames(this, "选择可执行程序", "/usr/bin");
        
        if (files.isEmpty()) {
            return;
        }
        
        bool added = false;
        for (const QString &file : files) {
            if (!processList->findItems(file, Qt::MatchExactly).isEmpty()) {
                continue; // 跳过已存在的程序
            }
            
            processList->addItem(file);
            added = true;
        }
        
        if (added) {
            saveConfig();
        } else {
            QMessageBox::information(this, "提示", "所有选择的程序已在列表中");
        }
    }
    
    void removeProcessEntry() {
        QList<QListWidgetItem*> selected = processList->selectedItems();
        if (selected.isEmpty()) {
            QMessageBox::warning(this, "警告", "请先选择要删除的程序");
            return;
        }
        
        for (QListWidgetItem *item : selected) {
            delete processList->takeItem(processList->row(item));
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
        
        // 保存白名单文件配置
        QFile fileConfig(configDir.filePath("hx_file_f.config"));
        if (fileConfig.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream out(&fileConfig);
            for (int i = 0; i < fileList->count(); ++i) {
                out << fileList->item(i)->text() << "\n";
            }
            fileConfig.close();
            logOutput->append("白名单配置已保存");
        } else {
            QMessageBox::critical(this, "错误", QString("无法写入白名单配置文件: %1").arg(fileConfig.errorString()));
        }
        
        // 保存可执行程序配置
        QFile processConfig(configDir.filePath("hx_file_p.config"));
        if (processConfig.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream out(&processConfig);
            for (int i = 0; i < processList->count(); ++i) {
                out << processList->item(i)->text() << "\n";
            }
            processConfig.close();
            logOutput->append("可执行程序配置已保存");
        } else {
            QMessageBox::critical(this, "错误", QString("无法写入程序配置文件: %1").arg(processConfig.errorString()));
        }
    }
    
    void loadKernelModule() {
        QProcess process;
        process.start("insmod", QStringList() << "hx_file.ko");
        process.waitForFinished();
        
        if (process.exitCode() != 0) {
            logOutput->append("加载内核模块失败: " + process.readAllStandardError());
        } else {
            logOutput->append("内核模块 hx_file.ko 已加载");
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
        process.start("rmmod", QStringList() << "hx_file.ko");
        process.waitForFinished();
        
        if (process.exitCode() != 0) {
            logOutput->append("卸载内核模块失败: " + process.readAllStandardError());
        } else {
            logOutput->append("内核模块 hx_file.ko 已卸载");
            moduleLoaded = false;
        }
    }
    
    void checkLogChanges() {
        QString logPath = "/hx/log/hx_file.log";
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
    QListWidget *fileList;
    QListWidget *processList;
    QPushButton *addFileButton;
    QPushButton *removeFileButton;
    QPushButton *addProcessButton;
    QPushButton *removeProcessButton;
    QPushButton *loadModuleButton;
    QPushButton *unloadModuleButton;
    QTextEdit *logOutput;
    QString lastLogContent;
    QFileSystemWatcher *logWatcher;
    bool moduleLoaded = false;

    void setupUI() {
        QWidget *centralWidget = new QWidget(this);
        QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);
        
        // 文件选择区域
        QGroupBox *fileGroup = new QGroupBox("白名单文件配置");
        QVBoxLayout *fileLayout = new QVBoxLayout(fileGroup);
        
        fileList = new QListWidget();
        fileList->setSelectionMode(QAbstractItemView::ExtendedSelection);
        fileLayout->addWidget(fileList);
        
        QHBoxLayout *fileButtonLayout = new QHBoxLayout();
        addFileButton = new QPushButton("添加文件");
        removeFileButton = new QPushButton("删除选中");
        fileButtonLayout->addWidget(addFileButton);
        fileButtonLayout->addWidget(removeFileButton);
        fileLayout->addLayout(fileButtonLayout);
        
        mainLayout->addWidget(fileGroup);
        
        // 可执行程序选择区域
        QGroupBox *processGroup = new QGroupBox("可执行程序配置");
        QVBoxLayout *processLayout = new QVBoxLayout(processGroup);
        
        processList = new QListWidget();
        processList->setSelectionMode(QAbstractItemView::ExtendedSelection);
        processLayout->addWidget(processList);
        
        QHBoxLayout *processButtonLayout = new QHBoxLayout();
        addProcessButton = new QPushButton("添加程序");
        removeProcessButton = new QPushButton("删除选中");
        processButtonLayout->addWidget(addProcessButton);
        processButtonLayout->addWidget(removeProcessButton);
        processLayout->addLayout(processButtonLayout);
        
        mainLayout->addWidget(processGroup);
        
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
        setWindowTitle("HX 文件保护配置工具 (管理员模式)");
        resize(800, 600);
    }
    
    void setupConnections() {
        connect(addFileButton, &QPushButton::clicked, this, &FileSelectorWindow::addFileEntry);
        connect(removeFileButton, &QPushButton::clicked, this, &FileSelectorWindow::removeFileEntry);
        connect(addProcessButton, &QPushButton::clicked, this, &FileSelectorWindow::addProcessEntry);
        connect(removeProcessButton, &QPushButton::clicked, this, &FileSelectorWindow::removeProcessEntry);
        connect(loadModuleButton, &QPushButton::clicked, this, &FileSelectorWindow::loadKernelModule);
        connect(unloadModuleButton, &QPushButton::clicked, this, &FileSelectorWindow::unloadKernelModule);
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
        QString logPath = logDir.filePath("hx_file.log");
        
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
        connect(logWatcher, &QFileSystemWatcher::fileChanged, this, &FileSelectorWindow::checkLogChanges);
        
        // 设置定时器定期检查日志更新
        QTimer *logTimer = new QTimer(this);
        connect(logTimer, &QTimer::timeout, this, &FileSelectorWindow::checkLogChanges);
        logTimer->start(1000); // 每秒检查一次
        
        // 初始读取日志
        checkLogChanges();
    }
    
    void loadConfig() {
        // 加载白名单文件配置
        QFile fileConfig("/hx/config/hx_file_f.config");
        if (fileConfig.exists() && fileConfig.open(QIODevice::ReadOnly | QIODevice::Text)) {
            QTextStream in(&fileConfig);
            while (!in.atEnd()) {
                QString line = in.readLine().trimmed();
                if (!line.isEmpty()) {
                    fileList->addItem(line);
                }
            }
            fileConfig.close();
            logOutput->append("已加载白名单配置");
        }
        
        // 加载可执行程序配置
        QFile processConfig("/hx/config/hx_file_p.config");
        if (processConfig.exists() && processConfig.open(QIODevice::ReadOnly | QIODevice::Text)) {
            QTextStream in(&processConfig);
            while (!in.atEnd()) {
                QString line = in.readLine().trimmed();
                if (!line.isEmpty()) {
                    processList->addItem(line);
                }
            }
            processConfig.close();
            logOutput->append("已加载可执行程序配置");
        }
    }
    
    bool isModuleLoaded() {
        QProcess process;
        process.start("lsmod");
        process.waitForFinished();
        QString output = process.readAllStandardOutput();
        return output.contains("hx_file");
    }
};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    
    FileSelectorWindow mainWindow;
    mainWindow.show();
    
    return app.exec();
}

#include "01_file_cli.moc"