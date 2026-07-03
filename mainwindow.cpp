#include "mainwindow.h"                    // Заголовок главного окна
#include "ui_mainwindow.h"                 // Сгенерированный UI-класс
#include "authmanager.h"                   // Менеджер аутентификации
#include <QMessageBox>                     // Для диалоговых окон
#include <QDateTime>                       // Для работы с датой/временем
#include <QDebug>                          // Для отладочного вывода
#include "envreader.h"                     // Для чтения .env файла

MainWindow::MainWindow(QWidget *parent)    // Конструктор
    : QMainWindow(parent), ui(new Ui::MainWindow)
{
    ui->setupUi(this);                     // Загрузка UI из .ui файла
    authManager = new AuthManager(this);   // Создание менеджера аутентификации
    QString clientId = EnvReader::get("CLIENT_ID"); // Чтение Client ID из .env. Получение Client ID
    qDebug() << "=== Client ID из .env ===" << clientId;

    if (clientId.isEmpty()) {
        qDebug() << "Ошибка: CLIENT_ID не найден в .env!";
        qDebug() << "Укажите CLIENT_ID в файле .env";
        clientId = "NOT_DEFINED"; // Fallback
    }
    authManager->setupOIDC(clientId);      // Настройка OIDC
    // Подключение сигналов кнопок
    connect(ui->loginButton, &QPushButton::clicked, this, &MainWindow::onLogin);
    connect(ui->refreshButton, &QPushButton::clicked, this, &MainWindow::onRefresh);
    connect(ui->logoutButton, &QPushButton::clicked, this, &MainWindow::onLogout);
    // Подключение сигналов AuthManager
    connect(authManager, &AuthManager::authenticated, this, &MainWindow::onAuthenticated);
    connect(authManager, &AuthManager::errorOccurred, this, &MainWindow::onError);
    connect(authManager, &AuthManager::tokenEndpointResponseReceived, this, &MainWindow::onTokenResponseReceived);
    connect(authManager, &AuthManager::sessionExpiring, this, &MainWindow::onSessionExpiring);
    connect(authManager, &AuthManager::sessionExpired, this, &MainWindow::onSessionExpired);
    authManager->restoreSession();         // Восстановление сессии
    updateUI();                            // Обновление UI
}
MainWindow::~MainWindow()                  // Деструктор
{
    delete ui;                             // Очистка UI
}
void MainWindow::updateUI()                // Обновление UI
{
    bool auth = authManager->isAuthenticated(); // Проверка аутентификации
    updateAuthStatus(auth);                // Обновление статуса
    if (auth) {
        populateTokens(authManager->getAccessToken(),   // Заполнение токенов
                       authManager->getIdToken(),
                       authManager->getRefreshToken());
        updateExpiryTime(authManager->getExpirationTime()); // Обновление времени истечения
    } else {
        clearAllFields();                  // Очистка полей
    }
}
void MainWindow::onLogin()                 // Кнопка Login
{
    ui->statusLabel->setText("Выполняется вход..."); // Статус
    ui->loginButton->setEnabled(false);    // Блокировка кнопки
    authManager->login();                  // Запуск входа
}
void MainWindow::onRefresh()               // Кнопка Refresh
{
    ui->statusLabel->setText("Обновление..."); // Статус
    ui->refreshButton->setEnabled(false);  // Блокировка кнопки
    authManager->refreshTokens();          // Обновление токенов
}
void MainWindow::onLogout()                // Кнопка Logout
{
    authManager->logout();                 // Выход
    updateUI();                            // Обновление UI
    ui->statusLabel->setText("Выход выполнен"); // Статус
}
void MainWindow::onAuthenticated()         // Успешная аутентификация
{
    updateUI();                            // Обновление UI
    updateLastRefreshTime();               // Обновление времени
}
void MainWindow::onTokenResponseReceived(const QString &response) // Ответ от /token
{
    ui->tokenResponseEdit->setPlainText(response); // Вывод ответа
}
void MainWindow::onError(const QString &error)     // Ошибка
{
    ui->statusLabel->setText("Ошибка");
    ui->loginButton->setEnabled(true);     // Разблокировка Login
    ui->refreshButton->setEnabled(true);   // Разблокировка Refresh
    showMessage("Ошибка", error, QMessageBox::Warning); // Показ сообщения
}
void MainWindow::onSessionExpiring()       // Сессия скоро истечет
{
    if (showQuestion("Сессия истекает", "Продлить сессию?")) { // Вопрос
        authManager->refreshTokens();      // Продление сессии
        ui->statusLabel->setText("Сессия продлена");
    } else {
        onLogout();                        // Выход
    }
}
void MainWindow::onSessionExpired()        // Сессия истекла
{
    updateUI();                            // Обновление UI
    showMessage("Сессия истекла", "Войдите заново.", QMessageBox::Information); // Сообщение
}
