#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "authmanager.h"
#include <QMessageBox>
#include <QDateTime>
#include <QDebug>
#include <jwt-cpp/jwt.h>        // Для декодирования JWT
#include <nlohmann/json.hpp>    // Для работы с JSON (парсинг Payload)

// ===== Конструктор главного окна =====
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this); // Загружаем интерфейс из .ui файла

    // Создаём менеджер аутентификации
    authManager = new AuthManager(this);
    // Настраиваем OIDC с Client ID из Авторизы
    authManager->setupOIDC("16e611ef-283d-4837-9776-23e153afdd2f");

    // Подключаем сигналы от кнопок к слотам
    connect(ui->loginButton, &QPushButton::clicked, this, &MainWindow::onLogin);
    connect(ui->refreshButton, &QPushButton::clicked, this, &MainWindow::onRefresh);
    connect(ui->logoutButton, &QPushButton::clicked, this, &MainWindow::onLogout);

    // Подключаем сигналы от AuthManager к слотам
    connect(authManager, &AuthManager::authenticated,
            this, &MainWindow::onAuthenticated);
    connect(authManager, &AuthManager::errorOccurred,
            this, &MainWindow::onError);
    connect(authManager, &AuthManager::tokenEndpointResponseReceived,
            this, &MainWindow::onTokenResponseReceived);

    // Подключаем уведомления о сессии
    connect(authManager, &AuthManager::sessionExpiring,
            this, &MainWindow::onSessionExpiring);
    connect(authManager, &AuthManager::sessionExpired,
            this, &MainWindow::onSessionExpired);

    // Пытаемся восстановить сессию при запуске
    authManager->restoreSession();
}

// ===== Деструктор =====
MainWindow::~MainWindow()
{
    delete ui; // Освобождаем память, занятую интерфейсом
}

// ===== Кнопка "Вход" =====
void MainWindow::onLogin()
{
    qDebug() << "=== Кнопка Login нажата ===";
    ui->statusLabel->setText("Статус: Выполняется вход...");
    authManager->login(); // Запускаем процесс аутентификации
}

// ===== Кнопка "Обновить токены" =====
void MainWindow::onRefresh()
{
    ui->statusLabel->setText("Статус: Обновление токенов...");
    authManager->refreshTokens(); // Принудительное обновление токенов
}

// ===== Кнопка "Выход" =====
void MainWindow::onLogout()
{
    authManager->logout(); // Очищаем токены и сессию

    // Очищаем все поля интерфейса
    ui->statusLabel->setText("Статус: Не авторизован");
    ui->accessTokenEdit->clear();
    ui->idTokenEdit->clear();
    ui->refreshTokenEdit->clear();
    ui->idPayloadEdit->clear();
    ui->accessPayloadEdit->clear();
    ui->tokenResponseEdit->clear();
    ui->accessExpiryLabel->setText("Время истечения: --");
    ui->lastRefreshLabel->setText("Время обновления: --");
}

// ===== Успешная аутентификация =====
void MainWindow::onAuthenticated()
{
    // Получаем токены из менеджера
    QString accessToken = authManager->getAccessToken();
    QString idToken = authManager->getIdToken();
    QString refreshToken = authManager->getRefreshToken();

    qDebug() << "=== onAuthenticated() ВЫЗВАН ===";

    // Обновляем интерфейс
    ui->statusLabel->setText("Статус: Авторизован");
    ui->accessTokenEdit->setPlainText(accessToken);
    ui->idTokenEdit->setPlainText(idToken);
    ui->refreshTokenEdit->setPlainText(refreshToken);
    ui->accessExpiryLabel->setText("Время истечения: " +
                                   authManager->getExpirationTime().toString());
    ui->lastRefreshLabel->setText("Время обновления: " +
                                  QDateTime::currentDateTime().toString());

    // Декодируем JWT и отображаем Payload
    ui->idPayloadEdit->setPlainText(decodeJWT(idToken));
    ui->accessPayloadEdit->setPlainText(decodeJWT(accessToken));

    // UserInfo удалён из ТЗ — не отображаем
}

// ===== Получен ответ от Token Endpoint (для отладки) =====
void MainWindow::onTokenResponseReceived(const QString &response)
{
    ui->tokenResponseEdit->setPlainText(response);
}

// ===== Обработчик ошибок =====
void MainWindow::onError(const QString &error)
{
    ui->statusLabel->setText("Статус: Ошибка");
    QMessageBox::warning(this, "Ошибка", error); // Показываем всплывающее окно
}

// ===== Сессия скоро истечет (уведомление) =====
void MainWindow::onSessionExpiring()
{
    qDebug() << "=== Сессия скоро истечет (уведомление) ===";

    // Спрашиваем пользователя, хочет ли он продлить сессию
    QMessageBox::StandardButton reply;
    reply = QMessageBox::warning(this, "Сессия истекает",
                                 "Ваша сессия истекает через минуту.\n"
                                 "Нажмите 'OK' для продления или 'Cancel' для выхода.",
                                 QMessageBox::Ok | QMessageBox::Cancel);

    if (reply == QMessageBox::Ok) {
        // Продлеваем сессию
        authManager->refreshTokens();
        ui->statusLabel->setText("Статус: Сессия продлена ");
    } else {
        // Выход
        onLogout();
        ui->statusLabel->setText("Статус: Выход выполнен ");
    }
}

// ===== Сессия истекла =====
void MainWindow::onSessionExpired()
{
    qDebug() << "=== Сессия истекла (очистка) ===";

    // Очищаем интерфейс
    onLogout();

    // Показываем сообщение
    QMessageBox::information(this, "Сессия истекла",
                             "Ваша сессия истекла.\n"
                             "Пожалуйста, войдите заново.");
}
