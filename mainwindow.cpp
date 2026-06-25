#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "authmanager.h"
#include <QMessageBox>
#include <QDateTime>
#include <QDebug>
#include <jwt-cpp/jwt.h>
#include <nlohmann/json.hpp>

// ===== Конструктор MainWindow =====
// Инициализация UI, создание AuthManager, настройка OIDC,
// подключение сигналов/слотов, восстановление сессии
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    // Создание и настройка менеджера аутентификации
    authManager = new AuthManager(this);
    authManager->setupOIDC("16e611ef-283d-4837-9776-23e153afdd2f");

    // Подключение кнопок UI
    connect(ui->loginButton, &QPushButton::clicked, this, &MainWindow::onLogin);
    connect(ui->refreshButton, &QPushButton::clicked, this, &MainWindow::onRefresh);
    connect(ui->logoutButton, &QPushButton::clicked, this, &MainWindow::onLogout);

    // Подключение сигналов AuthManager к слотам
    connect(authManager, &AuthManager::authenticated,
            this, &MainWindow::onAuthenticated);
    connect(authManager, &AuthManager::userInfoReceived,
            this, &MainWindow::onUserInfoReceived);
    connect(authManager, &AuthManager::errorOccurred,
            this, &MainWindow::onError);
    connect(authManager, &AuthManager::tokenEndpointResponseReceived,
            this, &MainWindow::onTokenResponseReceived);

    // Уведомления о сессии
    connect(authManager, &AuthManager::sessionExpiring,
            this, &MainWindow::onSessionExpiring);
    connect(authManager, &AuthManager::sessionExpired,
            this, &MainWindow::onSessionExpired);

    // Восстановление сессии при запуске
    authManager->restoreSession();
}

MainWindow::~MainWindow()
{
    delete ui;
}

// ===== Обработчик кнопки "Вход" =====
void MainWindow::onLogin()
{
    qDebug() << "=== Кнопка Login нажата ===";
    ui->statusLabel->setText("Статус: Выполняется вход...");
    authManager->login();
}

// ===== Обработчик кнопки "Обновить токены" =====
void MainWindow::onRefresh()
{
    ui->statusLabel->setText("Статус: Обновление токенов...");
    authManager->refreshTokens();
}

// ===== Обработчик кнопки "Выход" =====
// Очищает все поля и вызывает logout у AuthManager
void MainWindow::onLogout()
{
    authManager->logout();

    ui->statusLabel->setText("Статус: Не авторизован");
    ui->accessTokenEdit->clear();
    ui->idTokenEdit->clear();
    ui->refreshTokenEdit->clear();
    ui->idPayloadEdit->clear();
    ui->accessPayloadEdit->clear();
    ui->userInfoEdit->clear();
    ui->tokenResponseEdit->clear();
    ui->accessExpiryLabel->setText("Время истечения: --");
    ui->lastRefreshLabel->setText("Время обновления: --");
}

// ===== Успешная аутентификация =====
// Отображает полученные токены, декодирует JWT, запрашивает UserInfo
void MainWindow::onAuthenticated()
{
    QString accessToken = authManager->getAccessToken();
    QString idToken = authManager->getIdToken();
    QString refreshToken = authManager->getRefreshToken();

    qDebug() << "=== onAuthenticated() ВЫЗВАН ===";

    ui->statusLabel->setText("Статус: Авторизован");
    ui->accessTokenEdit->setPlainText(accessToken);
    ui->idTokenEdit->setPlainText(idToken);
    ui->refreshTokenEdit->setPlainText(refreshToken);
    ui->accessExpiryLabel->setText("Время истечения: " +
                                   authManager->getExpirationTime().toString());
    ui->lastRefreshLabel->setText("Время обновления: " +
                                  QDateTime::currentDateTime().toString());

    // Декодирование JWT токенов для отображения payload
    ui->idPayloadEdit->setPlainText(decodeJWT(idToken));
    ui->accessPayloadEdit->setPlainText(decodeJWT(accessToken));

    // ===== ИЗВЛЕЧЕНИЕ ИМЕНИ И EMAIL ИЗ ID TOKEN =====
    if (!idToken.isEmpty()) {
        try {
            auto decoded = jwt::decode(idToken.toStdString()); // ← исправлено
            auto payload = nlohmann::json::parse(decoded.get_payload());
            QString name = QString::fromStdString(payload.value("name", ""));
            QString email = QString::fromStdString(payload.value("email", ""));
            ui->userInfoEdit->setPlainText(QString("Имя: %1\nEmail: %2").arg(name).arg(email));
        } catch (const std::exception &e) {
            qDebug() << "Ошибка декодирования ID Token:" << e.what();
            ui->userInfoEdit->setPlainText("Не удалось извлечь данные из ID Token. Ошибка: " + QString(e.what()));
        } catch (...) {
            qDebug() << "Неизвестная ошибка при декодировании ID Token";
            ui->userInfoEdit->setPlainText("Неизвестная ошибка при извлечении данных из ID Token");
        }
    } else {
        ui->userInfoEdit->setPlainText("ID Token пуст");
    }

    // Запрос дополнительной информации о пользователе через /me
    authManager->fetchUserInfo();
}

// ===== Получены данные UserInfo =====
void MainWindow::onUserInfoReceived(const QString &data)
{
    ui->userInfoEdit->setPlainText("UserInfo из /me:\n" + data);
}

// ===== Получен ответ от токен-эндпоинта (для отладки) =====
void MainWindow::onTokenResponseReceived(const QString &response)
{
    ui->tokenResponseEdit->setPlainText(response);
}

// ===== Обработчик ошибок =====
void MainWindow::onError(const QString &error)
{
    ui->statusLabel->setText("Статус: Ошибка");
    QMessageBox::warning(this, "Ошибка", error);
}

// ===== Сессия скоро истечет =====
// Показывает диалог с предложением продлить сессию или выйти
void MainWindow::onSessionExpiring()
{
    qDebug() << "=== СЕССИЯ СКОРО ИСТЕЧЕТ (уведомление) ===";

    QMessageBox::StandardButton reply;
    reply = QMessageBox::warning(this, "Сессия истекает",
                                 "Ваша сессия истекает через минуту.\n"
                                 "Нажмите 'OK' для продления или 'Cancel' для выхода.",
                                 QMessageBox::Ok | QMessageBox::Cancel);

    if (reply == QMessageBox::Ok) {
        authManager->refreshTokens();
        ui->statusLabel->setText("Статус: Сессия продлена ");
    } else {
        onLogout();
        ui->statusLabel->setText("Статус: Выход выполнен ");
    }
}

// ===== Сессия истекла =====
// Выполняет выход и показывает информационное сообщение
void MainWindow::onSessionExpired()
{
    qDebug() << "=== СЕССИЯ ИСТЕКЛА (очистка) ===";

    onLogout();

    QMessageBox::information(this, "Сессия истекла",
                             "Ваша сессия истекла.\n"
                             "Пожалуйста, войдите заново.");
}