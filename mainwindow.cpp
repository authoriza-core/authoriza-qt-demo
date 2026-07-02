#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "authmanager.h"
#include <QMessageBox>   // Всплывающие диалоговые окна (информация, предупреждение, ошибка)
#include <QDateTime>     // Работа с датой и временем (отображение времени обновления)
#include <QDebug>        // Отладочный вывод (qDebug())
#include <jwt-cpp/jwt.h>        // Декодирование JWT-токенов (для отображения Payload)
#include <nlohmann/json.hpp>    // Парсинг JSON (для декодирования JWT)

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

    // ===== Новый вызов: обновляем UI после восстановления сессии =====
    updateUI();
}

// ===== Деструктор =====
MainWindow::~MainWindow()
{
    delete ui; // Освобождаем память, занятую интерфейсом
}


// ===== обновление UI в зависимости от состояния =====
void MainWindow::updateUI()
{
    if (authManager->isAuthenticated()) {
        // ===== Авторизованное состояние =====
        ui->statusLabel->setText("Статус: Авторизован ✅");

        // Получаем токены
        QString accessToken = authManager->getAccessToken();
        QString idToken = authManager->getIdToken();
        QString refreshToken = authManager->getRefreshToken();

        // Обновляем поля
        ui->accessTokenEdit->setPlainText(accessToken);
        ui->idTokenEdit->setPlainText(idToken);
        ui->refreshTokenEdit->setPlainText(refreshToken);

        // Обновляем время истечения
        QDateTime expiresAt = authManager->getExpirationTime();
        if (expiresAt.isValid()) {
            ui->accessExpiryLabel->setText("Время истечения: " + expiresAt.toString());
        } else {
            ui->accessExpiryLabel->setText("Время истечения: --");
        }

        // Декодируем JWT
        ui->idPayloadEdit->setPlainText(decodeJWT(idToken));
        ui->accessPayloadEdit->setPlainText(decodeJWT(accessToken));

        // Блокируем кнопку Login, разблокируем Refresh и Logout
        ui->loginButton->setEnabled(false);
        ui->refreshButton->setEnabled(true);
        ui->logoutButton->setEnabled(true);

    } else {
        // ===== Неавторизованное состояние =====
        ui->statusLabel->setText("Статус: Не авторизован ❌");

        // Очищаем все поля
        ui->accessTokenEdit->clear();
        ui->idTokenEdit->clear();
        ui->refreshTokenEdit->clear();
        ui->idPayloadEdit->clear();
        ui->accessPayloadEdit->clear();
        ui->tokenResponseEdit->clear();
        ui->accessExpiryLabel->setText("Время истечения: --");
        ui->lastRefreshLabel->setText("Время обновления: --");

        // Разблокируем кнопку Login, блокируем Refresh и Logout
        ui->loginButton->setEnabled(true);
        ui->refreshButton->setEnabled(false);
        ui->logoutButton->setEnabled(false);
    }
}

// ===== Кнопка "Вход" =====
void MainWindow::onLogin()
{
    qDebug() << "=== Кнопка Login нажата ===";
    ui->statusLabel->setText("Статус: Выполняется вход...");
    ui->loginButton->setEnabled(false); // Блокируем кнопку на время входа
    authManager->login(); // Запускаем процесс аутентификации
}

// ===== Кнопка "Обновить токены" =====
void MainWindow::onRefresh()
{
    ui->statusLabel->setText("Статус: Обновление токенов...");
    ui->refreshButton->setEnabled(false); // Блокируем кнопку на время обновления
    authManager->refreshTokens(); // Принудительное обновление токенов
}

// ===== Кнопка "Выход" =====
void MainWindow::onLogout()
{
    authManager->logout(); // Очищаем токены и сессию

    // Обновляем UI через updateUI()
    updateUI();

    // Дополнительно показываем статус
    ui->statusLabel->setText("Статус: Выполнен выход");
}

// ===== Успешная аутентификация =====
void MainWindow::onAuthenticated()
{
    qDebug() << "=== onAuthenticated() ВЫЗВАН ===";

    // Обновляем UI через updateUI()
    updateUI();

    // Дополнительно обновляем время последнего обновления
    ui->lastRefreshLabel->setText("Время обновления: " +
                                  QDateTime::currentDateTime().toString());

    // Разблокируем кнопки
    ui->loginButton->setEnabled(false);
    ui->refreshButton->setEnabled(true);
    ui->logoutButton->setEnabled(true);

    qDebug() << "=== Аутентификация успешна, UI обновлён ===";
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

    // Разблокируем кнопки
    ui->loginButton->setEnabled(true);
    ui->refreshButton->setEnabled(true);

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
        ui->statusLabel->setText("Статус: Сессия продлена");
    } else {
        // Выход
        onLogout();
        ui->statusLabel->setText("Статус: Выход выполнен");
    }
}

// ===== Сессия истекла =====
void MainWindow::onSessionExpired()
{
    qDebug() << "=== Сессия истекла (очистка) ===";

    // Очищаем интерфейс через updateUI()
    updateUI();

    // Показываем сообщение
    QMessageBox::information(this, "Сессия истекла",
                             "Ваша сессия истекла.\n"
                             "Пожалуйста, войдите заново.");
}
