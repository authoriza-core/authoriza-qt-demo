#include "authmanager.h"                    // Заголовок AuthManager
#include <QSettings>                        // Для сохранения/восстановления сессии
#include <QUrl>                             // Для работы с URL
#include <QDateTime>                        // Для работы с датой/временем
#include <QDebug>                           // Для отладочного вывода
#include <QtNetworkAuth>                    // OIDC-клиент (QOAuth2AuthorizationCodeFlow)
#include <QDesktopServices>                 // Для открытия браузера
#include <QUrlQuery>                        // Для формирования query-параметров URL
#include <QJsonDocument>                    // Для парсинга JSON
#include <QJsonObject>                      // Для работы с JSON-объектами
#include "envreader.h"                      // Для чтения .env файла
#include <jwt-cpp/jwt.h>                    // Для декодирования JWT-токенов
#include <nlohmann/json.hpp>                // Для парсинга JSON (в decodeJWT)

// Конструктор
AuthManager::AuthManager(QObject *parent)
    : QObject(parent)
{
    connect(&oidc, &QOAuth2AuthorizationCodeFlow::granted,  // Сигнал успешной аутентификации
            this, &AuthManager::onAuthenticationSuccess);
    connect(&oidc, &QOAuth2AuthorizationCodeFlow::error,    // Сигнал ошибки
            this, &AuthManager::onAuthenticationError);

    autoRefreshTimer = new QTimer(this);                    // Создание таймера
    connect(autoRefreshTimer, &QTimer::timeout,             // Подключение таймера к проверке
            this, &AuthManager::checkAndRefresh);
    autoRefreshTimer->start(60000);                         // Запуск таймера (каждую минуту)

    m_refreshCount = 0;                                     // Счетчик обновлений
}

// Настройка OIDC
void AuthManager::setupOIDC(const QString &clientId)
{
    if (clientId.isEmpty()) {                               // Проверка Client ID
        qDebug() << "Ошибка: Client ID не может быть пустым!";
        emit errorOccurred("Client ID не настроен. Проверьте .env файл.");
        return;
    }

    QString authUrl = EnvReader::get("AUTHORIZA_AUTH_URL",  // Чтение URL авторизации
                                     "https://oidc.authoriza.ru/oidc/auth");
    QString tokenUrl = EnvReader::get("AUTHORIZA_TOKEN_URL", // Чтение URL токена
                                      "https://oidc.authoriza.ru/oidc/token");

    oidc.setAuthorizationUrl(QUrl(authUrl));               // Установка URL авторизации
    oidc.setAccessTokenUrl(QUrl(tokenUrl));                 // Установка URL токена
    oidc.setClientIdentifier(clientId);                     // Установка Client ID
    oidc.setScope("openid profile email offline_access");   // Установка Scope

    QOAuthHttpServerReplyHandler *handler = new QOAuthHttpServerReplyHandler(8080, this); // Локальный HTTP-сервер
    oidc.setReplyHandler(handler);                           // Установка обработчика

    connect(handler, &QOAuthHttpServerReplyHandler::callbackReceived, // Подключение callback
            this, &AuthManager::onCallbackReceived);

    qDebug() << "OIDC настроен. Client ID:" << clientId;
}

// Геттеры
QString AuthManager::getAccessToken() const { return m_accessToken; }    // Возвращает Access Token
QString AuthManager::getIdToken() const { return m_idToken; }            // Возвращает ID Token
QString AuthManager::getRefreshToken() const { return m_refreshToken; }  // Возвращает Refresh Token
QDateTime AuthManager::getExpirationTime() const { return m_expiresAt; } // Возвращает время истечения
QDateTime AuthManager::getRefreshExpirationTime() const { return m_refreshExpiresAt; } // Возвращает время истечения Refresh

// Вспомогательная функция
QString decodeJWT(const QString &token)
{
    if (token.isEmpty()) {                                   // Проверка пустого токена
        return "Токен пуст";
    }

    try {
        auto decoded = jwt::decode(token.toStdString());     // Декодирование JWT
        auto payload = nlohmann::json::parse(decoded.get_payload()); // Парсинг Payload
        return QString::fromStdString(payload.dump(2));       // Возврат форматированного JSON
    } catch (const std::exception &e) {
        return QString("Ошибка декодирования: ") + e.what(); // Обработка ошибки
    }
}
