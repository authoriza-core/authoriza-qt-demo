#include "authmanager.h"
#include <QSettings>          // Сохранение/восстановление сессии (QSettings)
#include <QUrl>               // Работа с URL-адресами
#include <QDateTime>          // Работа с датой и временем (время жизни токенов)
#include <QDebug>             // Отладочный вывод (qDebug())
#include <QNetworkAccessManager>   // Отправка HTTP-запросов
#include <QNetworkRequest>         // Формирование HTTP-запросов
#include <QNetworkReply>           // Обработка HTTP-ответов
#include <QtNetworkAuth>           // OIDC-клиент (QOAuth2AuthorizationCodeFlow)
#include <QDesktopServices>        // Открытие браузера (QDesktopServices::openUrl())
#include <QUrlQuery>               // Формирование query-параметров URL
#include <QJsonDocument>           // Парсинг JSON-ответов
#include <QJsonObject>             // Работа с JSON-объектами
#include <QRandomGenerator>        // Генерация случайных чисел (PKCE)
#include <QCryptographicHash>      // Хеширование (SHA256 для PKCE)
#include <jwt-cpp/jwt.h>           // Декодирование JWT-токенов
#include <nlohmann/json.hpp>       // Парсинг JSON (для декодирования JWT)
#include "envreader.h"             // Чтение .env файла

// ============================================================
// Конструктор
// Инициализация OIDC-клиента, таймера для автообновления
// ============================================================
AuthManager::AuthManager(QObject *parent)
    : QObject(parent)
{
    // Подключение сигналов успешной аутентификации и ошибок
    connect(&oidc, &QOAuth2AuthorizationCodeFlow::granted,
            this, &AuthManager::onAuthenticationSuccess);
    connect(&oidc, &QOAuth2AuthorizationCodeFlow::error,
            this, &AuthManager::onAuthenticationError);

    // Таймер для автоматической проверки токенов (каждую минуту)
    autoRefreshTimer = new QTimer(this);
    connect(autoRefreshTimer, &QTimer::timeout,
            this, &AuthManager::checkAndRefresh);
    autoRefreshTimer->start(60000);

    m_refreshCount = 0; // Счётчик обновлений для уведомлений
}

// ============================================================
// Настройка OIDC
// Чтение URL из .env, настройка клиента и HTTP-сервера
// ============================================================
void AuthManager::setupOIDC(const QString &clientId)
{
    // Проверка: Client ID не может быть пустым
    if (clientId.isEmpty()) {
        qDebug() << "Ошибка: Client ID не может быть пустым!";
        emit errorOccurred("Client ID не настроен. Проверьте .env файл.");
        return;
    }

    // Чтение URL из .env с дефолтными значениями (продакшн)
    QString authUrl = EnvReader::get("AUTHORIZA_AUTH_URL",
                                     "https://oidc.authoriza.ru/oidc/auth");
    QString tokenUrl = EnvReader::get("AUTHORIZA_TOKEN_URL",
                                      "https://oidc.authoriza.ru/oidc/token");

    // Настройка OIDC-клиента
    oidc.setAuthorizationUrl(QUrl(authUrl));   // URL для авторизации
    oidc.setAccessTokenUrl(QUrl(tokenUrl));    // URL для получения токенов
    oidc.setClientIdentifier(clientId);        // Client ID из Авторизы
    oidc.setScope("openid profile email offline_access"); // Запрашиваемые scope

    // Создание локального HTTP-сервера на порту 8080 для callback
    QOAuthHttpServerReplyHandler *handler = new QOAuthHttpServerReplyHandler(8080, this);
    oidc.setReplyHandler(handler);

    // Подключение сигнала получения callback
    connect(handler, &QOAuthHttpServerReplyHandler::callbackReceived,
            this, &AuthManager::onCallbackReceived);

    qDebug() << "OIDC настроен. Client ID:" << clientId;
}

// ============================================================
// Вход
// Генерация PKCE, открытие браузера с URL авторизации
// ============================================================
void AuthManager::login()
{
    qDebug() << "=== AuthManager::login() вызван ===";

    // Генерация code_verifier (64 символа)
    const QString possibleCharacters("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~");
    const int randomStringLength = 64;

    QString codeVerifier;
    for (int i = 0; i < randomStringLength; ++i) {
        int index = QRandomGenerator::global()->bounded(possibleCharacters.length());
        codeVerifier.append(possibleCharacters.at(index));
    }
    m_codeVerifier = codeVerifier; // Сохраняем для обмена кода на токен

    // Вычисление code_challenge (SHA256 + Base64URL)
    QCryptographicHash hash(QCryptographicHash::Sha256);
    hash.addData(codeVerifier.toUtf8());
    QString codeChallenge = hash.result().toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);

    // Формирование URL авторизации с параметрами
    QUrl authUrl = oidc.authorizationUrl();
    QUrlQuery query;
    query.addQueryItem("client_id", oidc.clientIdentifier());
    query.addQueryItem("response_type", "code");
    query.addQueryItem("redirect_uri", "http://localhost:8080/");
    query.addQueryItem("scope", "openid profile email offline_access");
    query.addQueryItem("code_challenge", codeChallenge);
    query.addQueryItem("code_challenge_method", "S256");

    authUrl.setQuery(query);

    qDebug() << "Открываем URL:" << authUrl.toString();

    // Открытие браузера для входа пользователя
    QDesktopServices::openUrl(authUrl);
}

// ============================================================
// Получен Callback
// Обработка ответа от OIDC-сервера (код авторизации или ошибка)
// ============================================================
void AuthManager::onCallbackReceived(const QVariantMap &values)
{
    qDebug() << "=== Callback получен! ===";

    if (values.contains("code")) {
        // Успешно: получен код авторизации
        QString code = values["code"].toString();
        qDebug() << "Код авторизации:" << code;
        exchangeCodeForToken(code); // Обмен кода на токены
    } else if (values.contains("error")) {
        // Ошибка от сервера
        qDebug() << "Ошибка в callback:" << values["error"].toString();
        emit errorOccurred("Ошибка: " + values["error"].toString());
    }
}

// ============================================================
// Обмен кода на токены
// Отправка запроса к /token, получение Access/ID/Refresh
// ============================================================
void AuthManager::exchangeCodeForToken(const QString &code)
{
    qDebug() << "=== Обмен кода на токен ===";

    // Проверка: code_verifier не должен быть пустым
    if (m_codeVerifier.isEmpty()) {
        qDebug() << "Ошибка: code_verifier пуст!";
        emit errorOccurred("Ошибка PKCE: code_verifier не установлен");
        return;
    }

    QNetworkAccessManager *nam = new QNetworkAccessManager(this);

    // Формирование запроса к /token
    QUrl tokenUrl = oidc.accessTokenUrl();
    QUrlQuery query;
    query.addQueryItem("grant_type", "authorization_code");
    query.addQueryItem("code", code);
    query.addQueryItem("redirect_uri", "http://localhost:8080/");
    query.addQueryItem("client_id", oidc.clientIdentifier());
    query.addQueryItem("code_verifier", m_codeVerifier);

    QNetworkRequest request(tokenUrl);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");

    // Отправка запроса и обработка ответа
    connect(nam, &QNetworkAccessManager::finished,
            [this, nam](QNetworkReply *reply) {
                if (reply->error() == QNetworkReply::NoError) {
                    // Успешный ответ от сервера
                    QString response = QString::fromUtf8(reply->readAll());
                    qDebug() << "Ответ от токен-эндпоинта:" << response;

                    emit tokenEndpointResponseReceived(response); // Для отладки

                    // Парсинг JSON-ответа
                    QJsonDocument doc = QJsonDocument::fromJson(response.toUtf8());
                    QJsonObject obj = doc.object();

                    if (obj.contains("access_token")) {
                        // Сохранение токенов
                        m_accessToken = obj["access_token"].toString();
                        m_refreshToken = obj["refresh_token"].toString();
                        m_idToken = obj["id_token"].toString();

                        // Время жизни Access Token
                        int expiresIn = obj["expires_in"].toInt();
                        m_expiresAt = QDateTime::currentDateTime().addSecs(expiresIn);

                        // Время жизни Refresh Token (если сервер вернул)
                        if (obj.contains("refresh_expires_in")) {
                            int refreshExpiresIn = obj["refresh_expires_in"].toInt();
                            m_refreshExpiresAt = QDateTime::currentDateTime().addSecs(refreshExpiresIn);
                            qDebug() << "Refresh истекает:" << m_refreshExpiresAt.toString();
                        } else {
                            m_refreshExpiresAt = QDateTime(); // Неизвестно
                            qDebug() << "Refresh время истечения не получено от сервера";
                        }

                        qDebug() << "Access Token получен!";
                        qDebug() << "Refresh Token:" << m_refreshToken;
                        onAuthenticationSuccess(); // Успешная аутентификация
                    } else {
                        qDebug() << "В ответе нет access_token!";
                    }
                } else {
                    // Ошибка при получении токена
                    qDebug() << "Ошибка получения токена:" << reply->errorString();
                    emit errorOccurred("Ошибка получения токена: " + reply->errorString());
                }
                reply->deleteLater();
                nam->deleteLater();
            });

    nam->post(request, query.toString().toUtf8());
}

// ============================================================
// Обновление токенов
// Использование Refresh Token для получения новой пары токенов
// ============================================================
void AuthManager::refreshTokens()
{
    // Проверка: Refresh Token должен существовать
    if (m_refreshToken.isEmpty()) {
        emit errorOccurred("Нет Refresh Token. Пожалуйста, войдите заново.");
        return;
    }

    // Проверка: Refresh Token не истек
    if (m_refreshExpiresAt.isValid() &&
        QDateTime::currentDateTime() > m_refreshExpiresAt) {
        qDebug() << "Refresh Token истек!";
        handleSessionExpired();
        emit errorOccurred("Refresh Token истек. Пожалуйста, войдите заново.");
        return;
    }

    QUrl tokenUrl = oidc.accessTokenUrl();
    if (tokenUrl.isEmpty()) {
        emit errorOccurred("Token URL не настроен");
        return;
    }

    qDebug() << "=== Обновление токенов через refresh_token ===";

    QNetworkAccessManager *nam = new QNetworkAccessManager(this);

    // Формирование запроса на обновление
    QUrlQuery query;
    query.addQueryItem("grant_type", "refresh_token");
    query.addQueryItem("refresh_token", m_refreshToken);
    query.addQueryItem("client_id", oidc.clientIdentifier());
    query.addQueryItem("client_secret", "");

    QNetworkRequest request(tokenUrl);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");
    request.setRawHeader("Accept", "application/json");
    request.setTransferTimeout(15000); // Таймаут 15 секунд

    // Отправка запроса и обработка ответа
    connect(nam, &QNetworkAccessManager::finished,
            [this, nam](QNetworkReply *reply) {
                int httpCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
                QByteArray responseData = reply->readAll();

                qDebug() << "HTTP код ответа (refresh):" << httpCode;
                qDebug() << "Тело ответа:" << QString::fromUtf8(responseData);

                if (reply->error() == QNetworkReply::NoError) {
                    // Успешное обновление
                    QJsonDocument doc = QJsonDocument::fromJson(responseData);
                    QJsonObject obj = doc.object();

                    if (obj.contains("access_token")) {
                        // Обновление Access и ID токенов
                        m_accessToken = obj["access_token"].toString();
                        m_idToken = obj["id_token"].toString();

                        // Ротация Refresh Token (если сервер выдал новый)
                        if (obj.contains("refresh_token")) {
                            m_refreshToken = obj["refresh_token"].toString();
                            qDebug() << "Refresh Token обновлен (ротация):" << m_refreshToken;
                        } else {
                            qDebug() << "Refresh Token НЕ ПРИШЁЛ в ответе";
                        }

                        // Обновление времени жизни
                        int expiresIn = obj["expires_in"].toInt();
                        m_expiresAt = QDateTime::currentDateTime().addSecs(expiresIn);

                        if (obj.contains("refresh_expires_in")) {
                            int refreshExpiresIn = obj["refresh_expires_in"].toInt();
                            m_refreshExpiresAt = QDateTime::currentDateTime().addSecs(refreshExpiresIn);
                            qDebug() << "Refresh истекает:" << m_refreshExpiresAt.toString();
                        } else {
                            m_refreshExpiresAt = QDateTime();
                            qDebug() << "Refresh время истечения не получено от сервера";
                        }

                        qDebug() << "Токены обновлены!";
                        saveSession();          // Сохранение сессии
                        emit tokensRefreshed(); // Сигнал об успешном обновлении
                        emit authenticated();   // Сигнал о валидной сессии
                    } else {
                        qDebug() << "В ответе нет access_token!";
                        emit errorOccurred("В ответе нет access_token");
                    }
                } else {
                    // Ошибка при обновлении
                    if (httpCode == 400 || httpCode == 401) {
                        // Refresh Token невалиден → принудительный выход
                        qDebug() << "Refresh Token невалиден или истек!";
                        QString userMessage = "Ваша сессия истекла или токен недействителен.\n"
                                              "Пожалуйста, войдите заново.";
                        emit errorOccurred(userMessage);
                        handleSessionExpired(); // Очистка сессии
                    } else if (httpCode == 0) {
                        // Сервер недоступен
                        QString userMessage = "Сервер Авторизы недоступен.\n"
                                              "Проверьте подключение к интернету и попробуйте снова.";
                        emit errorOccurred(userMessage);
                    } else {
                        // Другая ошибка
                        QString userMessage = "Ошибка обновления токенов (HTTP " + QString::number(httpCode) + ").\n"
                                                                                                               "Пожалуйста, попробуйте позже.";
                        emit errorOccurred(userMessage);
                    }
                }
                reply->deleteLater();
                nam->deleteLater();
            });

    nam->post(request, query.toString().toUtf8());
}

// ============================================================
// Выход
// Очистка токенов, сессии и открытие страницы выхода
// ============================================================
void AuthManager::logout()
{
    // Очистка всех токенов и данных
    m_accessToken.clear();
    m_refreshToken.clear();
    m_idToken.clear();
    m_expiresAt = QDateTime();
    m_refreshExpiresAt = QDateTime();
    m_codeVerifier.clear();
    m_refreshCount = 0;

    // Очистка сохранённой сессии
    QSettings settings("MyApp", "Authoriza");
    settings.clear();

    // Открытие страницы выхода на сервере
    QString logoutUrl = EnvReader::get("AUTHORIZA_LOGOUT_URL",
                                       "https://oidc.authoriza.ru/oidc/session/end");
    QDesktopServices::openUrl(QUrl(logoutUrl));
}

// ============================================================
// Геттеры
// Получение значений токенов и времени их истечения
// ============================================================
QString AuthManager::getAccessToken() const { return m_accessToken; }
QString AuthManager::getIdToken() const { return m_idToken; }
QString AuthManager::getRefreshToken() const { return m_refreshToken; }
QDateTime AuthManager::getExpirationTime() const { return m_expiresAt; }
QDateTime AuthManager::getRefreshExpirationTime() const { return m_refreshExpiresAt; }

// ============================================================
// Проверка аутентификации
// Возвращает true, если все токены валидны и не истекли
// ============================================================
bool AuthManager::isAuthenticated() const
{
    return !m_accessToken.isEmpty() &&
           !m_refreshToken.isEmpty() &&
           m_expiresAt.isValid() &&
           QDateTime::currentDateTime() < m_expiresAt;
}

// ============================================================
// Сохранение сессии
// Запись токенов в QSettings для восстановления после перезапуска
// ============================================================
void AuthManager::saveSession()
{
    QSettings settings("MyApp", "Authoriza");
    settings.setValue("access_token", m_accessToken);
    settings.setValue("refresh_token", m_refreshToken);
    settings.setValue("id_token", m_idToken);
    settings.setValue("expires_at", m_expiresAt);
    settings.setValue("refresh_expires_at", m_refreshExpiresAt);
}

// ============================================================
// Восстановление сессии
// Чтение токенов из QSettings при запуске приложения
// ============================================================
void AuthManager::restoreSession()
{
    QSettings settings("MyApp", "Authoriza");
    m_refreshToken = settings.value("refresh_token").toString();
    m_idToken = settings.value("id_token").toString();

    m_expiresAt = settings.value("expires_at").toDateTime();
    m_refreshExpiresAt = settings.value("refresh_expires_at").toDateTime();

    // Если есть Refresh Token, проверяем Access Token
    if (!m_refreshToken.isEmpty()) {
        // Если Access Token скоро истекает (менее 5 минут), обновляем
        if (m_expiresAt.isValid() &&
            QDateTime::currentDateTime().secsTo(m_expiresAt) <= 300) {
            qDebug() << "Токен скоро истекает, обновляем при запуске...";
            refreshTokens();
        }
        emit sessionRestored(); // Сигнал о восстановлении сессии
    }
}

// ============================================================
// Успешная аутентификация
// Обработка успешного получения токенов
// ============================================================
void AuthManager::onAuthenticationSuccess()
{
    m_refreshCount = 0;      // Сброс счетчика обновлений
    saveSession();           // Сохранение сессии
    emit authenticated();    // Сигнал об успешной аутентификации
}

// ============================================================
// Ошибка аутентификации
// ============================================================
void AuthManager::onAuthenticationError(const QString &error)
{
    emit errorOccurred("Ошибка: " + error);
}

// ============================================================
// Периодическая проверка токенов
// Вызывается каждую минуту по таймеру
// ============================================================
void AuthManager::checkAndRefresh()
{
    qDebug() << "=== checkAndRefresh() ВЫЗВАН ===";

    if (m_accessToken.isEmpty()) {
        return; // Нет токена — нечего проверять
    }

    // Проверка: не истекла ли сессия
    if (isSessionExpired()) {
        qDebug() << "Сессия истекла (Refresh Token отсутствует)";
        handleSessionExpired();
        return;
    }

    // Проверка: нужно ли обновить токен
    if (shouldRefresh()) {
        m_refreshCount++;
        qDebug() << "Автоматическое обновление токенов";

        // Уведомление после 2-х обновлений
        if (m_refreshCount >= 2) {
            emit sessionExpiring(); // Сессия скоро истечет
            m_refreshCount = 0;     // Сброс счетчика
        }

        refreshTokens(); // Обновление токенов
    } else {
        qDebug() << "checkAndRefresh: обновление не требуется";
    }
}

// ============================================================
// Вспомогательные методы
// ============================================================

// Проверка: нужно ли обновить токен (осталось <= 30 секунд)
bool AuthManager::shouldRefresh() const
{
    if (m_accessToken.isEmpty() || m_refreshToken.isEmpty()) {
        return false;
    }

    qint64 secondsLeft = QDateTime::currentDateTime().secsTo(m_expiresAt);
    return secondsLeft <= 30 && secondsLeft > 0;
}

// Проверка: истекла ли сессия
bool AuthManager::isSessionExpired() const
{
    if (m_accessToken.isEmpty()) {
        return true;
    }

    if (m_refreshToken.isEmpty()) {
        return true; // Нет Refresh Token — восстановление невозможно
    }

    qint64 secondsLeft = QDateTime::currentDateTime().secsTo(m_expiresAt);
    return secondsLeft <= 0;
}

// Проверка: доступен ли Refresh Token
bool AuthManager::isRefreshTokenAvailable() const
{
    return !m_refreshToken.isEmpty();
}

// ============================================================
// Обработка истечения сессии
// Принудительная очистка всех данных сессии
// ============================================================
void AuthManager::handleSessionExpired()
{
    qDebug() << "=== Сессия истекла ===";

    // Очистка всех токенов
    m_accessToken.clear();
    m_refreshToken.clear();
    m_idToken.clear();
    m_expiresAt = QDateTime();
    m_refreshExpiresAt = QDateTime();
    m_refreshCount = 0;

    // Очистка сохранённой сессии
    QSettings settings("MyApp", "Authoriza");
    settings.clear();

    emit sessionExpired(); // Сигнал об истечении сессии
}

// ============================================================
// Декодирование JWT
// Возвращает Payload в виде форматированного JSON
// ============================================================
QString decodeJWT(const QString &token)
{
    if (token.isEmpty()) {
        return "Токен пуст";
    }

    try {
        // Декодирование JWT с помощью jwt-cpp
        auto decoded = jwt::decode(token.toStdString());
        // Парсинг Payload как JSON
        auto payload = nlohmann::json::parse(decoded.get_payload());
        return QString::fromStdString(payload.dump(2));
    } catch (const std::exception &e) {
        return QString("Ошибка декодирования: ") + e.what();
    }
}
