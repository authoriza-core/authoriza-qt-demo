#include "authmanager.h"
#include <QNetworkAccessManager>      // Для выполнения HTTP-запросов
#include <QNetworkRequest>            // Для формирования HTTP-запросов
#include <QNetworkReply>              // Для обработки ответов на HTTP-запросы
#include <QSettings>                  // Для сохранения токенов в реестр/файл
#include <QUrl>                       // Для работы с URL
#include <QDateTime>                  // Для работы с датой и временем
#include <QtNetworkAuth>              // Модуль Qt для OAuth2/OIDC
#include <QDesktopServices>           // Для открытия браузера
#include <QUrlQuery>                  // Для формирования параметров URL
#include <QJsonDocument>              // Для парсинга JSON-ответов
#include <QJsonObject>                // Для работы с JSON-объектами
#include <QDebug>                     // Для отладочного вывода
#include <QRandomGenerator>           // Для генерации случайных чисел (PKCE)
#include <QCryptographicHash>         // Для хэширования (SHA-256 для PKCE)
#include <jwt-cpp/jwt.h>              // Для декодирования JWT токенов
#include <nlohmann/json.hpp>          // Для работы с JSON (парсинг Payload)

// ===== Конструктор =====
AuthManager::AuthManager(QObject *parent)
    : QObject(parent)
{
    // Подключаем сигналы от OIDC-клиента
    connect(&oidc, &QOAuth2AuthorizationCodeFlow::granted,
            this, &AuthManager::onAuthenticationSuccess);
    connect(&oidc, &QOAuth2AuthorizationCodeFlow::error,
            this, &AuthManager::onAuthenticationError);

    // Таймер для автоматической проверки токенов (каждую минуту)
    autoRefreshTimer = new QTimer(this);
    connect(autoRefreshTimer, &QTimer::timeout,
            this, &AuthManager::checkAndRefresh);
    autoRefreshTimer->start(60000);

    m_refreshCount = 0; // Счетчик обновлений для уведомлений
}

// ===== Настройка OIDC провайдера =====
void AuthManager::setupOIDC(const QString &clientId)
{
    // Устанавливаем URL для авторизации и получения токенов
    oidc.setAuthorizationUrl(QUrl("https://a-kalinin-authoriza-backend-stand-d37a.twc1.net/oidc/auth"));
    oidc.setAccessTokenUrl(QUrl("https://a-kalinin-authoriza-backend-stand-d37a.twc1.net/oidc/token"));
    oidc.setClientIdentifier(clientId);
    oidc.setScope("openid profile email offline_access"); // Запрашиваем ID Token и Refresh Token

    // Создаём локальный HTTP-сервер на порту 8080 для получения callback
    QOAuthHttpServerReplyHandler *handler = new QOAuthHttpServerReplyHandler(8080, this);
    oidc.setReplyHandler(handler);

    // Подключаем сигнал получения callback
    connect(handler, &QOAuthHttpServerReplyHandler::callbackReceived,
            this, &AuthManager::onCallbackReceived);

    qDebug() << "OIDC настроен. Client ID:" << clientId;
}

// ===== Вход (Authorization Code Flow с PKCE) =====
void AuthManager::login()
{
    qDebug() << "=== AuthManager::login() ВЫЗВАН ===";

    // 1. Генерируем code_verifier (рандомная строка для PKCE)
    const QString possibleCharacters("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~");
    const int randomStringLength = 64;

    QString codeVerifier;
    for (int i = 0; i < randomStringLength; ++i) {
        int index = QRandomGenerator::global()->bounded(possibleCharacters.length());
        codeVerifier.append(possibleCharacters.at(index));
    }
    m_codeVerifier = codeVerifier;

    // 2. Вычисляем code_challenge (SHA-256 хэш от code_verifier, в Base64Url)
    QCryptographicHash hash(QCryptographicHash::Sha256);
    hash.addData(codeVerifier.toUtf8());
    QString codeChallenge = hash.result().toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);

    // 3. Формируем URL для авторизации с параметрами
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

    // 4. Открываем браузер для входа пользователя
    QDesktopServices::openUrl(authUrl);
}

// ===== Получен callback от OIDC провайдера =====
void AuthManager::onCallbackReceived(const QVariantMap &values)
{
    qDebug() << "=== Callback получен! ===";

    if (values.contains("code")) {
        // Извлекаем код авторизации
        QString code = values["code"].toString();
        qDebug() << "Код авторизации:" << code;
        exchangeCodeForToken(code); // Обмениваем код на токены
    } else if (values.contains("error")) {
        qDebug() << "Ошибка в callback:" << values["error"].toString();
        emit errorOccurred("Ошибка: " + values["error"].toString());
    }
}

// ===== Обмен кода на токены =====
void AuthManager::exchangeCodeForToken(const QString &code)
{
    qDebug() << "=== Обмен кода на токен ===";

    QNetworkAccessManager *nam = new QNetworkAccessManager(this);

    // Формируем POST-запрос к /token
    QUrl tokenUrl = oidc.accessTokenUrl();
    QUrlQuery query;
    query.addQueryItem("grant_type", "authorization_code");
    query.addQueryItem("code", code);
    query.addQueryItem("redirect_uri", "http://localhost:8080/");
    query.addQueryItem("client_id", oidc.clientIdentifier());
    query.addQueryItem("code_verifier", m_codeVerifier); // PKCE verifier

    QNetworkRequest request(tokenUrl);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");

    connect(nam, &QNetworkAccessManager::finished,
            [this, nam](QNetworkReply *reply) {
                if (reply->error() == QNetworkReply::NoError) {
                    QString response = QString::fromUtf8(reply->readAll());
                    qDebug() << "Ответ от токен-эндпоинта:" << response;

                    emit tokenEndpointResponseReceived(response);

                    // Парсим JSON-ответ
                    QJsonDocument doc = QJsonDocument::fromJson(response.toUtf8());
                    QJsonObject obj = doc.object();

                    if (obj.contains("access_token")) {
                        // Сохраняем токены и время истечения
                        m_accessToken = obj["access_token"].toString();
                        m_refreshToken = obj["refresh_token"].toString();
                        m_idToken = obj["id_token"].toString();
                        int expiresIn = obj["expires_in"].toInt();
                        m_expiresAt = QDateTime::currentDateTime().addSecs(expiresIn);

                        // Если refresh_expires_in не пришел, ставим 15 минут (900 сек)
                        int refreshExpiresIn = obj["refresh_expires_in"].toInt();
                        if (refreshExpiresIn == 0) {
                            refreshExpiresIn = 900;
                        }
                        m_refreshExpiresAt = QDateTime::currentDateTime().addSecs(refreshExpiresIn);

                        qDebug() << "Access Token получен!";
                        qDebug() << "Refresh Token:" << m_refreshToken;
                        qDebug() << "Refresh истекает:" << m_refreshExpiresAt.toString();
                        onAuthenticationSuccess();
                    } else {
                        qDebug() << "В ответе нет access_token!";
                    }
                } else {
                    qDebug() << "Ошибка получения токена:" << reply->errorString();
                    emit errorOccurred("Ошибка получения токена: " + reply->errorString());
                }
                reply->deleteLater();
                nam->deleteLater();
            });

    nam->post(request, query.toString().toUtf8());
}

// ===== Обновление токенов через Refresh Token =====
void AuthManager::refreshTokens()
{
    if (m_refreshToken.isEmpty()) {
        emit errorOccurred("Нет Refresh Token. Пожалуйста, войдите заново.");
        return;
    }

    QUrl tokenUrl = oidc.accessTokenUrl();
    if (tokenUrl.isEmpty()) {
        emit errorOccurred("Token URL не настроен");
        return;
    }

    qDebug() << "=== Обновление токенов через refresh_token ===";

    QNetworkAccessManager *nam = new QNetworkAccessManager(this);

    // Формируем POST-запрос с grant_type=refresh_token
    QUrlQuery query;
    query.addQueryItem("grant_type", "refresh_token");
    query.addQueryItem("refresh_token", m_refreshToken);
    query.addQueryItem("client_id", oidc.clientIdentifier());
    query.addQueryItem("client_secret", ""); // Для публичного клиента

    QNetworkRequest request(tokenUrl);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");
    request.setRawHeader("Accept", "application/json");
    request.setTransferTimeout(15000);

    connect(nam, &QNetworkAccessManager::finished,
            [this, nam](QNetworkReply *reply) {
                int httpCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
                QByteArray responseData = reply->readAll();

                qDebug() << "HTTP код ответа (refresh):" << httpCode;
                qDebug() << "Тело ответа:" << QString::fromUtf8(responseData);

                if (reply->error() == QNetworkReply::NoError) {
                    QJsonDocument doc = QJsonDocument::fromJson(responseData);
                    QJsonObject obj = doc.object();

                    if (obj.contains("access_token")) {
                        // Обновляем токены
                        m_accessToken = obj["access_token"].toString();
                        m_idToken = obj["id_token"].toString();

                        // Ротация refresh_token: если сервер выдал новый — сохраняем
                        if (obj.contains("refresh_token")) {
                            m_refreshToken = obj["refresh_token"].toString();
                            qDebug() << " Refresh Token обновлен (ротация):" << m_refreshToken;
                        } else {
                            qDebug() << " Refresh Token НЕ ПРИШЁЛ в ответе (сервер не выдал новый)";
                        }

                        int expiresIn = obj["expires_in"].toInt();
                        m_expiresAt = QDateTime::currentDateTime().addSecs(expiresIn);

                        int refreshExpiresIn = obj["refresh_expires_in"].toInt();
                        if (refreshExpiresIn == 0) {
                            refreshExpiresIn = 900;
                        }
                        m_refreshExpiresAt = QDateTime::currentDateTime().addSecs(refreshExpiresIn);

                        qDebug() << "Токены обновлены!";

                        saveSession(); // Сохраняем обновлённую сессию
                        emit tokensRefreshed();
                        emit authenticated();
                    } else {
                        qDebug() << "В ответе нет access_token!";
                        emit errorOccurred("В ответе нет access_token");
                    }
                } else {
                    // Улучшенная обработка ошибок
                    if (httpCode == 400 || httpCode == 401) {
                        qDebug() << "Refresh Token невалиден или истек!";
                        QString userMessage = "Ваша сессия истекла или токен недействителен.\n"
                                              "Пожалуйста, войдите заново.";
                        emit errorOccurred(userMessage);
                        handleSessionExpired();
                    } else if (httpCode == 0) {
                        QString userMessage = "Сервер Авторизы недоступен.\n"
                                              "Проверьте подключение к интернету и попробуйте снова.";
                        emit errorOccurred(userMessage);
                    } else {
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

// ===== Выход =====
void AuthManager::logout()
{
    // Очищаем все токены
    m_accessToken.clear();
    m_refreshToken.clear();
    m_idToken.clear();
    m_expiresAt = QDateTime();
    m_refreshExpiresAt = QDateTime();
    m_codeVerifier.clear();
    m_refreshCount = 0;

    // Очищаем сохранённые данные
    QSettings settings("MyApp", "Authoriza");
    settings.clear();

    // Открываем страницу выхода на сервере
    QUrl logoutUrl("https://a-kalinin-authoriza-backend-stand-d37a.twc1.net/oidc/session/end");
    QDesktopServices::openUrl(logoutUrl);
}

// ===== Геттеры для токенов =====
QString AuthManager::getAccessToken() const { return m_accessToken; }
QString AuthManager::getIdToken() const { return m_idToken; }
QString AuthManager::getRefreshToken() const { return m_refreshToken; }
QDateTime AuthManager::getExpirationTime() const { return m_expiresAt; }
QDateTime AuthManager::getRefreshExpirationTime() const { return m_refreshExpiresAt; }

// ===== Сохранение сессии =====
void AuthManager::saveSession()
{
    QSettings settings("MyApp", "Authoriza");
    settings.setValue("access_token", m_accessToken);
    settings.setValue("refresh_token", m_refreshToken);
    settings.setValue("id_token", m_idToken);
    settings.setValue("expires_at", m_expiresAt);
    settings.setValue("refresh_expires_at", m_refreshExpiresAt);
}

// ===== Восстановление сессии =====
void AuthManager::restoreSession()
{
    QSettings settings("MyApp", "Authoriza");
    m_refreshToken = settings.value("refresh_token").toString();
    m_idToken = settings.value("id_token").toString();

    m_expiresAt = settings.value("expires_at").toDateTime();
    m_refreshExpiresAt = settings.value("refresh_expires_at").toDateTime();

    if (!m_refreshToken.isEmpty()) {
        // Если до истечения Access Token меньше 5 минут — обновляем сразу
        if (m_expiresAt.isValid() &&
            QDateTime::currentDateTime().secsTo(m_expiresAt) <= 300) {
            qDebug() << "Токен скоро истекает, обновляем при запуске...";
            refreshTokens();
        }
        emit sessionRestored();
    }
}

// ===== Успешная аутентификация =====
void AuthManager::onAuthenticationSuccess()
{
    m_refreshCount = 0; // Сбрасываем счётчик при новом входе
    saveSession();
    emit authenticated();
}

// ===== Ошибка аутентификации =====
void AuthManager::onAuthenticationError(const QString &error)
{
    emit errorOccurred("Ошибка: " + error);
}

// ===== Периодическая проверка токенов (таймер) =====
void AuthManager::checkAndRefresh()
{
    qDebug() << "=== checkAndRefresh() ВЫЗВАН ===";

    if (m_accessToken.isEmpty()) {
        return;
    }

    if (!m_refreshExpiresAt.isValid()) {
        return;
    }

    // Проверяем время до истечения Refresh Token
    qint64 refreshSecondsLeft = QDateTime::currentDateTime().secsTo(m_refreshExpiresAt);
    qDebug() << "checkAndRefresh: refreshSecondsLeft =" << refreshSecondsLeft;

    // Если Refresh Token истек
    if (refreshSecondsLeft <= 0) {
        qDebug() << "Refresh Token истек!";
        handleSessionExpired();
        return;
    }

    // Уведомление за 2 минуты до истечения Refresh Token
    if (refreshSecondsLeft <= 120) {
        qDebug() << "Refresh Token скоро истечет (осталось" << refreshSecondsLeft << "сек)";
        emit sessionExpiring();
        QTimer::singleShot(60000, this, &AuthManager::handleSessionExpired);
        return;
    }

    // Проверяем время до истечения Access Token
    qint64 secondsLeft = QDateTime::currentDateTime().secsTo(m_expiresAt);
    qDebug() << "checkAndRefresh: secondsLeft (Access) =" << secondsLeft;

    // Обновляем Access Token, если осталось меньше 30 секунд
    if (secondsLeft <= 30 && secondsLeft > 0) {
        m_refreshCount++;
        qDebug() << "Автоматическое обновление токенов (осталось" << secondsLeft << "сек)";
        qDebug() << "Количество обновлений:" << m_refreshCount;

        // Уведомление после 2-х обновлений
        if (m_refreshCount >= 2) {
            emit sessionExpiring();
            m_refreshCount = 0;
        }

        refreshTokens();
    } else if (secondsLeft <= 0 && !m_refreshToken.isEmpty()) {
        qDebug() << "Access Token истек, обновляем...";
        refreshTokens();
    } else if (secondsLeft <= 0 && m_refreshToken.isEmpty()) {
        qDebug() << "Токен истёк, Refresh Token отсутствует";
        handleSessionExpired();
    } else {
        qDebug() << "checkAndRefresh: обновление не требуется";
    }
}

// ===== Обработка истечения сессии =====
void AuthManager::handleSessionExpired()
{
    qDebug() << "=== Сессия истекла ===";

    // Очищаем все токены
    m_accessToken.clear();
    m_refreshToken.clear();
    m_idToken.clear();
    m_expiresAt = QDateTime();
    m_refreshExpiresAt = QDateTime();
    m_refreshCount = 0;

    // Очищаем сохранённые данные
    QSettings settings("MyApp", "Authoriza");
    settings.clear();

    // Отправляем сигнал об истечении сессии
    emit sessionExpired();
}

// ===== Декодирование JWT токена =====
QString decodeJWT(const QString &token)
{
    if (token.isEmpty()) {
        return "Токен пуст";
    }

    try {
        // Декодируем JWT и извлекаем Payload
        auto decoded = jwt::decode(token.toStdString());
        auto payload = nlohmann::json::parse(decoded.get_payload());
        return QString::fromStdString(payload.dump(2)); // Форматированный JSON
    } catch (const std::exception &e) {
        return QString("Ошибка декодирования: ") + e.what();
    }
}
