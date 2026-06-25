#include "authmanager.h"
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QSettings>
#include <QUrl>
#include <QDateTime>
#include <QtNetworkAuth>
#include <QDesktopServices>
#include <QUrlQuery>
#include <QJsonDocument>
#include <QJsonObject>
#include <QDebug>
#include <QRandomGenerator>
#include <QCryptographicHash>
#include <jwt-cpp/jwt.h>
#include <nlohmann/json.hpp>

// ===== Конструктор =====
// Инициализация: подключаем сигналы OIDC, настраиваем таймер автообновления
AuthManager::AuthManager(QObject *parent)
    : QObject(parent)
{
    // Сигналы от OIDC клиента
    connect(&oidc, &QOAuth2AuthorizationCodeFlow::granted,
            this, &AuthManager::onAuthenticationSuccess);
    connect(&oidc, &QOAuth2AuthorizationCodeFlow::error,
            this, &AuthManager::onAuthenticationError);

    // Таймер для проверки токенов каждую минуту
    autoRefreshTimer = new QTimer(this);
    connect(autoRefreshTimer, &QTimer::timeout,
            this, &AuthManager::checkAndRefresh);
    autoRefreshTimer->start(60000);

    m_refreshCount = 0;
}

// ===== Настройка OIDC провайдера =====
// Устанавливаем URL для авторизации, токенов, Client ID, Scope
// Создаем локальный HTTP сервер для получения callback
void AuthManager::setupOIDC(const QString &clientId)
{
    oidc.setAuthorizationUrl(QUrl("https://a-kalinin-authoriza-backend-stand-d37a.twc1.net/oidc/auth"));
    oidc.setAccessTokenUrl(QUrl("https://a-kalinin-authoriza-backend-stand-d37a.twc1.net/oidc/token"));
    oidc.setClientIdentifier(clientId);
    oidc.setScope("openid profile email offline_access");

    // Локальный сервер на порту 8080 для получения callback
    QOAuthHttpServerReplyHandler *handler = new QOAuthHttpServerReplyHandler(8080, this);
    oidc.setReplyHandler(handler);

    connect(handler, &QOAuthHttpServerReplyHandler::callbackReceived,
            this, &AuthManager::onCallbackReceived);

    qDebug() << "OIDC настроен. Client ID:" << clientId;
}

// ===== Вход =====
// Генерируем PKCE code verifier и code challenge
// Открываем URL авторизации в браузере
void AuthManager::login()
{
    qDebug() << "=== AuthManager::login() ВЫЗВАН ===";

    // Генерация code verifier (рандомная строка для PKCE)
    const QString possibleCharacters("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~");
    const int randomStringLength = 64;

    QString codeVerifier;
    for (int i = 0; i < randomStringLength; ++i) {
        int index = QRandomGenerator::global()->bounded(possibleCharacters.length());
        codeVerifier.append(possibleCharacters.at(index));
    }
    m_codeVerifier = codeVerifier;

    // Создание code challenge (SHA256 хеш от code verifier, в base64url)
    QCryptographicHash hash(QCryptographicHash::Sha256);
    hash.addData(codeVerifier.toUtf8());
    QString codeChallenge = hash.result().toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);

    // Формирование URL для авторизации с PKCE параметрами
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

    // Открытие в браузере
    QDesktopServices::openUrl(authUrl);
}

// ===== Получен callback от OIDC провайдера =====
// Извлекаем код авторизации и обмениваем его на токены
void AuthManager::onCallbackReceived(const QVariantMap &values)
{
    qDebug() << "=== Callback получен! ===";

    if (values.contains("code")) {
        QString code = values["code"].toString();
        qDebug() << "Код авторизации:" << code;
        exchangeCodeForToken(code);
    } else if (values.contains("error")) {
        qDebug() << "Ошибка в callback:" << values["error"].toString();
        emit errorOccurred("Ошибка: " + values["error"].toString());
    }
}

// ===== Обмен кода на токены =====
// Отправляем POST запрос к /token с authorization_code и PKCE verifier
void AuthManager::exchangeCodeForToken(const QString &code)
{
    qDebug() << "=== Обмен кода на токен ===";

    QNetworkAccessManager *nam = new QNetworkAccessManager(this);

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

                    QJsonDocument doc = QJsonDocument::fromJson(response.toUtf8());
                    QJsonObject obj = doc.object();

                    if (obj.contains("access_token")) {
                        // Сохранение токенов и времени истечения
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

// ===== Обновление токенов =====
// Используем refresh_token для получения новой пары токенов
// Поддерживается ротация refresh_token (сервер может выдать новый)
void AuthManager::refreshTokens()
{
    if (m_refreshToken.isEmpty()) {
        emit errorOccurred("Нет Refresh Token");
        return;
    }

    QUrl tokenUrl = oidc.accessTokenUrl();
    if (tokenUrl.isEmpty()) {
        emit errorOccurred("Token URL не настроен");
        return;
    }

    qDebug() << "=== Обновление токенов через refresh_token ===";

    QNetworkAccessManager *nam = new QNetworkAccessManager(this);

    QUrlQuery query;
    query.addQueryItem("grant_type", "refresh_token");
    query.addQueryItem("refresh_token", m_refreshToken);
    query.addQueryItem("client_id", oidc.clientIdentifier());
    query.addQueryItem("client_secret", "");

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
                        // Обновление токенов
                        m_accessToken = obj["access_token"].toString();
                        m_idToken = obj["id_token"].toString();

                        // Ротация refresh_token: если сервер выдал новый - сохраняем
                        if (obj.contains("refresh_token")) {
                            m_refreshToken = obj["refresh_token"].toString();
                            qDebug() << " Refresh Token обновлен (ротация):" << m_refreshToken;
                        } else {
                            qDebug() << " Refresh Token НЕ ПРИШЁЛ в ответе (сервер не выдал новый)";
                            // Если сервер не выдал новый, оставляем старый
                        }

                        int expiresIn = obj["expires_in"].toInt();
                        m_expiresAt = QDateTime::currentDateTime().addSecs(expiresIn);

                        int refreshExpiresIn = obj["refresh_expires_in"].toInt();
                        if (refreshExpiresIn == 0) {
                            refreshExpiresIn = 900;
                        }
                        m_refreshExpiresAt = QDateTime::currentDateTime().addSecs(refreshExpiresIn);

                        qDebug() << "Токены обновлены!";

                        saveSession(); // Сохраняем обновленную сессию
                        emit tokensRefreshed();
                        emit authenticated();
                    } else {
                        qDebug() << "В ответе нет access_token!";
                        emit errorOccurred("В ответе нет access_token");
                    }
                } else {
                    // Если получили 401/400 - refresh_token невалиден
                    if (httpCode == 401 || httpCode == 400) {
                        qDebug() << "Refresh Token невалиден или истек!";
                        handleSessionExpired();
                    } else {
                        emit errorOccurred("Ошибка обновления: " + reply->errorString() +
                                           " (HTTP " + QString::number(httpCode) + ")");
                    }
                }
                reply->deleteLater();
                nam->deleteLater();
            });

    nam->post(request, query.toString().toUtf8());
}

// ===== Выход =====
// Очищаем все токены, удаляем сохраненную сессию, открываем logout URL
void AuthManager::logout()
{
    m_accessToken.clear();
    m_refreshToken.clear();
    m_idToken.clear();
    m_expiresAt = QDateTime();
    m_refreshExpiresAt = QDateTime();
    m_codeVerifier.clear();
    m_refreshCount = 0;

    QSettings settings("MyApp", "Authoriza");
    settings.clear();

    // Открытие URL для выхода на сервере
    QUrl logoutUrl("https://a-kalinin-authoriza-backend-stand-d37a.twc1.net/oidc/session/end");
    QDesktopServices::openUrl(logoutUrl);
}

// ===== Получение информации о пользователе =====
// Запрос к /me с Access Token в заголовке Authorization
void AuthManager::fetchUserInfo()
{
    qDebug() << "=== fetchUserInfo() Вызван ===";

    if (m_accessToken.isEmpty()) {
        qDebug() << "Access Token пуст!";
        emit errorOccurred("Нет Access Token");
        return;
    }

    QUrl userInfoUrl("https://a-kalinin-authoriza-backend-stand-d37a.twc1.net/oidc/me");

    QNetworkAccessManager *nam = new QNetworkAccessManager(this);
    QNetworkRequest request(userInfoUrl);
    request.setRawHeader("Authorization", "Bearer " + m_accessToken.toUtf8());
    request.setHeader(QNetworkRequest::UserAgentHeader, "QtAuthoriza/1.0");
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

    connect(nam, &QNetworkAccessManager::finished,
            [this, nam](QNetworkReply *reply) {
                if (reply->error() == QNetworkReply::NoError) {
                    QString data = QString::fromUtf8(reply->readAll());
                    qDebug() << "=== UserInfo УСПЕШНО получен ===";
                    emit userInfoReceived(data);
                } else {
                    qDebug() << "=== Ошибка UserInfo ===";
                    emit errorOccurred("Ошибка UserInfo: " + reply->errorString());
                }
                reply->deleteLater();
                nam->deleteLater();
            });

    nam->get(request);
}

// ===== Геттеры =====
QString AuthManager::getAccessToken() const { return m_accessToken; }
QString AuthManager::getIdToken() const { return m_idToken; }
QString AuthManager::getRefreshToken() const { return m_refreshToken; }
QDateTime AuthManager::getExpirationTime() const { return m_expiresAt; }
QDateTime AuthManager::getRefreshExpirationTime() const { return m_refreshExpiresAt; }

// ===== Сохранение сессии =====
// Сохраняем токены и время истечения в QSettings
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
// Загружаем сохраненные токены. Если Access Token скоро истечет - обновляем.
void AuthManager::restoreSession()
{
    QSettings settings("MyApp", "Authoriza");
    m_refreshToken = settings.value("refresh_token").toString();
    m_idToken = settings.value("id_token").toString();

    m_expiresAt = settings.value("expires_at").toDateTime();
    m_refreshExpiresAt = settings.value("refresh_expires_at").toDateTime();

    if (!m_refreshToken.isEmpty()) {
        // Если до истечения Access Token меньше 5 минут - обновляем
        if (m_expiresAt.isValid() &&
            QDateTime::currentDateTime().secsTo(m_expiresAt) <= 300) {
            qDebug() << "Токен скоро истекает, обновляем при запуске...";
            refreshTokens();
        }
        emit sessionRestored();
    }
}

// ===== Успешная аутентификация =====
// Останавливаем локальный HTTP сервер, сохраняем сессию, генерируем сигнал
void AuthManager::onAuthenticationSuccess()
{
    // Остановка локального сервера
    if (oidc.replyHandler()) {
        QOAuthHttpServerReplyHandler *handler = qobject_cast<QOAuthHttpServerReplyHandler*>(oidc.replyHandler());
        if (handler) {
            handler->close();
            qDebug() << "Локальный сервер остановлен";
        }
    }

    m_refreshCount = 0; // Сбрасываем счетчик при новом входе

    saveSession();
    emit authenticated();
}

// ===== Обработчик ошибок аутентификации =====
void AuthManager::onAuthenticationError(const QString &error)
{
    emit errorOccurred("Ошибка: " + error);
}

// ===== Периодическая проверка токенов =====
// Вызывается каждую минуту по таймеру
// Проверяет время истечения и при необходимости обновляет токены
void AuthManager::checkAndRefresh()
{
    qDebug() << "=== checkAndRefresh() ВЫЗВАН ===";

    if (m_accessToken.isEmpty()) {
        return;
    }

    if (!m_refreshExpiresAt.isValid()) {
        return;
    }

    qint64 refreshSecondsLeft = QDateTime::currentDateTime().secsTo(m_refreshExpiresAt);
    qDebug() << "checkAndRefresh: refreshSecondsLeft =" << refreshSecondsLeft;

    // Если Refresh Token истек
    if (refreshSecondsLeft <= 0) {
        qDebug() << "Refresh Token истек!";
        handleSessionExpired();
        return;
    }

    // Если Refresh Token скоро истечет (меньше 60 секунд)
    if (refreshSecondsLeft <= 60) {
        qDebug() << "Refresh Token скоро истечет (осталось" << refreshSecondsLeft << "сек)";
        emit sessionExpiring();
        QTimer::singleShot(30000, this, &AuthManager::handleSessionExpired);
        return;
    }

    // Проверка Access Token - обновляем если осталось меньше 30 секунд
    qint64 secondsLeft = QDateTime::currentDateTime().secsTo(m_expiresAt);
    qDebug() << "checkAndRefresh: secondsLeft (Access) =" << secondsLeft;

    if (secondsLeft <= 30 && secondsLeft > 0) {
        m_refreshCount++;
        qDebug() << "Автоматическое обновление токенов (осталось" << secondsLeft << "сек)";
        qDebug() << "Количество обновлений:" << m_refreshCount;

        // После 3-х обновлений генерируем сигнал о скором истечении
        if (m_refreshCount >= 3) {
            qDebug() << "Третье обновление, скоро сессия истечет!";
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
// Очищаем все токены, удаляем сохраненную сессию, генерируем сигналы
void AuthManager::handleSessionExpired()
{
    qDebug() << "=== СЕССИЯ ИСТЕКЛА ===";

    m_accessToken.clear();
    m_refreshToken.clear();
    m_idToken.clear();
    m_expiresAt = QDateTime();
    m_refreshExpiresAt = QDateTime();
    m_refreshCount = 0;

    QSettings settings("MyApp", "Authoriza");
    settings.clear();

    emit sessionExpired();
    emit errorOccurred("Сессия истекла. Пожалуйста, войдите заново.");
}

// ===== Декодирование JWT токена =====
// Использует jwt-cpp и nlohmann/json для отображения содержимого токена
QString decodeJWT(const QString &token)
{
    if (token.isEmpty()) {
        return "Токен пуст";
    }

    try {
        auto decoded = jwt::decode(token.toStdString());
        auto payload = nlohmann::json::parse(decoded.get_payload());
        return QString::fromStdString(payload.dump(2));
    } catch (const std::exception &e) {
        return QString("Ошибка декодирования: ") + e.what();
    }
}