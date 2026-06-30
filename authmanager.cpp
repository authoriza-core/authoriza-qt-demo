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
#include "envreader.h"

// ===== Конструктор =====
AuthManager::AuthManager(QObject *parent)
    : QObject(parent)
{
    connect(&oidc, &QOAuth2AuthorizationCodeFlow::granted,
            this, &AuthManager::onAuthenticationSuccess);
    connect(&oidc, &QOAuth2AuthorizationCodeFlow::error,
            this, &AuthManager::onAuthenticationError);

    autoRefreshTimer = new QTimer(this);
    connect(autoRefreshTimer, &QTimer::timeout,
            this, &AuthManager::checkAndRefresh);
    autoRefreshTimer->start(60000);

    m_refreshCount = 0;
}

// ===== Настройка OIDC провайдера =====
void AuthManager::setupOIDC(const QString &clientId)
{
    // ===== проверка clientId =====
    if (clientId.isEmpty()) {
        qDebug() << "Ошибка: Client ID не может быть пустым!";
        emit errorOccurred("Client ID не настроен. Проверьте .env файл.");
        return;
    }

    QString authUrl = EnvReader::get("AUTHORIZA_AUTH_URL",
                                     "https://a-kalinin-authoriza-backend-stand-d37a.twc1.net/oidc/auth");
    QString tokenUrl = EnvReader::get("AUTHORIZA_TOKEN_URL",
                                      "https://a-kalinin-authoriza-backend-stand-d37a.twc1.net/oidc/token");

    oidc.setAuthorizationUrl(QUrl(authUrl));
    oidc.setAccessTokenUrl(QUrl(tokenUrl));
    oidc.setClientIdentifier(clientId);
    oidc.setScope("openid profile email offline_access");

    QOAuthHttpServerReplyHandler *handler = new QOAuthHttpServerReplyHandler(8080, this);
    oidc.setReplyHandler(handler);

    connect(handler, &QOAuthHttpServerReplyHandler::callbackReceived,
            this, &AuthManager::onCallbackReceived);

    qDebug() << "OIDC настроен. Client ID:" << clientId;
}

// ===== Вход =====
void AuthManager::login()
{
    qDebug() << "=== AuthManager::login() вызван ===";

    const QString possibleCharacters("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~");
    const int randomStringLength = 64;

    QString codeVerifier;
    for (int i = 0; i < randomStringLength; ++i) {
        int index = QRandomGenerator::global()->bounded(possibleCharacters.length());
        codeVerifier.append(possibleCharacters.at(index));
    }
    m_codeVerifier = codeVerifier;

    QCryptographicHash hash(QCryptographicHash::Sha256);
    hash.addData(codeVerifier.toUtf8());
    QString codeChallenge = hash.result().toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);

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

    QDesktopServices::openUrl(authUrl);
}

// ===== Получен callback =====
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
void AuthManager::exchangeCodeForToken(const QString &code)
{
    qDebug() << "=== Обмен кода на токен ===";

    // ===== проверка code_verifier =====
    if (m_codeVerifier.isEmpty()) {
        qDebug() << "Ошибка: code_verifier пуст!";
        emit errorOccurred("Ошибка PKCE: code_verifier не установлен");
        return;
    }

    QNetworkAccessManager *nam = new QNetworkAccessManager(this);

    QUrl tokenUrl = oidc.accessTokenUrl();
    QUrlQuery query;
    query.addQueryItem("grant_type", "authorization_code");
    query.addQueryItem("code", code);
    query.addQueryItem("redirect_uri", "http://localhost:8080/");
    query.addQueryItem("client_id", oidc.clientIdentifier());
    query.addQueryItem("code_verifier", m_codeVerifier);

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
                        m_accessToken = obj["access_token"].toString();
                        m_refreshToken = obj["refresh_token"].toString();
                        m_idToken = obj["id_token"].toString();
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

                        qDebug() << "Access Token получен!";
                        qDebug() << "Refresh Token:" << m_refreshToken;
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
void AuthManager::refreshTokens()
{
    if (m_refreshToken.isEmpty()) {
        emit errorOccurred("Нет Refresh Token. Пожалуйста, войдите заново.");
        return;
    }

    // ===== проверка истечения Refresh Token =====
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
                        m_accessToken = obj["access_token"].toString();
                        m_idToken = obj["id_token"].toString();

                        if (obj.contains("refresh_token")) {
                            m_refreshToken = obj["refresh_token"].toString();
                            qDebug() << "Refresh Token обновлен (ротация):" << m_refreshToken;
                        } else {
                            qDebug() << "Refresh Token НЕ ПРИШЁЛ в ответе";
                        }

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
                        saveSession();
                        emit tokensRefreshed();
                        emit authenticated();
                    } else {
                        qDebug() << "В ответе нет access_token!";
                        emit errorOccurred("В ответе нет access_token");
                    }
                } else {
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
    m_accessToken.clear();
    m_refreshToken.clear();
    m_idToken.clear();
    m_expiresAt = QDateTime();
    m_refreshExpiresAt = QDateTime();
    m_codeVerifier.clear();
    m_refreshCount = 0;

    QSettings settings("MyApp", "Authoriza");
    settings.clear();

    QString logoutUrl = EnvReader::get("AUTHORIZA_LOGOUT_URL",
                                       "https://a-kalinin-authoriza-backend-stand-d37a.twc1.net/oidc/session/end");
    QDesktopServices::openUrl(QUrl(logoutUrl));
}

// ===== Геттеры =====
QString AuthManager::getAccessToken() const { return m_accessToken; }
QString AuthManager::getIdToken() const { return m_idToken; }
QString AuthManager::getRefreshToken() const { return m_refreshToken; }
QDateTime AuthManager::getExpirationTime() const { return m_expiresAt; }
QDateTime AuthManager::getRefreshExpirationTime() const { return m_refreshExpiresAt; }

// ===== isAuthenticated =====
bool AuthManager::isAuthenticated() const
{
    return !m_accessToken.isEmpty() &&
           !m_refreshToken.isEmpty() &&
           m_expiresAt.isValid() &&
           QDateTime::currentDateTime() < m_expiresAt;
}

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
    m_refreshCount = 0;
    saveSession();
    emit authenticated();
}

// ===== Ошибка аутентификации =====
void AuthManager::onAuthenticationError(const QString &error)
{
    emit errorOccurred("Ошибка: " + error);
}

// ===== Периодическая проверка токенов =====
void AuthManager::checkAndRefresh()
{
    qDebug() << "=== checkAndRefresh() ВЫЗВАН ===";

    if (m_accessToken.isEmpty()) {
        return;
    }

    if (isSessionExpired()) {
        qDebug() << "Сессия истекла (Refresh Token отсутствует)";
        handleSessionExpired();
        return;
    }

    if (shouldRefresh()) {
        m_refreshCount++;
        qDebug() << "Автоматическое обновление токенов";

        if (m_refreshCount >= 2) {
            emit sessionExpiring();
            m_refreshCount = 0;
        }

        refreshTokens();
    } else {
        qDebug() << "checkAndRefresh: обновление не требуется";
    }
}

// ===== Вспомогательные методы =====

bool AuthManager::shouldRefresh() const
{
    if (m_accessToken.isEmpty() || m_refreshToken.isEmpty()) {
        return false;
    }

    qint64 secondsLeft = QDateTime::currentDateTime().secsTo(m_expiresAt);
    return secondsLeft <= 30 && secondsLeft > 0;
}

bool AuthManager::isSessionExpired() const
{
    if (m_accessToken.isEmpty()) {
        return true;
    }

    if (m_refreshToken.isEmpty()) {
        return true;
    }

    qint64 secondsLeft = QDateTime::currentDateTime().secsTo(m_expiresAt);
    return secondsLeft <= 0;
}

bool AuthManager::isRefreshTokenAvailable() const
{
    return !m_refreshToken.isEmpty();
}

// ===== Обработка истечения сессии =====
void AuthManager::handleSessionExpired()
{
    qDebug() << "=== Сессия истекла ===";

    m_accessToken.clear();
    m_refreshToken.clear();
    m_idToken.clear();
    m_expiresAt = QDateTime();
    m_refreshExpiresAt = QDateTime();
    m_refreshCount = 0;

    QSettings settings("MyApp", "Authoriza");
    settings.clear();

    emit sessionExpired();
}

// ===== Декодирование JWT =====
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
