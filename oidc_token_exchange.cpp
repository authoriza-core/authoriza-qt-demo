#include "authmanager.h"                    // Заголовок AuthManager
#include <QNetworkAccessManager>            // Для HTTP-запросов
#include <QNetworkRequest>                  // Для HTTP-запросов
#include <QNetworkReply>                    // Для HTTP-ответов
#include <QJsonDocument>                    // Для парсинга JSON
#include <QJsonObject>                      // Для работы с JSON-объектами
#include <QDebug>                           // Для отладочного вывода
#include "envreader.h"                      // Для чтения .env файла

// Обмен кода на токены
void AuthManager::exchangeCodeForToken(const QString &code)
{
    qDebug() << "=== Обмен кода на токен ===";           // Лог

    if (m_codeVerifier.isEmpty()) {                       // Проверка code_verifier
        qDebug() << "Ошибка: code_verifier пуст!";
        emit errorOccurred("Ошибка PKCE: code_verifier не установлен");
        return;
    }

    QNetworkRequest request = buildTokenExchangeRequest(); // Построение запроса
    QByteArray body = buildTokenExchangeBody(code);       // Построение тела

    sendPostRequest(request, body, &AuthManager::handleTokenExchangeResponse); // Отправка
}

// Построение запроса
QNetworkRequest AuthManager::buildTokenExchangeRequest() const
{
    QNetworkRequest request(oidc.accessTokenUrl());       // URL для получения токена
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded"); // Тип контента
    return request;
}

// Построение тела
QByteArray AuthManager::buildTokenExchangeBody(const QString &code) const
{
    QString redirectUri = EnvReader::get("REDIRECT_URI", "http://localhost:8080/"); // Чтение redirect_uri

    QUrlQuery query;
    query.addQueryItem("grant_type", "authorization_code");   // Тип гранта
    query.addQueryItem("code", code);                         // Код авторизации
    query.addQueryItem("redirect_uri", redirectUri);          // Redirect URI
    query.addQueryItem("client_id", oidc.clientIdentifier()); // Client ID
    query.addQueryItem("code_verifier", m_codeVerifier);      // PKCE code_verifier
    return query.toString().toUtf8();
}

// Обработка ответа
void AuthManager::handleTokenExchangeResponse(QNetworkReply *reply)
{
    if (reply->error() != QNetworkReply::NoError) {           // Ошибка HTTP
        qDebug() << "Ошибка получения токена:" << reply->errorString();
        emit errorOccurred("Ошибка получения токена: " + reply->errorString());
        cleanupReply(reply);                                  // Очистка
        return;
    }

    QString response = QString::fromUtf8(reply->readAll());   // Чтение ответа
    qDebug() << "Ответ от токен-эндпоинта:" << response;
    emit tokenEndpointResponseReceived(response);             // Сигнал для отладки

    QJsonObject obj = QJsonDocument::fromJson(response.toUtf8()).object(); // Парсинг JSON

    if (!obj.contains("access_token")) {                      // Проверка наличия токена
        qDebug() << "В ответе нет access_token!";
        cleanupReply(reply);
        return;
    }

    parseAndSaveTokens(obj);                                  // Парсинг и сохранение токенов
    cleanupReply(reply);                                      // Очистка
    onAuthenticationSuccess();                                // Успешная аутентификация
}

// Парсинг токенов
void AuthManager::parseAndSaveTokens(const QJsonObject &obj)
{
    m_accessToken = obj["access_token"].toString();           // Access Token
    m_refreshToken = obj["refresh_token"].toString();         // Refresh Token
    m_idToken = obj["id_token"].toString();                   // ID Token

    int expiresIn = obj["expires_in"].toInt();                // Время жизни Access Token
    m_expiresAt = QDateTime::currentDateTime().addSecs(expiresIn); // Вычисление времени истечения

    if (obj.contains("refresh_expires_in")) {                 // Если сервер вернул время
        int refreshExpiresIn = obj["refresh_expires_in"].toInt();
        m_refreshExpiresAt = QDateTime::currentDateTime().addSecs(refreshExpiresIn);
        qDebug() << "Refresh истекает:" << m_refreshExpiresAt.toString();
    } else {
        m_refreshExpiresAt = QDateTime();                     // Неизвестно
        qDebug() << "Refresh время истечения не получено от сервера";
    }

    qDebug() << "Access Token получен!";
    qDebug() << "Refresh Token:" << m_refreshToken;
}
