#include "authmanager.h"                    // Заголовок AuthManager
#include <QNetworkAccessManager>            // Для HTTP-запросов
#include <QNetworkRequest>                  // Для HTTP-запросов
#include <QNetworkReply>                    // Для HTTP-ответов
#include <QJsonDocument>                    // Для парсинга JSON
#include <QJsonObject>                      // Для работы с JSON-объектами
#include <QDebug>                           // Для отладочного вывода

void AuthManager::refreshTokens() // Обновление токенов
{
    // Проверка наличия Refresh Token
    if (m_refreshToken.isEmpty()) {                               // Если Refresh Token отсутствует
        emit errorOccurred("Нет Refresh Token. Пожалуйста, войдите заново.");
        return;
    }

    // Проверка: не истек ли Refresh Token
    if (m_refreshExpiresAt.isValid() &&                           // Если время истечения валидно
        QDateTime::currentDateTime() > m_refreshExpiresAt) {      // И текущее время больше времени истечения
        qDebug() << "Refresh Token истек!";
        handleSessionExpired();                                   // Обработка истечения сессии
        emit errorOccurred("Refresh Token истек. Пожалуйста, войдите заново.");
        return;
    }

    // Проверка: настроен ли URL
    if (oidc.accessTokenUrl().isEmpty()) {                       // Если URL токена не настроен
        emit errorOccurred("Token URL не настроен");
        return;
    }

    qDebug() << "=== Обновление токенов через refresh_token ===";
    sendPostRequest(buildRefreshRequest(), buildRefreshBody(),    // Отправка POST-запроса
                    &AuthManager::handleRefreshResponse);
}

QNetworkRequest AuthManager::buildRefreshRequest() const // Построение запроса
{
    QNetworkRequest request(oidc.accessTokenUrl());              // URL для обновления
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded"); // Тип контента
    request.setRawHeader("Accept", "application/json");           // Ожидаемый формат ответа
    request.setTransferTimeout(15000);                           // Таймаут 15 секунд
    return request;
}

QByteArray AuthManager::buildRefreshBody() const // Построение тела
{
    QUrlQuery query;
    query.addQueryItem("grant_type", "refresh_token");            // Тип гранта
    query.addQueryItem("refresh_token", m_refreshToken);          // Refresh Token
    query.addQueryItem("client_id", oidc.clientIdentifier());     // Client ID
    return query.toString().toUtf8();
}

void AuthManager::handleRefreshResponse(QNetworkReply *reply)// Обработка ответа
{
    int httpCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt(); // HTTP код
    QByteArray data = reply->readAll();                           // Чтение данных

    qDebug() << "HTTP код ответа (refresh):" << httpCode;
    qDebug() << "Тело ответа:" << QString::fromUtf8(data);

    if (reply->error() == QNetworkReply::NoError) {              // Если нет ошибки HTTP
        QJsonObject obj = QJsonDocument::fromJson(data).object(); // Парсинг JSON

        if (!obj.contains("access_token")) {                     // Если нет Access Token
            qDebug() << "В ответе нет access_token!";
            emit errorOccurred("В ответе нет access_token");
            cleanupReply(reply);                                 // Очистка
            return;
        }

        parseAndSaveTokens(obj);                                 // Парсинг и сохранение токенов
        qDebug() << "Токены обновлены!";
        saveSession();                                           // Сохранение сессии
        emit tokensRefreshed();                                  // Сигнал об обновлении
        emit authenticated();                                    // Сигнал об успешной аутентификации
    } else {
        handleRefreshError(httpCode);                            // Обработка ошибки
    }

    cleanupReply(reply);                                         // Очистка
}

void AuthManager::handleRefreshError(int httpCode)// Обработка ошибки
{
    if (httpCode == 400 || httpCode == 401) {                   // Ошибка авторизации
        qDebug() << "Refresh Token невалиден или истек!";
        emit errorOccurred("Ваша сессия истекла. Пожалуйста, войдите заново.");
        handleSessionExpired();                                  // Обработка истечения сессии
    } else if (httpCode == 0) {                                  // Сервер недоступен
        emit errorOccurred("Сервер Авторизы недоступен.");
    } else {
        emit errorOccurred("Ошибка обновления токенов (HTTP " +
                           QString::number(httpCode) + ")");     // Другая ошибка
    }
}
