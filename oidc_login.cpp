#include "authmanager.h"                    // Заголовок AuthManager
#include <QRandomGenerator>                 // Для генерации случайных чисел (PKCE)
#include <QCryptographicHash>               // Для хеширования (SHA256)
#include <QDesktopServices>                 // Для открытия браузера
#include <QUrlQuery>                        // Для формирования query-параметров
#include <QDebug>                           // Для отладочного вывода
#include "envreader.h"                      // Для чтения .env файла

// Вход
void AuthManager::login()
{
    qDebug() << "=== AuthManager::login() вызван ===";           // Лог

    QString codeVerifier = generateCodeVerifier();                // Генерация code_verifier
    m_codeVerifier = codeVerifier;                                // Сохранение

    QString codeChallenge = generateCodeChallenge(codeVerifier);  // Генерация code_challenge

    QUrl authUrl = buildAuthorizationUrl(codeChallenge);          // Построение URL авторизации

    qDebug() << "Открываем URL:" << authUrl.toString();
    QDesktopServices::openUrl(authUrl);                           // Открытие браузера
}

// Генерация Code_Verifier (PKCE)
QString AuthManager::generateCodeVerifier() const
{
    const QString chars("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"); // Допустимые символы
    const int length = 64;                                        // Длина code_verifier (64 символа)

    QString result;
    for (int i = 0; i < length; ++i) {
        int index = QRandomGenerator::global()->bounded(chars.length()); // Случайный индекс
        result.append(chars.at(index));                           // Добавление символа
    }
    return result;
}

// Генерация Code_Challenge (PKCE)
QString AuthManager::generateCodeChallenge(const QString &codeVerifier) const
{
    QCryptographicHash hash(QCryptographicHash::Sha256);           // SHA256
    hash.addData(codeVerifier.toUtf8());                          // Добавление данных
    QString result = hash.result().toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals); // Base64URL
    qDebug() << "code_verifier:" << codeVerifier;
    qDebug() << "code_challenge:" << result;
    return result;
}

// Построение URL авторизации
QUrl AuthManager::buildAuthorizationUrl(const QString &codeChallenge) const
{
    // Чтение redirect_uri из .env
    QString redirectUri = EnvReader::get("REDIRECT_URI", "http://localhost:8080/"); // Получение redirect_uri
    qDebug() << "redirect_uri из .env:" << redirectUri;

    QUrl authUrl = oidc.authorizationUrl();                       // Базовый URL авторизации
    QUrlQuery query;

    query.addQueryItem("client_id", oidc.clientIdentifier());     // Client ID
    query.addQueryItem("response_type", "code");                  // Тип ответа
    query.addQueryItem("redirect_uri", redirectUri);              // Redirect URI
    query.addQueryItem("scope", "openid profile email offline_access"); // Scope
    query.addQueryItem("code_challenge", codeChallenge);          // PKCE code_challenge
    query.addQueryItem("code_challenge_method", "S256");          // Метод PKCE

    authUrl.setQuery(query);                                      // Установка query-параметров
    qDebug() << "Correct URL:" << authUrl.toString();
    return authUrl;
}

// Получен Callback
void AuthManager::onCallbackReceived(const QVariantMap &values)
{
    qDebug() << "=== Callback получен! ===";                     // Лог

    if (values.contains("code")) {                                // Если получен код авторизации
        QString code = values["code"].toString();
        qDebug() << "Код авторизации:" << code;
        exchangeCodeForToken(code);                               // Обмен кода на токены
    } else if (values.contains("error")) {                       // Если получена ошибка
        qDebug() << "Ошибка в callback:" << values["error"].toString();
        emit errorOccurred("Ошибка: " + values["error"].toString());
    }
}
