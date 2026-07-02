#ifndef AUTHMANAGER_H
#define AUTHMANAGER_H

#include <QObject>                     // Базовый класс Qt с сигналами/слотами
#include <QtNetworkAuth>               // OIDC-клиент (QOAuth2AuthorizationCodeFlow)
#include <QDateTime>                   // Для времени жизни токенов
#include <QString>                     // Для строк (токены, URL, ID)
#include <QVariantMap>                 // Для данных из callback
#include <QTimer>                      // Для автоматического обновления
#include <QNetworkRequest>             // Для HTTP-запросов

class QNetworkReply;                   // Для обработки HTTP-ответов
class QJsonObject;                     // Для парсинга JSON

// AuthManager — управление OIDC-аутентификацией (Authorization Code Flow + PKCE)
class AuthManager : public QObject
{
    Q_OBJECT                           // Макрос для сигналов/слотов

public:
    explicit AuthManager(QObject *parent = nullptr);  // Конструктор

    void setupOIDC(const QString &clientId);          // Настройка OIDC-клиента
    void login();                                     // Запуск входа (открывает браузер)
    void refreshTokens();                             // Принудительное обновление токенов
    void logout();                                    // Выход (очистка сессии)

    QString getAccessToken() const;                   // Возвращает Access Token
    QString getIdToken() const;                       // Возвращает ID Token
    QString getRefreshToken() const;                  // Возвращает Refresh Token
    QDateTime getExpirationTime() const;              // Время истечения Access Token
    QDateTime getRefreshExpirationTime() const;       // Время истечения Refresh Token

    bool isAuthenticated() const;                     // Проверка: авторизован ли пользователь
    void saveSession();                               // Сохранение сессии в QSettings
    void restoreSession();                            // Восстановление сессии из QSettings

signals:
    void authenticated();                             // Успешная аутентификация
    void tokensRefreshed();                           // Токены обновлены
    void errorOccurred(const QString &error);         // Ошибка
    void sessionRestored();                           // Сессия восстановлена
    void tokenEndpointResponseReceived(const QString &response);  // Ответ от /token (для отладки)
    void sessionExpiring();                           // Сессия скоро истечет
    void sessionExpired();                            // Сессия истекла

private slots:
    void onAuthenticationSuccess();                   // Успешный обмен кода на токены
    void onAuthenticationError(const QString &error); // Ошибка аутентификации
    void onCallbackReceived(const QVariantMap &values); // Получен callback от OIDC
    void exchangeCodeForToken(const QString &code);   // Обмен кода на токены
    void checkAndRefresh();                           // Периодическая проверка токенов

private:
    QOAuth2AuthorizationCodeFlow oidc;                // OIDC-клиент Qt

    QString m_accessToken;                            // Access Token
    QString m_refreshToken;                           // Refresh Token
    QString m_idToken;                                // ID Token
    QDateTime m_expiresAt;                            // Время истечения Access Token
    QDateTime m_refreshExpiresAt;                     // Время истечения Refresh Token
    QString m_codeVerifier;                           // PKCE code_verifier

    QTimer *autoRefreshTimer = nullptr;               // Таймер автообновления
    int m_refreshCount = 0;                           // Счётчик обновлений

    void handleSessionExpired();                      // Обработка истечения сессии
    bool shouldRefresh() const;                       // Нужно ли обновить токен?
    bool isSessionExpired() const;                    // Истекла ли сессия?
    bool isRefreshTokenAvailable() const;             // Доступен ли Refresh Token?

    void performAutoRefresh();                        // Выполнение автообновления

    void handleTokenExchangeResponse(QNetworkReply *reply);  // Обработка ответа от /token
    void handleRefreshResponse(QNetworkReply *reply);        // Обработка ответа на обновление
    void handleRefreshError(int httpCode);                   // Обработка ошибки обновления
    void parseAndSaveTokens(const QJsonObject &obj);         // Парсинг и сохранение токенов

    QString generateCodeVerifier() const;                    // Генерация code_verifier
    QString generateCodeChallenge(const QString &codeVerifier) const; // Генерация code_challenge
    QUrl buildAuthorizationUrl(const QString &codeChallenge) const;   // Построение URL авторизации

    QNetworkRequest buildTokenExchangeRequest() const;       // Запрос для обмена кода
    QByteArray buildTokenExchangeBody(const QString &code) const; // Тело запроса обмена

    QNetworkRequest buildRefreshRequest() const;             // Запрос для обновления
    QByteArray buildRefreshBody() const;                     // Тело запроса обновления

    void sendPostRequest(const QNetworkRequest &request,     // Отправка POST-запроса
                         const QByteArray &body,
                         void (AuthManager::*handler)(QNetworkReply*));
    void cleanupReply(QNetworkReply *reply);                 // Очистка HTTP-ответа
};

QString decodeJWT(const QString &token);           // Декодирование JWT в JSON

#endif // AUTHMANAGER_H
