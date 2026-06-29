#ifndef AUTHMANAGER_H
#define AUTHMANAGER_H

#include <QObject>           // Базовый класс для объектов Qt с сигналами/слотами
#include <QtNetworkAuth>     // Модуль Qt для OAuth2/OIDC (содержит QOAuth2AuthorizationCodeFlow)
#include <QDateTime>         // Для работы с датой и временем (время жизни токенов)
#include <QString>           // Для работы со строками (токены, URL)
#include <QVariantMap>       // Для передачи данных в callback от OIDC
#include <QTimer>            // Для автоматического обновления токенов по таймеру

// ===== Класс AuthManager: управление аутентификацией через OIDC =====
// Отвечает за:
// - настройку OIDC-клиента
// - вход (Authorization Code Flow + PKCE)
// - получение и обновление токенов
// - сохранение и восстановление сессии
// - уведомления об истечении сессии
class AuthManager : public QObject
{
    Q_OBJECT   // Макрос для поддержки сигналов и слотов

public:
    explicit AuthManager(QObject *parent = nullptr);

    // Настройка OIDC (URL, Client ID, Scope)
    void setupOIDC(const QString &clientId);
    // Запуск процесса входа (открывает браузер)
    void login();
    // Обновление токенов через refresh_token
    void refreshTokens();
    // Выход (очистка токенов и сессии)
    void logout();

    // Геттеры для токенов
    QString getAccessToken() const;
    QString getIdToken() const;
    QString getRefreshToken() const;
    QDateTime getExpirationTime() const;          // Время истечения Access Token
    QDateTime getRefreshExpirationTime() const;   // Время истечения Refresh Token

    // Сохранение и восстановление сессии (через QSettings)
    void saveSession();
    void restoreSession();

signals:
    void authenticated();                         // Успешная аутентификация
    void tokensRefreshed();                       // Токены обновлены
    void errorOccurred(const QString &error);     // Ошибка
    void sessionRestored();                       // Сессия восстановлена
    void tokenEndpointResponseReceived(const QString &response); // Ответ от /token (для отладки)

    // Уведомления о состоянии сессии
    void sessionExpiring();   // Сессия скоро истечет (после 2-х обновлений)
    void sessionExpired();    // Сессия истекла

private slots:
    void onAuthenticationSuccess();               // Успешный обмен кода на токены
    void onAuthenticationError(const QString &error); // Ошибка аутентификации
    void onCallbackReceived(const QVariantMap &values); // Получен callback от OIDC
    void exchangeCodeForToken(const QString &code);     // Обмен кода на токены
    void checkAndRefresh();                       // Периодическая проверка токенов (таймер)

private:
    QOAuth2AuthorizationCodeFlow oidc;   // OIDC-клиент Qt

    // Хранилище токенов
    QString m_accessToken;               // Access Token — для доступа к API
    QString m_refreshToken;              // Refresh Token — для обновления Access Token
    QString m_idToken;                   // ID Token — содержит имя, email, sub
    QDateTime m_expiresAt;               // Время истечения Access Token
    QDateTime m_refreshExpiresAt;        // Время истечения Refresh Token
    QString m_codeVerifier;              // PKCE code_verifier (для защиты)

    QTimer *autoRefreshTimer;            // Таймер для автоматического обновления (каждую минуту)
    int m_refreshCount;                  // Счетчик обновлений (для уведомления после 2-х обновлений)

    void handleSessionExpired();         // Обработка истечения сессии
};

// ===== Вспомогательная функция =====
// Декодирует JWT и возвращает Payload в виде форматированного JSON
QString decodeJWT(const QString &token);

#endif // AUTHMANAGER_H
