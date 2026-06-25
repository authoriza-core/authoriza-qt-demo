#ifndef AUTHMANAGER_H
#define AUTHMANAGER_H

#include <QObject>
#include <QtNetworkAuth>
#include <QDateTime>
#include <QString>
#include <QVariantMap>
#include <QTimer>

// Класс для управления аутентификацией через OIDC
// Отвечает за: вход, обновление токенов, выход, хранение сессии
class AuthManager : public QObject
{
    Q_OBJECT

public:
    explicit AuthManager(QObject *parent = nullptr);

    // Настройка OIDC провайдера
    void setupOIDC(const QString &clientId);
    // Запуск процесса входа (открывает браузер)
    void login();
    // Обновление токенов через refresh_token
    void refreshTokens();
    // Выход из системы
    void logout();
    // Получение информации о пользователе
    void fetchUserInfo();

    // Геттеры для токенов
    QString getAccessToken() const;
    QString getIdToken() const;
    QString getRefreshToken() const;
    QDateTime getExpirationTime() const;
    QDateTime getRefreshExpirationTime() const;

    // Сохранение/восстановление сессии (через QSettings)
    void saveSession();
    void restoreSession();

signals:
    void authenticated();                // Успешная аутентификация
    void tokensRefreshed();              // Токены обновлены
    void userInfoReceived(const QString &data); // Получены данные пользователя
    void errorOccurred(const QString &error);   // Ошибка
    void sessionRestored();              // Сессия восстановлена
    void tokenEndpointResponseReceived(const QString &response); // Отладка

    // Сигналы для уведомлений пользователя
    void sessionExpiring();   // Сессия скоро истечет
    void sessionExpired();    // Сессия истекла

private slots:
    void onAuthenticationSuccess();      // Обработчик успешной аутентификации
    void onAuthenticationError(const QString &error); // Обработчик ошибки
    void onCallbackReceived(const QVariantMap &values); // Получен callback от OIDC
    void exchangeCodeForToken(const QString &code);     // Обмен кода на токен
    void checkAndRefresh();              // Проверка и обновление токенов (таймер)

private:
    QOAuth2AuthorizationCodeFlow oidc;   // OIDC клиент Qt

    // Хранимые токены
    QString m_accessToken;
    QString m_refreshToken;
    QString m_idToken;
    QDateTime m_expiresAt;               // Время истечения Access Token
    QDateTime m_refreshExpiresAt;        // Время истечения Refresh Token
    QString m_codeVerifier;              // PKCE code verifier

    QTimer *autoRefreshTimer;            // Таймер для автоматического обновления

    int m_refreshCount; // Счетчик обновлений для уведомлений (после 3-х обновлений сессия скоро истечет)

    void handleSessionExpired();         // Обработка истечения сессии
};

// Вспомогательная функция для декодирования JWT токена
QString decodeJWT(const QString &token);

#endif // AUTHMANAGER_H