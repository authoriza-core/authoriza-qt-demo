#ifndef AUTHMANAGER_H
#define AUTHMANAGER_H

#include <QObject>
#include <QtNetworkAuth>
#include <QDateTime>
#include <QString>
#include <QVariantMap>
#include <QTimer>

class AuthManager : public QObject
{
    Q_OBJECT

public:
    explicit AuthManager(QObject *parent = nullptr);

    // Настройка OIDC
    void setupOIDC(const QString &clientId);
    void login();
    void refreshTokens();
    void logout();

    // Геттеры
    QString getAccessToken() const;
    QString getIdToken() const;
    QString getRefreshToken() const;
    QDateTime getExpirationTime() const;
    QDateTime getRefreshExpirationTime() const;

    // Состояние
    bool isAuthenticated() const;

    // Сохранение/восстановление
    void saveSession();
    void restoreSession();

signals:
    void authenticated();
    void tokensRefreshed();
    void errorOccurred(const QString &error);
    void sessionRestored();
    void tokenEndpointResponseReceived(const QString &response);

    void sessionExpiring();
    void sessionExpired();

private slots:
    void onAuthenticationSuccess();
    void onAuthenticationError(const QString &error);
    void onCallbackReceived(const QVariantMap &values);
    void exchangeCodeForToken(const QString &code);
    void checkAndRefresh();

private:
    // OIDC клиент
    QOAuth2AuthorizationCodeFlow oidc;

    // Токены
    QString m_accessToken;
    QString m_refreshToken;
    QString m_idToken;
    QDateTime m_expiresAt;
    QDateTime m_refreshExpiresAt;
    QString m_codeVerifier;

    // Таймер и счётчик
    QTimer *autoRefreshTimer;
    int m_refreshCount;

    // Вспомогательные методы
    void handleSessionExpired();

    // ===== Проверки состояния =====
    bool shouldRefresh() const;
    bool isSessionExpired() const;
    bool isRefreshTokenAvailable() const;
};

// Вспомогательная функция
QString decodeJWT(const QString &token);

#endif // AUTHMANAGER_H
