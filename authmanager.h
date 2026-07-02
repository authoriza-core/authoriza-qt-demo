#ifndef AUTHMANAGER_H
#define AUTHMANAGER_H

#include <QObject>          // Базовый класс для всех объектов Qt с поддержкой сигналов/слотов
#include <QtNetworkAuth>    // OIDC-клиент (QOAuth2AuthorizationCodeFlow)
#include <QDateTime>        // Работа с датой и временем (время жизни токенов)
#include <QString>          // Работа со строками (токены, URL, Client ID)
#include <QVariantMap>      // Передача данных в callback от OIDC (ключ-значение)
#include <QTimer>           // Таймер для автоматического обновления токенов


// ============================================================
// Класс AuthManager
// Управление аутентификацией через OIDC (Authorization Code Flow + PKCE)
//
// Отвечает за:
//   - настройку OIDC-клиента (URL, Client ID, Scope)
//   - вход пользователя (генерация PKCE, открытие браузера)
//   - получение и обновление токенов (Access, ID, Refresh)
//   - сохранение и восстановление сессии (QSettings)
//   - автоматическое обновление токенов (таймер)
//   - уведомления об истечении сессии
// ============================================================

class AuthManager : public QObject
{
    Q_OBJECT   // Макрос для поддержки сигналов и слотов

public:
    // ===== Конструктор =====
    explicit AuthManager(QObject *parent = nullptr);

    // ===== Настройка OIDC =====
    void setupOIDC(const QString &clientId);   // Настройка клиента (URL, Client ID)
    void login();                               // Запуск процесса входа (открывает браузер)
    void refreshTokens();                       // Принудительное обновление токенов
    void logout();                              // Выход (очистка токенов и сессии)

    // ===== Геттеры =====
    QString getAccessToken() const;             // Возвращает Access Token
    QString getIdToken() const;                 // Возвращает ID Token
    QString getRefreshToken() const;            // Возвращает Refresh Token
    QDateTime getExpirationTime() const;        // Время истечения Access Token
    QDateTime getRefreshExpirationTime() const; // Время истечения Refresh Token

    // ===== Состояние =====
    bool isAuthenticated() const;               // Проверка: авторизован ли пользователь

    // ===== Сохранение/восстановление =====
    void saveSession();                         // Сохранение сессии в QSettings
    void restoreSession();                      // Восстановление сессии из QSettings

signals:
    // ===== Сигналы для UI =====
    void authenticated();                       // Успешная аутентификация
    void tokensRefreshed();                     // Токены успешно обновлены
    void errorOccurred(const QString &error);   // Ошибка
    void sessionRestored();                     // Сессия восстановлена
    void tokenEndpointResponseReceived(const QString &response); // Ответ от /token (для отладки)

    // ===== Уведомления о сессии =====
    void sessionExpiring();   // Сессия скоро истечет (после 2-х обновлений)
    void sessionExpired();    // Сессия истекла

private slots:
    // ===== Обработчики OIDC =====
    void onAuthenticationSuccess();                // Успешный обмен кода на токены
    void onAuthenticationError(const QString &error); // Ошибка аутентификации
    void onCallbackReceived(const QVariantMap &values); // Получен callback от OIDC
    void exchangeCodeForToken(const QString &code); // Обмен кода на токены

    // ===== Автоматическое обновление =====
    void checkAndRefresh();   // Периодическая проверка токенов (вызывается по таймеру)

private:
    // ===== OIDC-клиент =====
    QOAuth2AuthorizationCodeFlow oidc;   // Основной OIDC-клиент Qt

    // ===== Токены =====
    QString m_accessToken;               // Access Token — для доступа к API
    QString m_refreshToken;              // Refresh Token — для обновления Access Token
    QString m_idToken;                   // ID Token — содержит имя, email, sub
    QDateTime m_expiresAt;               // Время истечения Access Token
    QDateTime m_refreshExpiresAt;        // Время истечения Refresh Token
    QString m_codeVerifier;              // PKCE code_verifier (для защиты)

    // ===== Таймер и счётчик =====
    QTimer *autoRefreshTimer;            // Таймер для автоматического обновления (каждую минуту)
    int m_refreshCount;                  // Счётчик обновлений (для уведомлений)

    // ===== Вспомогательные методы =====
    void handleSessionExpired();         // Обработка истечения сессии

    // ===== Проверки состояния =====
    bool shouldRefresh() const;          // Нужно ли обновить токен? (осталось <= 30 секунд)
    bool isSessionExpired() const;       // Истекла ли сессия?
    bool isRefreshTokenAvailable() const; // Доступен ли Refresh Token?
};



// Вспомогательная функция
QString decodeJWT(const QString &token);  // Декодирование JWT и возврат Payload в виде JSON

#endif // AUTHMANAGER_H
