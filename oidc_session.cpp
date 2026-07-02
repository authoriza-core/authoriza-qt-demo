#include "authmanager.h"                    // Заголовок AuthManager
#include <QSettings>                        // Для сохранения/восстановления сессии
#include <QDateTime>                        // Для работы с датой/временем
#include <QDebug>                           // Для отладочного вывода
#include <QDesktopServices>                 // Для открытия страницы выхода в браузере
#include <QUrl>                             // Для работы с URL
#include "envreader.h"                      // Для чтения .env файла

// Проверка аутентификации
bool AuthManager::isAuthenticated() const
{
    return !m_accessToken.isEmpty() &&                          // Access Token не пуст
           !m_refreshToken.isEmpty() &&                         // Refresh Token не пуст
           m_expiresAt.isValid() &&                             // Время истечения валидно
           QDateTime::currentDateTime() < m_expiresAt;          // Текущее время меньше времени истечения
}

// Сохранение сессии
void AuthManager::saveSession()
{
    QSettings settings("MyApp", "Authoriza");                   // Создание объекта настроек
    settings.setValue("access_token", m_accessToken);           // Сохранение Access Token
    settings.setValue("refresh_token", m_refreshToken);         // Сохранение Refresh Token
    settings.setValue("id_token", m_idToken);                   // Сохранение ID Token
    settings.setValue("expires_at", m_expiresAt);               // Сохранение времени истечения
    settings.setValue("refresh_expires_at", m_refreshExpiresAt); // Сохранение времени истечения Refresh
}

// Восстановление сессии
void AuthManager::restoreSession()
{
    QSettings settings("MyApp", "Authoriza");                   // Создание объекта настроек
    m_refreshToken = settings.value("refresh_token").toString(); // Восстановление Refresh Token
    m_idToken = settings.value("id_token").toString();           // Восстановление ID Token
    m_expiresAt = settings.value("expires_at").toDateTime();     // Восстановление времени истечения
    m_refreshExpiresAt = settings.value("refresh_expires_at").toDateTime(); // Восстановление времени истечения Refresh

    if (!m_refreshToken.isEmpty()) {                            // Если есть Refresh Token
        if (m_expiresAt.isValid() &&                            // Если время истечения валидно
            QDateTime::currentDateTime().secsTo(m_expiresAt) <= 300) { // И осталось <= 5 минут
            qDebug() << "Токен скоро истекает, обновляем при запуске...";
            refreshTokens();                                    // Обновление токенов
        }
        emit sessionRestored();                                 // Сигнал о восстановлении сессии
    }
}

// Выход
void AuthManager::logout()
{
    m_accessToken.clear();                                      // Очистка Access Token
    m_refreshToken.clear();                                     // Очистка Refresh Token
    m_idToken.clear();                                          // Очистка ID Token
    m_expiresAt = QDateTime();                                  // Сброс времени истечения
    m_refreshExpiresAt = QDateTime();                           // Сброс времени истечения Refresh
    m_codeVerifier.clear();                                     // Очистка code_verifier
    m_refreshCount = 0;                                         // Сброс счетчика обновлений

    QSettings settings("MyApp", "Authoriza");                   // Создание объекта настроек
    settings.clear();                                           // Очистка всех сохраненных данных

    // Чтение URL выхода из .env
    QString logoutUrl = EnvReader::get("AUTHORIZA_LOGOUT_URL",  // Получение URL выхода
                                       "https://oidc.authoriza.ru/oidc/session/end");
    QDesktopServices::openUrl(QUrl(logoutUrl));                 // Открытие страницы выхода в браузере
}

// Обработка истечения сессии
void AuthManager::handleSessionExpired()
{
    qDebug() << "=== Сессия истекла ===";                       // Лог

    m_accessToken.clear();                                      // Очистка Access Token
    m_refreshToken.clear();                                     // Очистка Refresh Token
    m_idToken.clear();                                          // Очистка ID Token
    m_expiresAt = QDateTime();                                  // Сброс времени истечения
    m_refreshExpiresAt = QDateTime();                           // Сброс времени истечения Refresh
    m_refreshCount = 0;                                         // Сброс счетчика обновлений

    QSettings settings("MyApp", "Authoriza");                   // Создание объекта настроек
    settings.clear();                                           // Очистка всех сохраненных данных

    emit sessionExpired();                                      // Сигнал об истечении сессии
}
