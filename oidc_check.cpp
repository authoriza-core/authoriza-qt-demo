#include "authmanager.h"                    // Заголовок AuthManager
#include <QDateTime>                        // Для работы с датой/временем
#include <QDebug>                           // Для отладочного вывода

// Периодическая проверка токенов
void AuthManager::checkAndRefresh()
{
    qDebug() << "=== checkAndRefresh() вызван ===";           // Лог

    if (m_accessToken.isEmpty()) {                            // Если нет Access Token - выходим
        return;
    }

    if (isSessionExpired()) {                                 // Если сессия истекла
        qDebug() << "Сессия истекла (Refresh Token отсутствует)";
        handleSessionExpired();                               // Обработка истечения
        return;
    }

    if (shouldRefresh()) {                                    // Если нужно обновить
        performAutoRefresh();                                 // Выполнение автообновления
    } else {
        qDebug() << "checkAndRefresh: обновление не требуется";
    }
}

// Выполнение автоматического обновления
void AuthManager::performAutoRefresh()
{
    m_refreshCount++;                                         // Увеличение счетчика обновлений
    qDebug() << "Автоматическое обновление токенов (№" << m_refreshCount << ")";

    if (m_refreshCount >= 2) {                                // Если достигнут лимит (2 обновления)
        qDebug() << "Достигнут лимит обновлений, отправляем уведомление";
        emit sessionExpiring();                               // Сигнал о скором истечении сессии
        m_refreshCount = 0;                                   // Сброс счетчика
    }

    refreshTokens();                                          // Обновление токенов
}

// Проверка: нужно ли обновить токен
bool AuthManager::shouldRefresh() const
{
    if (m_accessToken.isEmpty() || m_refreshToken.isEmpty()) { // Если нет токенов
        return false;
    }

    qint64 secondsLeft = QDateTime::currentDateTime().secsTo(m_expiresAt); // Осталось секунд до истечения
    return secondsLeft <= 30 && secondsLeft > 0;              // Обновлять если осталось <= 30 секунд
}

// Проверка: истекла ли сессия
bool AuthManager::isSessionExpired() const
{
    if (m_accessToken.isEmpty() || m_refreshToken.isEmpty()) { // Если нет токенов
        return true;
    }

    qint64 secondsLeft = QDateTime::currentDateTime().secsTo(m_expiresAt); // Осталось секунд до истечения
    return secondsLeft <= 0;                                  // Истекла если осталось <= 0 секунд
}

// Проверка: доступен ли Refresh Token
bool AuthManager::isRefreshTokenAvailable() const
{
    return !m_refreshToken.isEmpty();                         // Возвращает true если Refresh Token не пуст
}
