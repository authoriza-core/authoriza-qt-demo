#include "authmanager.h"                    // Заголовок AuthManager
#include <QDebug>                           // Для отладочного вывода

// Успешная аутентификация
void AuthManager::onAuthenticationSuccess()
{
    m_refreshCount = 0;                                     // Сброс счетчика обновлений
    saveSession();                                          // Сохранение сессии
    emit authenticated();                                   // Сигнал об успешной аутентификации
}

// Ошибка аутентификации
void AuthManager::onAuthenticationError(const QString &error)
{
    emit errorOccurred("Ошибка: " + error);                 // Сигнал об ошибке
}
