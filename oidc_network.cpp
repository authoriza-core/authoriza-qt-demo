#include "authmanager.h"                    // Заголовок AuthManager
#include <QNetworkAccessManager>            // Для отправки HTTP-запросов
#include <QNetworkReply>                    // Для обработки HTTP-ответов
#include <QDebug>                           // Для отладочного вывода

// Отправка POST-запроса с обработчиком
void AuthManager::sendPostRequest(const QNetworkRequest &request,
                                  const QByteArray &body,
                                  void (AuthManager::*handler)(QNetworkReply*))
{
    QNetworkAccessManager *nam = new QNetworkAccessManager(this); // Создание менеджера HTTP
    connect(nam, &QNetworkAccessManager::finished, this, handler); // Подключение обработчика
    nam->post(request, body);                                     // Отправка POST-запроса
}

// Очистка ответа
void AuthManager::cleanupReply(QNetworkReply *reply)
{
    reply->deleteLater();                  // Удаление объекта ответа
    reply->parent()->deleteLater();        // Удаление родителя (QNetworkAccessManager)
}
