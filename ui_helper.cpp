#include "mainwindow.h"                    // Заголовок главного окна
#include "ui_mainwindow.h"                 // Сгенерированный UI-класс
#include "authmanager.h"                   // Менеджер аутентификации
#include <QMessageBox>                     // Для диалоговых окон
#include <QDateTime>                       // Для работы с датой/временем
#include <QDebug>                          // Для отладочного вывода

// Получение токенов
void MainWindow::populateTokens(const QString &access, const QString &id, const QString &refresh)
{
    ui->accessTokenEdit->setPlainText(access);        // Вывод Access Token
    ui->idTokenEdit->setPlainText(id);                // Вывод ID Token
    ui->refreshTokenEdit->setPlainText(refresh);      // Вывод Refresh Token

    ui->idPayloadEdit->setPlainText(decodeJWT(id));   // Декодирование и вывод ID Token Payload
    ui->accessPayloadEdit->setPlainText(decodeJWT(access)); // Декодирование и вывод Access Token Payload
}

// Статус аутентификации
void MainWindow::updateAuthStatus(bool authenticated)
{
    if (authenticated) {
        ui->statusLabel->setText("Статус: Авторизован ✅");   // Обновление статуса
        ui->loginButton->setEnabled(false);                   // Блокировка кнопки Login
        ui->refreshButton->setEnabled(true);                  // Разблокировка Refresh
        ui->logoutButton->setEnabled(true);                   // Разблокировка Logout
    } else {
        ui->statusLabel->setText("Статус: Не авторизован ❌"); // Обновление статуса
        ui->loginButton->setEnabled(true);                    // Разблокировка Login
        ui->refreshButton->setEnabled(false);                 // Блокировка Refresh
        ui->logoutButton->setEnabled(false);                  // Блокировка Logout
    }
}

// Очистка полей
void MainWindow::clearAllFields()
{
    ui->accessTokenEdit->clear();          // Очистка Access Token
    ui->idTokenEdit->clear();              // Очистка ID Token
    ui->refreshTokenEdit->clear();         // Очистка Refresh Token
    ui->idPayloadEdit->clear();            // Очистка ID Payload
    ui->accessPayloadEdit->clear();        // Очистка Access Payload
    ui->tokenResponseEdit->clear();        // Очистка ответа от /token
    ui->accessExpiryLabel->setText("Время истечения: --");   // Сброс времени истечения
    ui->lastRefreshLabel->setText("Время обновления: --");   // Сброс времени обновления
}

// Время истечения
void MainWindow::updateExpiryTime(const QDateTime &expiresAt)
{
    if (expiresAt.isValid()) {
        ui->accessExpiryLabel->setText("Время истечения: " + expiresAt.toString()); // Показ времени
    } else {
        ui->accessExpiryLabel->setText("Время истечения: --");   // Если время невалидно
    }
}

// Время последнего обновления
void MainWindow::updateLastRefreshTime()
{
    ui->lastRefreshLabel->setText("Время обновления: " +
                                  QDateTime::currentDateTime().toString()); // Текущее время
}

// Показ сообщения
void MainWindow::showMessage(const QString &title, const QString &text,
                             QMessageBox::Icon icon)
{
    QMessageBox msgBox(icon, title, text, QMessageBox::Ok, this); // Создание диалога
    msgBox.exec();    // Отображение модального окна
}

// Показ вопроса
bool MainWindow::showQuestion(const QString &title, const QString &text)
{
    return QMessageBox::question(this, title, text,           // Показ вопроса с OK/Cancel
                                 QMessageBox::Ok | QMessageBox::Cancel)
           == QMessageBox::Ok;    // Возвращает true если нажат OK
}
