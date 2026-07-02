#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>                 // Базовый класс главного окна Qt
#include <QMessageBox>                 // Для диалоговых окон (ошибки, уведомления)

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }     // Опережающее объявление UI-класса
QT_END_NAMESPACE

class AuthManager;                     // Опережающее объявление AuthManager

class MainWindow : public QMainWindow  // Главное окно приложения
{
    Q_OBJECT                           // Макрос для сигналов/слотов

public:
    explicit MainWindow(QWidget *parent = nullptr);  // Конструктор
    ~MainWindow();                                   // Деструктор

private slots:
    void onLogin();                                  // Обработчик кнопки "Login"
    void onRefresh();                                // Обработчик кнопки "Refresh"
    void onLogout();                                 // Обработчик кнопки "Logout"
    void onAuthenticated();                          // Успешная аутентификация
    void onError(const QString &error);              // Ошибка от AuthManager
    void onTokenResponseReceived(const QString &response); // Ответ от /token
    void onSessionExpiring();                        // Сессия скоро истечет
    void onSessionExpired();                         // Сессия истекла

private:
    Ui::MainWindow *ui;                 // Указатель на интерфейс (из .ui файла)
    AuthManager *authManager;           // Указатель на менеджер аутентификации

    void updateUI();                    // Обновление UI в зависимости от состояния

    // Вспомогательные методы для UI
    void populateTokens(const QString &access, const QString &id, const QString &refresh); // Заполнение полей токенами
    void updateAuthStatus(bool authenticated);          // Обновление статуса авторизации
    void clearAllFields();                              // Очистка всех полей
    void updateExpiryTime(const QDateTime &expiresAt);  // Обновление времени истечения
    void updateLastRefreshTime();                       // Обновление времени последнего обновления
    void showMessage(const QString &title, const QString &text,   // Показ сообщения
                     QMessageBox::Icon icon = QMessageBox::Information);
    bool showQuestion(const QString &title, const QString &text); // Показ вопроса (OK/Cancel)
};

#endif // MAINWINDOW_H
