#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QObject>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class AuthManager;

// ===== Главное окно приложения =====
// Отвечает за UI и взаимодействие с AuthManager
class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    // Слоты для кнопок UI
    void onLogin();                // Нажатие кнопки "Вход"
    void onRefresh();              // Нажатие кнопки "Обновить токены"
    void onLogout();               // Нажатие кнопки "Выход"

    // Слоты для сигналов AuthManager
    void onAuthenticated();        // Успешная аутентификация
    void onError(const QString &error); // Ошибка
    void onUserInfoReceived(const QString &data); // Получены данные пользователя
    void onTokenResponseReceived(const QString &response); // Получен ответ от /token

    // Слоты для уведомлений о сессии
    void onSessionExpiring();      // Сессия скоро истечет (показываем диалог)
    void onSessionExpired();       // Сессия истекла

private:
    Ui::MainWindow *ui;
    AuthManager *authManager;
};

#endif // MAINWINDOW_H