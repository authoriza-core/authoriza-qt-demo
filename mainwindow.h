#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>  // Базовый класс для главного окна с меню, панелями и статусной строкой
#include <QObject>      // Базовый класс для всех объектов Qt с поддержкой сигналов/слотов

// Опережающее объявление класса UI, сгенерированного из .ui файла
QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

// Опережающее объявление класса AuthManager, чтобы не подключать заголовочный файл
class AuthManager;

// ===== Главное окно приложения =====
class MainWindow : public QMainWindow
{
    Q_OBJECT   // Макрос для поддержки сигналов и слотов

public:
    explicit MainWindow(QWidget *parent = nullptr);  // Конструктор
    ~MainWindow();                                   // Деструктор

private slots:
    // Слоты для кнопок
    void onLogin();          // Нажатие "Вход"
    void onRefresh();        // Нажатие "Обновить токены"
    void onLogout();         // Нажатие "Выход"

    // Слоты для сигналов от AuthManager
    void onAuthenticated();                          // Успешная аутентификация
    void onError(const QString &error);              // Ошибка
    void onTokenResponseReceived(const QString &response); // Ответ от /token

    // Слоты для уведомлений о сессии
    void onSessionExpiring();   // Сессия скоро истечет
    void onSessionExpired();    // Сессия истекла

private:
    Ui::MainWindow *ui;        // Указатель на интерфейс
    AuthManager *authManager;  // Указатель на менеджер аутентификации
};

#endif // MAINWINDOW_H
