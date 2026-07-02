#ifndef ENVREADER_H
#define ENVREADER_H

#include <QString>   // Работа со строками (ключи и значения переменных окружения)
#include <QMap>      // Ассоциативный контейнер ключ-значение (хранение переменных из .env)

// Класс для чтения переменных из .env файла
class EnvReader
{
public:
    // Загружает .env файл и возвращает карту переменных
    static QMap<QString, QString> loadEnvFile(const QString &filePath = ".env");

    // Получает значение переменной из .env
    // Если переменная не найдена, возвращает defaultValue
    static QString get(const QString &key, const QString &defaultValue = "");

private:
    static QMap<QString, QString> m_envCache; // Кэш переменных
    static bool m_loaded;                     // Флаг загрузки
};

#endif // ENVREADER_H
