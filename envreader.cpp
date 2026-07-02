#include "envreader.h"
#include <QFile>          // Работа с файлами (открытие .env файла)
#include <QTextStream>    // Чтение текста из файла (построчное чтение)
#include <QDebug>         // Отладочный вывод (предупреждения, информация о загрузке)



// Инициализация статических членов класса
QMap<QString, QString> EnvReader::m_envCache;  // Кэш переменных (ключ → значение)
bool EnvReader::m_loaded = false;              // Флаг: загружен ли .env файл



// Загрузка .env файла
QMap<QString, QString> EnvReader::loadEnvFile(const QString &filePath)
{
    QMap<QString, QString> env;   // Временный контейнер для переменных

    // Если файл уже загружен — сразу возвращаем кэш (не читаем повторно)
    if (m_loaded) {
        return m_envCache;
    }

    // Открытие файла
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        // Файл не найден — используем значения по умолчанию
        qDebug() << "Предупреждение: .env файл не найден! Используются значения по умолчанию.";
        m_loaded = true;   // Помечаем как загруженное (чтобы не пытаться снова)
        return env;        // Возвращаем пустой словарь
    }

    // Построчное чтение файла
    QTextStream stream(&file);
    while (!stream.atEnd()) {
        QString line = stream.readLine().trimmed();

        // Пропускаем пустые строки и комментарии (начинаются с #)
        if (line.isEmpty() || line.startsWith("#")) {
            continue;
        }

        // Поиск разделителя '='
        int separatorPos = line.indexOf('=');
        if (separatorPos != -1) {
            // Извлечение ключа (левая часть)
            QString key = line.left(separatorPos).trimmed();
            // Извлечение значения (правая часть)
            QString value = line.mid(separatorPos + 1).trimmed();
            // Сохранение в словарь
            env[key] = value;
        }
    }

    file.close();                     // Закрываем файл
    m_envCache = env;                 // Сохраняем в кэш
    m_loaded = true;                  // Помечаем как загруженное

    qDebug() << "Загружено" << env.size() << "переменных из .env";
    return env;
}



// Получение значения переменной
QString EnvReader::get(const QString &key, const QString &defaultValue)
{
    // Ленивая загрузка: загружаем файл только при первом обращении
    if (!m_loaded) {
        loadEnvFile();   // Загрузка .env (если не загружен)
    }

    // Поиск значения в кэше. Если ключ не найден — возвращаем defaultValue
    return m_envCache.value(key, defaultValue);
}
