#include "envreader.h"
#include <QFile>
#include <QTextStream>
#include <QDebug>

// Инициализация статических членов
QMap<QString, QString> EnvReader::m_envCache;
bool EnvReader::m_loaded = false;

QMap<QString, QString> EnvReader::loadEnvFile(const QString &filePath)
{
    QMap<QString, QString> env;

    // Если файл уже загружен, возвращаем кэш
    if (m_loaded) {
        return m_envCache;
    }

    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        qDebug() << " Предупреждение: .env файл не найден! Используются значения по умолчанию.";
        m_loaded = true;
        return env;
    }

    QTextStream stream(&file);
    while (!stream.atEnd()) {
        QString line = stream.readLine().trimmed();

        // Пропускаем пустые строки и комментарии
        if (line.isEmpty() || line.startsWith("#")) {
            continue;
        }

        // Ищем разделитель '='
        int separatorPos = line.indexOf('=');
        if (separatorPos != -1) {
            QString key = line.left(separatorPos).trimmed();
            QString value = line.mid(separatorPos + 1).trimmed();
            env[key] = value;
        }
    }

    file.close();
    m_envCache = env;
    m_loaded = true;

    qDebug() << "Загружено" << env.size() << "переменных из .env";
    return env;
}

QString EnvReader::get(const QString &key, const QString &defaultValue)
{
    // Загружаем файл, если ещё не загружен
    if (!m_loaded) {
        loadEnvFile();
    }

    return m_envCache.value(key, defaultValue);
}
