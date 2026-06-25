# QtAuthoriza

**Демонстрационный проект интеграции Авторизы для Qt Desktop (C++)**

Проект представляет собой desktop-приложение на Qt, демонстрирующее интеграцию с сервисом Авториза по протоколу OpenID Connect. Приложение реализует полный цикл аутентификации и работы с токенами.

---

##  Назначение проекта

Данный проект является примером интеграции Авторизы для стека **Qt Desktop (C++)**. Он демонстрирует:

- Реализацию **OpenID Connect Authorization Code Flow** с **PKCE**.
- Получение и отображение токенов (Access, ID, Refresh).
- Декодирование JWT-токенов и отображение их содержимого (Payload).
- Получение и отображение UserInfo.
- Сохранение и восстановление сессии.
- Ручное и автоматическое обновление токенов.
- Выход из приложения с очисткой сессии.

---

##  Стек технологий

| Компонент | Инструмент |
|-----------|------------|
| **Язык** | C++17 |
| **Фреймворк** | Qt 6.8.0 |
| **ОIDC клиент** | `QtNetworkAuth` (`QOAuth2AuthorizationCodeFlow`) |
| **HTTP-запросы** | `QNetworkAccessManager` |
| **Декодирование JWT** | `jwt-cpp` + `nlohmann/json` |
| **OpenSSL** | 3.3.7 (для работы с криптографией) |
| **Сборка** | CMake |
| **IDE** | Qt Creator |
| **Компилятор** | MinGW 64-bit (или MSVC 2022) |

---

##  Требования к окружению

Перед запуском убедиться, что установлены следующие компоненты:

- **Qt 6.8.0** или новее (с модулями: `Core`, `Widgets`, `Network`, `NetworkAuth`).
- **Компилятор C++17**: MinGW 64-bit (рекомендуется) или MSVC 2022.
- **CMake** 3.19 или новее (входит в состав установщика Qt).
- **OpenSSL** 3.3.x (64-bit) — для работы `jwt-cpp`.
- **Git** (опционально, для клонирования репозитория).

---

##  Установка зависимостей

### 1. Клонирование репозитория

```bash
git clone <ссылка на ваш репозиторий>
cd QtAuthoriza
```

### 2. Установка Qt

Скачать и установить Qt 6.8.0 : [https://www.rusrailsim.ru/qt6-qtcreator-ide-installation/].

При установке **обязательно** выберите компоненты:

- `Qt 6.8.0` → `MinGW 64-bit` (или `MSVC 2022 64-bit`)
- `Qt NetworkAuth`
- `Qt Network`
- `Qt Widgets`
- `CMake` и `Ninja` (в разделе Tools)

### 3. Установка OpenSSL (для jwt-cpp)

`jwt-cpp` требует OpenSSL для работы с криптографией.

1. Скачать **Win64 OpenSSL v3.3.7 EXE** с сайта:  
   [https://slproweb.com/products/Win32OpenSSL.html](https://slproweb.com/products/Win32OpenSSL.html)
2. Установить в `C:\Program Files\OpenSSL-Win64` (или запомнить выбранный путь).
3. При установке выбрать опцию **"The OpenSSL binaries (/bin) directory"**.

### 4. Подключение jwt-cpp и nlohmann/json

Библиотеки уже включены в проект (папки `jwt-cpp-master` и `json-develop`). Если их нет, скачать:

- **jwt-cpp**: [https://github.com/Thalhammer/jwt-cpp](https://github.com/Thalhammer/jwt-cpp) (папка `include`)
- **nlohmann/json**: [https://github.com/nlohmann/json](https://github.com/nlohmann/json) (файл `single_include/nlohmann/json.hpp`)


---

##  Запуск проекта

### 1. Откройте проект в Qt Creator

- Запустить **Qt Creator**.
- Нажать **«Открыть проект...»** и выбрать `CMakeLists.txt` в папке проекта.

### 2. Настройка комплекта (Kit)

Убедиться, что в **«Инструменты» → «Параметры» → «Наборы»** выбран комплект с:

- **Версия Qt**: `Qt 6.8.0 (mingw_64)` (или `msvc2022_64`)
- **Компилятор**: `MinGW 64-bit` (или `MSVC 2022`)
- **Отладчик**: `GDB` или `LLDB`

### 3. Настройка OpenSSL в CMakeLists.txt

Если OpenSSL установлен в нестандартный путь, изменить путь в `CMakeLists.txt`:

```cmake
set(OPENSSL_ROOT_DIR "C:/Program Files/OpenSSL-Win64")
```

### 4. Сборка и запуск

- Нажмите **«Собрать»** (`Ctrl+B`).
- Нажмите **«Запустить»** (`Ctrl+R`).

---

##  Настройка приложения в Авторизе

Для работы приложения необходимо зарегистрировать его в Авторизе и получить **Client ID**.

1. **Войдите** в интерфейс Авторизы.
2. **Создайте новый проект** (или откройте существующий).
3. **Создайте приложение** со следующими параметрами:

| Параметр | Значение |
|----------|----------|
| **Имя** | `Qt Desktop Demo` (любое) |
| **Тип** | `Public: Mobile, SPA, Desktop` |
| **Redirect URI** | `http://localhost:8080/` |
| **Состояние** | `ВКЛ` |

4. **Сохраните** приложение и скопируйте **Client ID**.

5. **Вставьте Client ID** в файл `mainwindow.cpp`:

```cpp
authManager->setupOIDC("16e611ef-283d-4837-9776-23e153afdd2f");
```

---

##  Проверка основных сценариев

### 1. Авторизация (Login)

- Нажмите **«Login»**.
- Откроется браузер с формой входа Авторизы.
- Введите логин и пароль.
- После входа приложение получит токены и отобразит их в интерфейсе.

**Ожидаемый результат:**
- Статус: `Авторизован `.
- Поля `Access Token`, `ID Token`, `Refresh Token` заполнены.
- Поля `Payload` содержат декодированный JSON.

### 2. Обновление токенов (Refresh)

- Нажмите **«Refresh»**.
- Токены обновятся, в поле `Token Endpoint Response` отобразится ответ сервера.

**Ожидаемый результат:**
- Статус: `Авторизован `.
- Время истечения обновлено.

### 3. Выход (Logout)

- Нажмите **«Logout»**.
- Все токены очищаются, интерфейс сбрасывается.

**Ожидаемый результат:**
- Статус: `Не авторизован `.
- Все поля очищены.

### 4. Восстановление сессии

- Закройте и снова запустите приложение.
- Сессия восстановится автоматически (если Refresh Token был сохранён).

---

##  Структура проекта

```
QtAuthoriza/
├── CMakeLists.txt          # Файл сборки CMake
├── main.cpp                 # Точка входа
├── mainwindow.h             # Заголовок главного окна
├── mainwindow.cpp           # Реализация главного окна
├── mainwindow.ui            # Визуальный интерфейс (Qt Designer)
├── authmanager.h            # Заголовок менеджера аутентификации
├── authmanager.cpp          # Реализация OIDC-клиента
├── jwt-cpp-master/          # Библиотека jwt-cpp
├── json-develop/            # Библиотека nlohmann/json
└── README.md                # Этот файл
```

---

##  Возможные проблемы и решения

| Проблема | Решение |
|----------|---------|
| **OpenSSL не найден** | Проверьте путь в `CMakeLists.txt` (`OPENSSL_ROOT_DIR`). Убедитесь, что OpenSSL установлен. |
| **Порт 8080 занят** | Закройте программы, использующие порт 8080, или измените порт в коде (`authmanager.cpp`, `QOAuthHttpServerReplyHandler`). |
| **Refresh Token не выдан** | Убедитесь, что в запросе передан `scope=offline_access` и параметр `prompt=login consent`. |
| **Ошибка декодирования JWT** | Убедитесь, что подключены `jwt-cpp` и `nlohmann/json`. Проверьте пути в `CMakeLists.txt`. |
| **Ошибка "No valid kits found"** | Настройте комплект (Kit) в Qt Creator с правильной версией Qt и компилятором. |

---

##  Полезные ссылки

- [Документация Авторизы](https://a-kalinin-authoriza-frontend-stand-a5dc.twc1.net/docs/)
- [Qt NetworkAuth Documentation](https://doc.qt.io/qt-6/qtnetworkauth-index.html)
- [jwt-cpp GitHub](https://github.com/Thalhammer/jwt-cpp)
- [nlohmann/json GitHub](https://github.com/nlohmann/json)

---

##  Автор

**Кристина**  
Проект выполнен в рамках практики по интеграции Авторизы для стека Qt Desktop (C++).

