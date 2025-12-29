# Пример MCP-сервера

Полностью рабочий прототип MCP-сервера, доступного по HTTP (mcp-протокол поверх http). Подключается к Cursor (проверено).
Я старался следовать Security Best Practices от Anthropic, потому условно считаю, что это безопасный MCP (Model Context Protocol) сервер.
Код свалил в кучу, т.к. хотел показать реализацию решения. Тому, кто не сможет мириться с этой лапшой, предлагаю самостоятельно довести code-style до совершенства :)

В данной конкретной реализации по протоколу MCP ваш Cursor может подключится к серверу и получить текущее время. 

## Чуть больше деталей

MCP Time Server предоставляет инструмент `get_current_time` для получения текущей даты и времени в различных форматах. Сервер реализован на FastAPI и поддерживает:

- **JSON-RPC 2.0** протокол для взаимодействия с MCP-клиентами
- **HTTP транспорт** для подключения из Cursor
- **Безопасность**: Bearer token аутентификация, rate limiting, валидация входных данных
- **Контейнеризация**: Docker/Podman с read-only файловой системой
- **Мониторинг**: Health check эндпоинт

Да, можно было заюзать FastMCP, но польза этого примера в том, что можно посмотреть как это вообще работает.

## Возможности

### Инструменты

- **`get_current_time`** - Возвращает текущую дату и время в указанном формате
  - Поддерживаемые форматы: `iso`, `timestamp`, `rfc3339`, а также пользовательские strftime форматы
  - Безопасная валидация форматов для предотвращения инъекций

### Безопасность

Как писал выше, старался следовать Security Best Practices от Anthropic:

- ✅ Bearer token аутентификация (опционально)
- ✅ Rate limiting (100 запросов/минуту по умолчанию)
- ✅ Валидация и санитизация входных данных
- ✅ CORS поддержка
- ✅ Trusted Hosts проверка
- ✅ Read-only файловая система в контейнере
- ✅ Запуск от непривилегированного пользователя

Если Вас хакнули через этот сервер - я не виноват.

## Требования

- Python 3.11+
- Docker или Podman
- Docker Compose или Podman Compose

## Быстрый старт

### 1. Клонирование репозитория

```bash
git clone https://github.com/SPIDER-L33T/mcphttp_sample.git MCP-sample
cd MCP-sample
```

### 2. Настройка переменных окружения

Создайте файл `.env` в корне проекта:

```bash
# Обязательные переменные
API_KEY=your-secret-api-key-here
SECRET_KEY=your-secret-key-here

# Опциональные переменные
ENABLE_AUTH=true                    # Включить аутентификацию (по умолчанию: true)
RATE_LIMIT_PER_MINUTE=100           # Лимит запросов в минуту (по умолчанию: 100)
ALLOWED_ORIGINS=                    # Разрешенные CORS origins (через запятую)
ALLOWED_HOSTS=localhost,127.0.0.1   # Разрешенные хосты (через запятую)
ENABLE_DOCS=false                   # Включить Swagger документацию (по умолчанию: false)
ENV=production                      # Окружение: production или development
PORT=8000                           # Порт сервера (по умолчанию: 8000)
```

### 3. Запуск с Docker Compose

```bash
docker-compose up -d --build
```

### 4. Запуск с Podman Compose

```bash
podman-compose up -d --build
```

### 5. Проверка работы

```bash
# Health check
curl http://localhost:8000/health

# Проверка корневого эндпоинта
curl http://localhost:8000/
```

## Конфигурация для Cursor

Для подключения сервера к Cursor добавьте следующую конфигурацию в настройки Cursor:

```json
{
  "mcpServers": {
    "mcp-time-server": {
      "url": "http://localhost:8000/",
      "transport": "http",
      "headers": {
        "Authorization": "Bearer YOUR_API_KEY_HERE"
      }
    }
  }
}
```

Замените `YOUR_API_KEY_HERE` на значение из переменной окружения `API_KEY`.

## API Документация

### MCP JSON-RPC Эндпоинты

#### POST `/`

Основной эндпоинт для MCP JSON-RPC запросов.

**Поддерживаемые методы:**

1. **`initialize`** - Инициализация соединения
   ```json
   {
     "jsonrpc": "2.0",
     "id": 1,
     "method": "initialize",
     "params": {
       "protocolVersion": "2024-11-05",
       "capabilities": {},
       "clientInfo": {
         "name": "client-name",
         "version": "1.0.0"
       }
     }
   }
   ```

2. **`mcp/listOfferings`** - Получение информации о сервере
   ```json
   {
     "jsonrpc": "2.0",
     "id": 2,
     "method": "mcp/listOfferings"
   }
   ```

3. **`tools/list`** - Список доступных инструментов
   ```json
   {
     "jsonrpc": "2.0",
     "id": 3,
     "method": "tools/list"
   }
   ```

4. **`tools/call`** - Вызов инструмента
   ```json
   {
     "jsonrpc": "2.0",
     "id": 4,
     "method": "tools/call",
     "params": {
       "name": "get_current_time",
       "arguments": {
         "format": "iso"
       }
     }
   }
   ```

**Примеры форматов для `get_current_time`:**

- `"iso"` - ISO 8601 формат (по умолчанию): `2025-12-29T14:30:00.123456Z`
- `"timestamp"` - Unix timestamp: `1735477800.123456`
- `"rfc3339"` - RFC 3339 формат: `2025-12-29T14:30:00.123456Z`
- Пользовательские strftime форматы: `"%Y-%m-%d %H:%M:%S"`, `"%d.%m.%Y"`, и т.д.

### REST API Эндпоинты

#### GET `/health`

Проверка состояния сервера.

**Ответ:**
```json
{
  "status": "healthy",
  "timestamp": "2025-12-29T14:30:00.123456Z",
  "version": "2.0.0",
  "service": "mcp-time-server"
}
```

#### GET `/`

Корневой эндпоинт с информацией о сервере.

#### GET `/tools`

Список доступных инструментов (требует аутентификации).

#### POST `/tools/call`

Вызов инструмента (требует аутентификации).

## Примеры использования

### Использование через curl

```bash
# Инициализация
curl -X POST http://localhost:8000/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2024-11-05",
      "capabilities": {},
      "clientInfo": {"name": "test", "version": "1.0"}
    }
  }'

# Получение списка инструментов
curl -X POST http://localhost:8000/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/list"
  }'

# Вызов инструмента get_current_time
curl -X POST http://localhost:8000/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {
      "name": "get_current_time",
      "arguments": {
        "format": "iso"
      }
    }
  }'
```

### Использование через Python

```python
import requests
import json

API_KEY = "your-api-key"
BASE_URL = "http://localhost:8000"

headers = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {API_KEY}"
}

# Вызов инструмента
response = requests.post(
    f"{BASE_URL}/",
    headers=headers,
    json={
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "get_current_time",
            "arguments": {
                "format": "iso"
            }
        }
    }
)

result = response.json()
print(result["result"]["content"][0]["text"])
```

## Безопасность

### Рекомендации для продакшена

1. **Используйте сильные ключи:**
   ```bash
   # Генерация безопасного API_KEY
   openssl rand -hex 32
   
   # Генерация SECRET_KEY
   python -c "import secrets; print(secrets.token_urlsafe(32))"
   ```

2. **Включите аутентификацию:**
   ```bash
   ENABLE_AUTH=true
   ```

3. **Настройте CORS:**
   ```bash
   ALLOWED_ORIGINS=https://your-domain.com
   ```

4. **Ограничьте хосты:**
   ```bash
   ALLOWED_HOSTS=your-domain.com
   ```

5. **Используйте HTTPS** (настройте reverse proxy, например nginx)

6. **Настройте файрвол** для ограничения доступа (разрешите коннекты по порту этого сервера только для доверенных IP)

### Rate Limiting

По умолчанию установлен лимит 100 запросов в минуту на IP-адрес. При превышении лимита возвращается HTTP 429 с заголовками:

- `X-RateLimit-Limit` - максимальное количество запросов
- `X-RateLimit-Remaining` - оставшееся количество запросов
- `X-RateLimit-Reset` - время сброса лимита

## Мониторинг и логирование

### Логи

Логи выводятся в stdout и могут быть просмотрены через:

```bash
# Docker Compose
docker-compose logs -f mcp-server

# Podman Compose
podman-compose logs -f mcp-server

# Podman напрямую
podman logs -f mcp-sample_mcp-server_1
```

### Health Check

Контейнер автоматически проверяет состояние через health check эндпоинт `/health` каждые 30 секунд.

### Аудит

Все действия логируются с указанием:
- Действие (action)
- Детали запроса
- IP-адрес клиента

## Разработка

### Локальный запуск без Docker

```bash
# Установка зависимостей
pip install -r requirements.txt

# Настройка переменных окружения
export API_KEY=test-key
export SECRET_KEY=test-secret
export ENABLE_AUTH=false
export ENV=development

# Запуск сервера
python main.py
```

### Включение Swagger документации

Для разработки можно включить Swagger UI:

```bash
ENABLE_DOCS=true
```

Документация будет доступна по адресу: `http://localhost:8000/docs`

## Структура проекта

```
MCP-sample/
├── main.py              # Основной файл приложения
├── requirements.txt     # Python зависимости
├── Dockerfile          # Docker образ
├── docker-compose.yml  # Docker Compose конфигурация
├── README.md           # Документация
└── .env                # Переменные окружения (создать вручную)
```

## Устранение неполадок

### Ошибка "405 Method Not Allowed"

Убедитесь, что используете POST запрос на эндпоинт `/` для MCP JSON-RPC запросов.

### Ошибка "401 Unauthorized"

Проверьте:
- Правильность API_KEY в заголовке Authorization
- Что ENABLE_AUTH=true (или отключите для тестирования)

### Ошибка "429 Too Many Requests"

Превышен лимит запросов. Подождите минуту или увеличьте `RATE_LIMIT_PER_MINUTE`.

### Контейнер не запускается

Проверьте логи:
```bash
podman logs mcp-sample_mcp-server_1
```

Убедитесь, что:
- Порт 8000 не занят другим процессом
- Переменные окружения настроены правильно
- Docker/Podman запущен
- Руки не пахнут какашками. Если пахнут - значит растут из жопы :)

## Лицензия

Mozilla Public License Version 2.0

## Авторы

SPIDER-L33T

## Поддержка

- Пишите письма и отправляйте голубями или пневмопочтой.
- Можете отправить Фродо и Сэма пешим ходом в качестве почтовых курьеров.
