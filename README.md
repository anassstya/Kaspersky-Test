# Information Exchange Service

REST API для обмена информацией об угрозах, идентифицируемых по MD5-хешу файла. Проект реализован на Go с PostgreSQL (Supabase); API описан в OpenAPI.

## Возможности

| Метод | Путь | Описание |
| --- | --- | --- |
| `POST` | `/info` | Создать запись об угрозе |
| `GET` | `/info/{md5}` | Получить информацию по MD5 |
| `PUT` | `/info/{md5}` | Обновить существующую запись |

Модель включает MD5, название, тип и уровень угрозы, статус проверки, описание, источник и даты первого обнаружения, создания и обновления. Валидация реализована в сервисном слое и частично дублируется ограничениями PostgreSQL (`PRIMARY KEY`, `NOT NULL`, `CHECK`). MD5 нормализуется в нижний регистр.

## Стек

- Go 
- PostgreSQL в Supabase
- Docker / Docker Compose
- Swagger UI, OpenAPI 3.0


## Настройка базы данных

Для работы сервиса используется PostgreSQL, размещённая в Supabase. База данных уже создана, таблица `threats` инициализируется SQL-миграцией.

Для локального запуска необходимо:

1. Создать файл `.env` в корне проекта на основе `.env.example`.
2. Указать в нём строку подключения к PostgreSQL:

   ```dotenv
   DATABASE_URL=postgresql://USER:PASSWORD@HOST:5432/postgres?sslmode=require
   ```
3. Получить параметры подключения (в архиве в файл добавлю).
4. Запустить приложение:

   ```bash
   docker compose up -d --build
   ```

После запуска REST API доступен на `http://localhost:8080`, Swagger UI на `http://localhost:8081`.


## Тестирование

### Unit-тесты

```bash
go test ./service -v
```

### Интеграционные тесты

```bash
set -a
source .env
set +a

go test ./test -v
```


## OpenAPI и кодогенерация

Контракт API находится в `api/openapi.yml`. **В текущей реализации Go-модели, HTTP-обработчики и слой сервиса написаны вручную, без кодогенерации.** 

Можно было использовать [`oapi-codegen`](https://github.com/oapi-codegen/oapi-codegen)
