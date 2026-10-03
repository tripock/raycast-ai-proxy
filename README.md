# raycast-bridge

OpenAI-совместимый прокси к Raycast AI. Один файл (`server.mjs`), ноль зависимостей.
Даёт все встроенные модели Raycast (GPT, Claude, Gemini, Grok, GLM, Kimi, DeepSeek, Qwen, Perplexity — 80+ штук) любому OpenAI-клиенту — включая OMP.

## Запуск (одна команда)

```
npm start
```

или `node server.mjs`. При первом запуске мост **сам** откроет браузер для входа в аккаунт Raycast, перехватит OAuth-код (через временный HKCU-оверрайд схемы `com.raycast://`), обменяет его на токен и сохранит в `token.json` (в git не попадает). Дальше стартует сервер:

- `GET  http://127.0.0.1:8787/v1/models` — каталог (живой, без авторизации)
- `POST http://127.0.0.1:8787/v1/chat/completions` — чат (stream и обычный)
- `GET  http://127.0.0.1:8787/healthz`

Токен протух → авто-refresh (`refresh_token`); refresh не удался → повторный логин.

> Если код авторизации не перехватился за 5 минут — закрой приложение Raycast (оно могло съесть deeplink) и запусти снова.

## Подключение к OMP

`~/.omp/agent/models.yml`:

```yaml
providers:
  raycast:
    baseUrl: http://127.0.0.1:8787/v1
    auth: none
    api: openai-completions
    models:
      - id: openai-gpt-5.5
        name: GPT-5.5
        ...
```

Полный блок на все модели: `npm run models` (генерируется из живого каталога).

## Команды

| Команда | Что делает |
|---|---|
| `npm start` | логин (если надо) + сервер |
| `npm run models` | напечатать YAML-блок моделей для OMP |
| `npm run refresh` | принудительный refresh токена |
| `npm run logout` | удалить токен |

## Как это работает (реверс)

- Эндпоинт: `POST https://backend.raycast.com/api/v1/ai/chat_completions` (SSE-стрим, OpenAI-подобное тело: `{model, provider, messages, tools, buffer_id}`).
- Подпись: `X-Raycast-Signature-v2 = HMAC-SHA256(secret, rot13+5(ts '.' deviceId '.' sha256hex(body)))` — секрет статически зашит в `Raycast.dll` (`Secrets.get_SignatureSecret`).
- `X-Raycast-DeviceId = sha256(SMBIOS_UUID + Serial + "xK7mQ2vLpN8wY4jR6tBfHsAeDc" + "Production")`.
- Bearer — OAuth PKCE (S256) с родным client_id Raycast: authorize `www.raycast.com/oauth/authorize` → токен `backend.raycast.com/oauth/token`.
- Всё это выверено по `backend/index.mjs` и `Raycast.dll` версии 2.6.1.0 (MS Store).

Env-переменные: `RAYCAST_BRIDGE_PORT` (8787), `RAYCAST_DEVICE_TAG`, `RAYCAST_DEVICE_UUID`, `RAYCAST_DEVICE_SERIAL`, `RAYCAST_API`.
