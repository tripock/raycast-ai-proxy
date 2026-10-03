# raycast-bridge

OpenAI-совместимый прокси к Raycast AI. Два файла логики (`server.mjs` + `extract-token.mjs`), ноль зависимостей.
Даёт все встроенные модели Raycast (GPT, Claude, Gemini, Grok, GLM, Kimi, DeepSeek, Qwen, Perplexity — 80+ штук) любому OpenAI-клиенту — включая [Oh My Pi](https://github.com/oh-my-pi) или любой другой.

## Требование

**Приложение Raycast (Windows, MS Store) должно быть установлено и залогинено в твоём аккаунте.**
Прокси сам достаёт OAuth-токен из базы данных залогиненного приложения (их же нативным аддоном, ключ базы читается из Windows Credential Manager). Никаких ручных ключей.
Хочешь юзать прокси — сначала логинься в приложение Raycast на своей машине. Точка.

## Установка и запуск

```
git clone https://github.com/tripock/raycast-ai-proxy.git
cd raycast-ai-proxy
npm start
```

Сервер поднимается на `http://127.0.0.1:8787/v1` мгновенно; токен подтянется автоматически при первом чат-запросе. Нужен Node ≥ 18.

- `GET  /v1/models` — каталог (живой, без авторизации)
- `POST /v1/chat/completions` — чат (stream и обычный, tools поддерживаются)
- `GET  /healthz`

Токен протух → refresh через `refresh_token`; не вышло → снова извлечение из базы приложения; совсем ничего → fallback на браузерный OAuth (откроет окно входа Raycast).

## Подключение к OMP

Добавь в `~/.omp/agent/models.yml`:

```yaml
providers:
  raycast:
    baseUrl: http://127.0.0.1:8787/v1
    auth: none
    api: openai-completions
    models:
      - id: openai-gpt-5.5
        name: GPT-5.5
        reasoning: true
        input: [text, image]
        contextWindow: 200000
        maxTokens: 32768
```

Полный блок на все 80+ моделей: `npm run models` (генерируется из живого каталога Raycast). Выбор модели: `omp m raycast/openai-gpt-5.5`.

## Команды

| Команда | Что делает |
|---|---|
| `npm start` | сервер (+ авто-токен при запросе) |
| `node extract-token.mjs --write` | вручную перечитать токен из приложения |
| `npm run models` | YAML-блок моделей для OMP |
| `npm run refresh` | принудительный refresh токена |
| `npm run logout` | удалить token.json |

## Как получить токен руками (если очень надо)

`token.json` в папке проекта — внутри `access_token` (`rca_…`). Это и есть bearer для `Authorization: Bearer …` к `backend.raycast.com/api/v1/ai/chat_completions`. Но одного bearer мало — запрос ещё подписывается `X-Raycast-Signature-v2` (HMAC ключ зашит в Raycast.dll), мост делает это за тебя.

## Как это работает (реверс Raycast 2.6.1.0, MS Store)

- Эндпоинт: `POST https://backend.raycast.com/api/v1/ai/chat_completions` (SSE, OpenAI-подобное тело `{model, provider, messages, tools, buffer_id}`).
- Каталог: `GET /api/v1/ai/models` — публичный, без авторизации.
- Подпись: `X-Raycast-Signature-v2 = HMAC-SHA256(secret, rot13+5(ts '.' deviceId '.' sha256hex(body)))`, секрет статичен в `Raycast.dll` (`Secrets.get_SignatureSecret`).
- `X-Raycast-DeviceId = sha256(SMBIOS_UUID + Serial + "xK7mQ2vLpN8wY4jR6tBfHsAeDc" + "Production")`.
- Токен: лежит в зашифрованной SQLite (`%LOCALAPPDATA%\Raycast`) под ключом `OAuthTokenResponse`; ключ базы — в Windows Credential Manager (`Raycast-Production/BackendDBKey`); кодек — их нативный аддон `data.win32-x64-msvc.node` (N-API). Мост при первом запуске сам находит приложение (`Get-AppxPackage Raycast`) и копирует аддон в `vendor/`.
- OAuth-параметры (fallback): client_id `FRsHICIAlyPB_…`, PKCE S256, authorize `www.raycast.com/oauth/authorize`, токен `backend.raycast.com/oauth/token`.

## Куда что кладётся

- `token.json` — токен (git-ignored)
- `device.json` — вычисленный deviceTag (git-ignored)
- `catalog-cache.json` — кэш каталога (git-ignored)
- `vendor/` — `data.win32-x64-msvc.node` из приложения (копируется автоматически, git-ignored)

Env: `RAYCAST_BRIDGE_PORT` (8787), `RAYCAST_SUPPORT_DIR`, `RAYCAST_CRED_TARGET`, `RAYCAST_BACKEND_DB_KEY`, `RAYCAST_DEVICE_TAG`, `RAYCAST_API`.

As-is, без гарантий. Обновил Raycast — удали `vendor/`, мост перекачает свежий аддон при следующем запуске.
