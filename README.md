# hy-panel

Минимальная панель пользователей для Hysteria 2 в духе wg-easy: один статический бинарник (~7 МБ), JSON-файл вместо БД, без Docker. Работает рядом с официальным `hysteria-server`: не запускает Hysteria и не трогает его конфиг.

Требования: Hysteria ≥ 2.4.4 (`/online` в trafficStats), Linux amd64/arm64.

## Что взято из H-UI, Blitz и s-ui и что сделано иначе

| Механизм | У них | Здесь |
|---|---|---|
| Авторизация | H-UI, Blitz: HTTP-auth бэкенд, без перезапуска Hysteria | так же; `/auth` только с loopback, запросы с proxy-заголовками отклоняются |
| Учёт трафика | H-UI (30 с), Blitz (1 мин): `/traffic?clear=1` и накопление в БД | так же, раз в 10 с; трафик учитывается, даже если `/online` вернул ошибку |
| Отключение заблокированных | H-UI кикает каждые 30 с, пока юзер онлайн; Blitz кикает при любой правке, даже офлайн-юзера | kick в Hysteria одноразовый и не истекает: висящий флаг убивает следующую легальную сессию. Здесь kick уходит только онлайн-юзеру и только после того, как предыдущий сработал |
| Смена пароля | Blitz: kick при любой правке | «Новый ключ» (пароль + ссылка подписки) рвёт старые сессии, без висящих флагов |
| Лимит устройств | H-UI: по `/online` при auth | так же |
| Формат входа | Blitz: `user:pass` | `user:pass` (имя без учёта регистра, как в userpass Hysteria) или голый пароль: старые клиенты на `auth.type: password` работают |
| Сертификат | Blitz хранит `pinSHA256` в своём конфиге | pin считается из `tls.cert`, только для self-signed (LE-сертификат ротируется, pin бы сломался). SNI берётся из DNS SAN: дефолтный `sniGuard: dns-san` в Hysteria рвёт рукопожатие без него |
| Подписка | s-ui, H-UI: `Subscription-Userinfo`, `Profile-Title` | так же; base64-URI, для mihomo/clash по UA — YAML. Живёт на отдельном порту, остальная панель не торчит наружу |
| Ежемесячный сброс | H-UI: cron на всех | флаг на пользователя, 1-го числа по времени сервера |

Не взято: управление процессом и конфигом Hysteria, ACME, MongoDB/SQLite, Telegram-бот, мульти-ноды, WARP, лимит по IP через iptables (Blitz).

Проверено: e2e с Hysteria 2.13 (официальный клиент, legacy-клиент, sniGuard, лимит устройств, kick, новый ключ, падение trafficStats) и mihomo 1.19.32 (сниппет, proxy-provider, base64-подписка, неверный pin отклоняется). `go test -race ./...` включает модель KickMap/OnlineMap Hysteria.

## Установка

```bash
# 1. Бинарник из Releases (amd64 или arm64) или собранный из исходников, см. «Сборка»
install -m755 hy-panel-linux-amd64 /usr/local/bin/hy-panel

# 2. Пароль панели (обязателен)
echo "HYP_PASSWORD=$(openssl rand -base64 18)" > /etc/hy-panel.env && chmod 600 /etc/hy-panel.env

# 3. Юнит: поправь -host (публичный IP или домен) и -name
cp hy-panel.service /etc/systemd/system/ && systemctl daemon-reload
systemctl enable --now hy-panel
journalctl -u hy-panel -n 5
#   imported auth.password as user 'default' — existing clients keep working
#   links: 1.2.3.4:8443 sni="bing.com" obfs="salamander" pinned=true
```

Первый запуск делай до правки конфига Hysteria: панель импортирует `auth.password` (как пользователя `default`) или `auth.userpass`.

```yaml
# 4. /etc/hysteria/config.yaml: заменить auth и добавить trafficStats
auth:
  type: http
  http:
    url: http://127.0.0.1:8090/auth
trafficStats:
  listen: 127.0.0.1:25413
  secret: <openssl rand -hex 16>
```

```bash
systemctl restart hy-panel hysteria-server
```

## Доступ

Панель слушает `127.0.0.1:8090`:

```bash
ssh -L 8090:127.0.0.1:8090 evo@vps   # → http://localhost:8090
```

Подписки включаются отдельным портом, на нём есть только `/sub/<token>`:

```
-sub-listen :2096                         # ссылка: http://<host>:2096/sub/...
-sub-listen 127.0.0.1:2096 -sub-url https://vpn.example.com   # за reverse-proxy с TLS
```

По голому HTTP содержимое подписки (сервер, obfs-пароль, ключ) видно провайдеру и DPI. Без домена и TLS лучше раздавать QR и ссылки, а подписку не включать.

## Флаги

```
-listen      127.0.0.1:8090                UI, API, /auth для Hysteria
-sub-listen  (выкл)                        публичный порт подписок
-sub-url     http://<host>:<sub-port>      внешний адрес подписок
-hy-config   /etc/hysteria/config.yaml
-data        /var/lib/hy-panel/users.json
-host        из acme / DNS SAN сертификата  публичный IP или домен в ссылках
-port        из listen                     порт или диапазон port hopping (20000-50000)
-sni         из acme / DNS SAN сертификата
-name        префикс профиля в клиентах
-interval    10s                           синхронизация трафика
env HYP_PASSWORD                           пароль панели, ≥8 символов
```

## Поведение и ограничения

- Если панель лежит, новые подключения не авторизуются. Активные сессии продолжают работать. Юнит стоит с `Restart=always`.
- Конфиг Hysteria читается при старте. После смены порта, obfs или сертификата перезапусти `hy-panel`.
- Kick срабатывает на следующем пакете сессии. Молчащая сессия заблокированного пользователя висит онлайн, но первый же её пакет её закроет. Если включить пользователя раньше, она закроется один раз, и клиент переподключится.
- Лимит устройств считает сессии. После смены сети у телефона старая сессия держится до таймаута простоя (30 с), поэтому телефону ставь ≥2.
- Квота и срок проверяются при подключении и раз в 10 с: превышение возможно на объём трафика за 10 с.
- Имя пользователя служит ID в статистике Hysteria, поэтому переименования нет.
- `users.json` — это вся база и бэкап, права 0600: в файле пароли.

## Сборка

Go ≥ 1.22, без cgo:

```bash
go test -race ./...
CGO_ENABLED=0 GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o hy-panel-linux-amd64 .
```

Файлы: `main.go` (HTTP, auth, синхронизация и kick), `store.go` (пользователи, `users.json`), `hy.go` (конфиг Hysteria, сертификат, клиент trafficStats), `links.go` (ссылки, mihomo), `index.html` (UI, вшит в бинарник).
