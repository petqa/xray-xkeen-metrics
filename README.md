# Сборка
Собираем с помощью go, выбрав свою архитектуру процессора

```bash
GOOS=linux GOARCH=arm64 go build -o xray-xkeen-metrics
```

Далее получаем бинарный фаил перемещаем в /opt/sbin entware

S25xrayxkeenmetrics помещаем в /opt/etc/init.d и запускаем с помощью /opt/etc/init.d/S25xrayxkeenmetrics start

### Метрики

```bash
curl $router_ip:2112/metrics
...
connections_accepted_total{dest_ip="1.1.1.1",dest_port="443",from="redirect",protocol="tcp",source_ip="192.168.0.1",to="vless"} 3
...
```

### Проверка статуса

```bash
curl $router_ip:2112/status
Status:   Прокси-клиент запущен
```

### Проверка статуса

```bash
curl --cookie "AuthToken=qwerty12345" $router_ip:2112/restart
```

### Пулл изменений

```bash
curl --cookie "AuthToken=qwerty12345" $router_ip:2112/pull
Initiating git pull...
Git pull executed successfully. Output: Already up to date.
```