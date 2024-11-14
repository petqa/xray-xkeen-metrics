# Сборка
Собираем с помощью go, выбрав свою архитектуру процессора

```bash
GOOS=linux GOARCH=arm64 go build -o xray-xkeen-metrics
```

Далее получаем бинарный фаил перемещаем в /opt/bin entware
Скачиваем S25xrayxkeenmetrics и помещаем в /opt/etc/init.d и запускаем с помощью /opt/etc/init.d/S25xrayxkeenmetrics start

На выходе получаем метрики
curl $router_ip:2112/metrics