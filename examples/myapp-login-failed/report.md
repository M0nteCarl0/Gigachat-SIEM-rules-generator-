# Отчёт генератора детекций

- Итог: **ГОТОВО К РЕВЬЮ**
- Движок: `wazuh`
- Правило: `100100`, уровень `10`
- Описание: MyApp: повторный неуспешный вход для пользователя $(srcuser) с $(srcip)
- Уверенность модели: 0.9
- Провайдер: `fake` (fake-deterministic)
- Промпт: `detection` v1 sha256 `8be0d3a2da69…`

## Проверки

| Проверка | Статус | Уровень | Детали |
|---|---|---|---|
| `decoder_wellformed` | ok | error | XML разобран, корневой тег совпадает |
| `rule_wellformed` | ok | error | XML разобран, корневой тег совпадает |
| `rule_id_in_range` | ok | error | id=100100, допустимый диапазон [100100; 120000) |
| `rule_id_unique` | ok | error | свободен |
| `decoded_as_matches_decoder` | ok | error | decoded_as='myapp-login', декодер='myapp-login' |
| `order_fields_allowed` | ok | error | все поля допустимы |
| `order_matches_regex_groups` | ok | error | групп захвата 2, полей в <order> 2 |
| `regex_compiles` | ok | error | регулярное выражение компилируется |
| `decoder_offset_allowed` | ok | error | offset='after_prematch' |
| `mitre_in_allowlist` | ok | error | техники подтверждены справочником |

## Прогон через движок

- Статус: `skipped`
- Детали: движок wazuh не найден в PATH: правило не проверено. Поднимите лабораторию из docker-compose.yml или укажите путь к бинарю.

## Требует ручного ревью

- нет

## Сообщения

- нет

## Обоснование модели

Префикс myapp[pid] задаёт источник, 'login_failed' — признак события, user= и src= разбираются в srcuser/srcip, attempts= поглощается без захвата.
