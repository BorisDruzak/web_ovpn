# Тестовые SSH-черновики серверов

## Цель

Добавить в OpenVPN web-панель отдельный раздел для сохранения тестовых
серверов и безопасной проверки SSH-доступа с gateway. Черновик не является
целью collector и не изменяет его runtime-конфигурацию, timer или снимок
health-проверок.

## Границы

В scope входят:

- список, создание, повторная проверка и удаление SSH-черновиков;
- показ и скачивание только публичного observer SSH-ключа;
- получение fingerprint host key, явное подтверждение оператором и pinning;
- асинхронная проверка доступа с gateway;
- аудит действий и безопасное отображение статусов.

В scope не входят:

- выдача или отображение private key;
- пароли, произвольные SSH-команды и shell-ввод из web;
- изменение server-observer runtime-конфигурации;
- подключение черновиков к collector, systemd timer или существующему
  server-health snapshot;
- автоматическое доверие новому либо изменившемуся host key.

## Выбранная архитектура

Web-процесс не получает доступа к observer private key. Он записывает только
валидированный запрос в очередь. Отдельный systemd worker запускается как
openvpm, владеет ключом и выполняет фиксированную проверку.

    Web UI -> SQLite drafts + request queue -> openvpm worker -> SSH target
                      ^                                |
                      +--------- result queue ---------+

### Данные черновика

Для каждого черновика сохраняются: случайный UUID, отображаемое имя, host,
SSH-пользователь, порт, состояние (new, fingerprint_pending, confirmed,
checking, ok, error), pinned fingerprint, время и безопасная категория
последнего результата. Адрес и пользователь видны только в аутентифицированном
списке черновиков. Пароли, private key, raw SSH output и host key material не
попадают в audit log или browser response.

Адрес и SSH-пользователь валидируются теми же безопасными правилами, что и
server observer. Порт принимает только допустимый TCP-порт. Идентификатор
очереди — UUID, а worker повторно валидирует все поля до любого сетевого
действия.

### Public key

Веб-страница читает отдельный read-only файл с публичной частью уже
существующего observer key. Она предлагает копирование и скачивание файла
openvpm-observer.pub. Private key не монтируется, не копируется и не
доступен пользователю web-процесса.

### Проверка host key и доступа

1. Оператор создаёт черновик после размещения public key на целевом сервере.
2. Worker получает host key с gateway и возвращает только алгоритм и
   SHA-256 fingerprint как fingerprint_pending.
3. Оператор подтверждает показанный fingerprint отдельным POST с CSRF.
4. Worker сохраняет pinned host key в отдельном draft known-hosts store и
   запускает единственную allow-listed команду ssh true.
5. SSH использует BatchMode=yes, StrictHostKeyChecking=yes, отдельный
   known-hosts file, observer key и лимит 20 секунд.
6. В UI и audit записывается только ok, timeout, host_key_mismatch,
   authentication, transport либо invalid_response; raw stderr не сохраняется
   и не выводится.

Изменившийся fingerprint возвращает черновик в fingerprint_pending; старая
привязка не заменяется автоматически.

### Worker и очередь

Очередь и результаты находятся в отдельном каталоге с ограниченными
владельцем и группой правами. Web-процесс создаёт request-файл атомарно;
worker обрабатывает его через systemd path/service без sudo-вызова из
web-приложения. Worker имеет доступ только к draft queue, draft known-hosts,
observer key и result queue. Его service hardening повторяет ограничения
server-observer.service, но не получает доступ к основному collector snapshot
или web secrets.

Повторный запрос проверки для того же черновика, пока он находится в
checking, отклоняется. Worker ограничивает одну проверку 20 секундами;
обработка очереди имеет верхний лимит 3 минуты.

## Web-поверхность

Раздел /network/server-drafts требует обычную authenticated session:

- таблица с именем, host, пользователем, состоянием, fingerprint и временем
  последней проверки;
- /network/server-drafts/new — форма создания;
- публичный ключ: copy-кнопка и download endpoint;
- кнопки «Получить fingerprint», «Подтвердить fingerprint», «Проверить
  доступ», «Удалить»;
- flash-сообщения раскрывают только безопасную категорию результата.

Все изменяющие POST требуют CSRF и пишут audit record. DOM-код использует
textContent; не используется innerHTML для данных черновиков.

## Тестирование

Автоматические тесты покрывают:

- аутентификацию и CSRF всех POST;
- валидацию UUID, host, пользователя и порта;
- отсутствие private key и raw host key в ответах, audit и шаблонах;
- workflow fingerprint → explicit confirm → queued access check;
- строгую SSH-команду, 20-секундный таймаут и redaction ошибок;
- блокировку повторной проверки и обработку mismatch;
- права очереди, worker service hardening и отсутствие доступа web-процесса
  к private key;
- безопасную отрисовку списка и выдачу public key.

## Критерии готовности

Оператор может сохранить черновик, получить public key, подтвердить
fingerprint и увидеть результат ssh true с gateway. При этом ни один
черновик не влияет на collector, а private key и raw SSH output остаются
недоступны web-панели.
