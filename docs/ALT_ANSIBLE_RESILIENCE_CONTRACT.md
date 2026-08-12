# Контракт устойчивости ALT Ansible

## Инварианты

- Не создавать assignment до успешной авторитетной проверки.
- Не удалять, не сбрасывать, не перемещать и не переиспользовать AD computer
  account автоматически.
- Не выполнять automatic unjoin как способ повторной попытки.
- Не отключать TLS, проверку SSH host key, подписи пакетов, checksum или Vault.
- Не повторять неоднозначную state-changing операцию, пока не проверено
  фактическое состояние.
- Не включать в публичный результат stdout/stderr, Vault, пароли, claims,
  приватные ключи или содержимое артефактов.

## Классы ошибок

| Класс | Реакция |
| --- | --- |
| fatal_invariant | Сразу остановить. Повтор запрещён. |
| retryable_transient | Ограниченно повторить и записать число попыток. |
| ambiguous_mutation | Сначала reconciliation фактического состояния. |
| component_failure | Продолжить независимые компоненты, честно записать итог. |
| cleanup_failure | Записать отдельно; не заменять первичную ошибку. |

## Публичный результат configure

Каждый terminal configure run обязан сохранить secret-free JSON версии 1 с
полями machine_uuid, hostname, profile, status, phase, retryable, recovered,
reboot_required, error, components и verification.

Поле status принимает только successful, degraded или failed. Поле phase
принимает preflight, identity, upgrade, network, domain_join,
domain_core_verify, components или finalize. Ошибка содержит только code,
class и safe_message.

Ansible пишет результат через always/finalizer. Если playbook не был запущен,
истёк timeout или не смог создать result, контроллер атомарно сохраняет
совместимый synthetic failed result. Код выхода Ansible и status результата
должны согласовываться.

## Повторные операции

Все retries ограничены и классифицированы. Разрешены только для
распознанных временных сбоев: lock пакетного менеджера, временная ошибка
репозитория, сходимость DNS/NTP/GPO/SSSD/LDAP и startup systemd.
Ошибки подписи, checksum, архитектуры, сертификата, конфликта AD,
неверного UUID/hostname и учётных данных не повторяются.
