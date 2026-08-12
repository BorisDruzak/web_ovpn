# Матрица отказов ALT Ansible

| Сценарий | Класс | Ожидаемый код | Безопасное действие |
| --- | --- | --- | --- |
| apt lock освобождён в лимите | retryable_transient | recovered | Ограниченно повторить транзакцию |
| apt lock не освобождён | retryable_transient | package_manager_locked | Завершить с числом попыток |
| DNS SRV ещё не сошёлся | retryable_transient | domain_dns_unhealthy | Повторить проверки без изменения DNS |
| DNS post-check неуспешен | retryable_transient | resolver_validation_failed | Откатить изменённые файлы |
| timeout system-auth write ad | ambiguous_mutation | domain_join_outcome_unknown | Проверить join и AD trust до повтора |
| Foreign/conflicting AD computer | fatal_invariant | domain_computer_conflict | Не менять объект |
| Ошибка обязательного компонента | component_failure | component_name_failed | Продолжить независимые, итог failed |
| Ошибка optional KRFB | component_failure | component_krfb_failed | Итог degraded |
| Ошибка revoke/cleanup Endpoint | cleanup_failure | endpoint_cleanup_failed | Сохранить первичную ошибку |
| Ansible non-zero с valid result | terminal result | код из result | Контроллер читает result, не обобщает |
| Ansible timeout/нет result | terminal result | configure_execution_unavailable | Контроллер пишет synthetic result |

Для каждого сценария сохраняются только безопасные поля: фаза, класс,
attempts, retryable/recovered, код и run_id. Секреты и raw logs остаются
только в защищённой директории run.
