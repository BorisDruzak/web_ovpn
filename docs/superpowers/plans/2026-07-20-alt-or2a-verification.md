# ALT Workstation Provisioning OR-2A — verification evidence

Дата проверки: 2026-07-20.

## Проверенная версия

Временный verification workflow был запущен для branch source SHA:

```text
851d37bd427402433ca184a9c61e33f91bb029b1
```

GitHub Actions проверил pull-request merge ref:

```text
a541fbf9caec4b36363aa3eb2f1699cb5fd1dd51
```

Workflow run:

```text
29749140321
```

## Результаты

Focused OR-2A tests:

```text
35 passed in 0.35s
```

Полный ALT Linux test suite:

```text
206 passed in 1.25s
```

Полный repository test suite:

```text
427 passed, 89 warnings in 24.00s
```

Ansible syntax-check:

```text
deploy/alt-linux/ansible/playbooks/01-preflight.yml: PASS
```

При syntax-check использовался временный CI-only файл через
`ANSIBLE_VAULT_PASSWORD_FILE`. Production `ansible.cfg`, активный Vault и
controller secret files не изменялись и не читались.

Diff validation:

```text
git diff --check origin/main...HEAD: PASS
```

## Дополнительная диагностика syntax-check

Первый CI syntax-check был остановлен отсутствующим на GitHub runner файлом,
заданным production-конфигурацией:

```text
/home/altserver/.ansible-vault-pass
```

Диагностический run доказал:

```text
syntax-check из корня repository: exit 0
syntax-check из deploy/alt-linux/ansible: exit 0
```

после безопасного CI-only override `ANSIBLE_VAULT_PASSWORD_FILE`. Проблема не
была связана с YAML, `roles_path` или OR-2A sudo marker.

## Safety statement

Во время автоматической проверки:

- не выполнялись реальные SSH-подключения;
- не запускался provisioning;
- не использовался controller runtime;
- не читался активный Ansible Vault;
- не использовались реальные SSH private keys или known-host records;
- не создавались реальные jobs или assignments;
- эталонная VM не использовалась.

Тесты работали только с синтетическими diagnostics и isolated filesystem под
pytest `tmp_path`.
