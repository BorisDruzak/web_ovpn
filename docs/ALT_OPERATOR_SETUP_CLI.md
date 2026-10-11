# ALT Workstation: операторский AD Setup CLI V1

CLI настраивает уже установленную ALT Workstation для существующего сотрудника AD. Оператор работает в терминале контроллера без Codex. ISO/PXE, сеть и веб-панель в этот workflow не входят.

## Допуск и подготовка

Администратор подтверждает конкретный зарегистрированный ПК, сотрудника, точную OU, профиль и действия. Для настроенного ПК сначала разрешается только чтение/планирование. План описывает намерения stage-03; он не является Ansible dry-run и не гарантирует `changed=0` всех baseline-ролей. Исправное trust исключает повторный join, однако apply может обновить baseline, программы и GPO.

Для первого join выделить разрешённый новый/disposable ПК. Проверка настроенного ПК не доказывает первый join. Перезагрузка и завершение сеанса требуют отдельного разрешения; CLI их не выполняет. Принятый эталонный ПК не использовать для destructive acceptance.

Exact проверенный SHA устанавливать штатным guarded deployment path, без обхода `alt-deploy-guard`. До deployment необходимы Controller Readiness, отсутствие несовместимых jobs, актуальные OR-3P3 backup/rehearsal evidence и независимый recovery access. Сохранять Vault, ключи, регистрации, jobs и оба вида assignments. Git, deployment и acceptance ПК — отдельные gates.

Нужны существующие Python 3.12/Ansible/SSH prerequisites, OpenLDAP `ldapsearch`, Kerberos `kinit`/`kdestroy`. На ПК probe использует Python 3, passwordless sudo, `system-auth`, Samba `net`, SSSD и `getent`.

```sh
sudo -u altserver /usr/local/sbin/workstationctl --json controller readiness
sudo -u altserver /usr/local/sbin/workstationctl --json vault check
sudo -u altserver /usr/local/sbin/workstationctl --json jobs active
```

## Directory configuration и права

`/etc/alt-deploy/ad-directory.json`: root-owned, без group/other write, без секретов. Пример использует synthetic OU; реальная OU утверждается отдельно:

```json
{
  "uri": "ldap://sosnadmin.local",
  "auth": "gssapi",
  "credential_source": "join-vault",
  "approved_ous": ["OU=ApprovedComputers,DC=sosnadmin,DC=local"]
}
```

Без файла разрешены read-only queries через временный ticket из существующего join Vault, но approved_ous пуст и setup plan блокируется. Department-to-OU mapping в V1 отсутствует: OU выбирается явно, никогда из DN сотрудника.

GSSAPI требует confidentiality `minssf=56`. Источник `ticket` использует заранее выданный cache; `join-vault` получает временный ticket из существующих делегированных credentials; `readonly-vault` использует отдельные `vault_ad_readonly_user` и `vault_ad_readonly_password`. Adapter выполняет только LDAP search. Пароль поступает kinit через stdin; private cache удаляется.

Fallback `auth=starttls` требует `ldap://`; `auth=ldaps` требует `ldaps://`. Оба требуют отдельного `readonly-vault` и `ca_file`. Certificate/SAN verification обязательны; незашифрованного password bind нет. ldapsearch читает пароль из временного файла `0600`, argv содержит только путь.

Read identity нужны права чтения user/computer/OU и computed account-state attributes. UNKNOWN блокирует setup. Join identity нужны делегированные права штатного создания computer object только в утверждённой OU; Domain Admin не обязателен. Read-only lookup не доказывает это право: предупреждение сохраняется, недостаточные права требуют действия AD administrator.

## Сценарий оператора

Поиск V1 точный по sAMAccountName/UPN. Частичного автоматического выбора нет:

```sh
workstationctl ad users search --login synthetic.user
workstationctl ad users show --login synthetic.user@sosnadmin.local
workstationctl ad ous list
workstationctl ad computers check --hostname alt-a1-pc3
workstationctl machines list
workstationctl setup plan --machine 11111111-2222-3333-4444-555555555555 \
  --user synthetic.user --computer-ou 'OU=ApprovedComputers,DC=sosnadmin,DC=local' \
  --software-profile core-apps
```

Добавлять `--json` перед командой для automation. AD display диагностирует disabled/locked/expired, а plan такие accounts отвергает. Machine selector — UUID либо уникальный зарегистрированный hostname; IP не идентификатор.

Проверить UUID/hostname/IP, сотрудника и GUID/SID, точную OU, computer object, domain/trust, profile, prerequisites, changes, warnings и deferred actions. Plan выполняет read-only AD/SSH и localhost component preflight; создаёт только защищённый план. Registry и assignments не переписываются.

core-apps использует действующий stage-03 catalog, включая CryptoPro, CAdES и ГосПлагин. License/Vault/artifacts проверяются до изменений ПК. base — минимальный профиль. Remote profile по умолчанию none. KRFB opt-in через `--remote-access-profile krfb`, дополнительно требуется существующее явное `ALT_DEPLOY_KRFB_TCP_5900_RESTRICTED_CONFIRMED=true`. CLI его не выставляет.

Полный SHA связывает payload, source fingerprint и metadata/TTL 30 минут. content_sha256 детерминирован для одинакового семантического payload. При одинаковом времени/observations план одинаков; новый момент или состояние меняют полный SHA. Сохранённый JSON не редактировать.

```sh
workstationctl setup apply PLAN_ID --confirm-sha256 FULL_SHA256
workstationctl setup status RUN_ID
workstationctl setup verify --machine 11111111-2222-3333-4444-555555555555
```

Apply повторно проверяет AD/ПК/prerequisites под lifecycle lock. Drift требует нового плана. Только ConfigurePlanner и фиксированный stage-03 playbook; произвольные shell/playbook/Ansible vars отсутствуют. Test/assigned user — один выбранный UPN.

Domain assignment хранится отдельно: UUID, GUID/SID, login, OU, profiles, revision, run ID, дата/результат. Иная привязка блокируется; смена сотрудника вне V1. Один сотрудник допустим на нескольких ПК. Local provision assignment требует compatibility review; автоматической конверсии нет. Старые configure/provision сохранены для unbound ПК и блокируют обход managed domain assignment.

Status содержит configuration run ID, компоненты, GPO evidence, trust/SSSD/user verification, reboot requirement и deferred actions. Read-only verify показывает текущую identity/trust и group_policy_last_run из configure result; GPO update делает только pipeline. Home-dependent операции откладываются до первого domain login; затем пройти existing component acceptance checklist.

## Отказы и ручное продолжение

| Коды | Действие |
|---|---|
| ad_user_not_found / ad_user_ambiguous | Выбрать точную существующую запись; пользователей не создавать |
| ad_user_disabled / locked / expired / password_expired | Обратиться к AD administrator; CLI account не исправляет |
| ad_user_state_unknown / identity_invalid | Проверить атрибуты/read permissions; UNKNOWN не обходить |
| ad_dc_unavailable / timeout / tls_failed / kerberos_failed | Исправить connectivity/trust/time/credentials; verification не отключать |
| setup_ou_not_approved / not_found | Утвердить точную существующую OU |
| domain_computer_conflict / domain_conflict | Отдельный recovery review; account не удалять, не двигать и не сбрасывать |
| assignment_conflict / setup_assignment_managed | Корректный setup workflow; assignments не удалять для обхода |
| setup_plan_expired / mismatch / drift | Новый план и его полный SHA |
| setup_component_prerequisites_failed | Исправить catalog/artifacts/Vault до повторного plan |
| setup_execution_failed / previous_run_unresolved | RUN_ID из вывода → status → private result/log и фактическое состояние |

Failed/running/interrupted run автоматически не повторяется. V1 требует отдельного reviewed recovery workflow после ambiguous failure; удаление jobs/assignments не поддерживается. Exact завершённый plan возвращает сохранённый результат без execution. Новый безопасный повтор требует нового проверенного плана.

Пароли/tickets/private keys/raw diagnostics в output не выводятся. State/logs доступны только сервисной учётке. Public reports обезличивают реальные identifiers.

## Live acceptance

L0: цель/действия. L1: real user GUID/SID/state, OU, computer. L2: plan/no mutations. L3: approved guarded deployment и confirmed apply. L4: trust/SSSD/getent/GPO/no local duplicate/identity continuity/repeated plan. L5: safe negatives без AD writes. Graphical login/home после reboot — только с отдельным разрешением. Code/CI/readiness эти gates не заменяют.
