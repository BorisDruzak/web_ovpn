# Inventory Card Blocks and PC Detail Migration

## Goal

Make the mobile inventory card easier to complete by grouping fields, replacing free-text PC classification fields with constrained choices, and migrating existing device comments and PC detail values without losing information.

## Scope

- Move the `К ЛОКАЦИИ` control outside the collapsible device-card `<details>` element.
- Remove the asset-card `Комментарий` input and migrate all existing `inventory_assets.notes` values into `inventory_assets.description`.
- Group every editable asset field into labelled form blocks.
- Add `os_version` to PC details and render PC operating system, processor, RAM, and storage as separate blocks.
- Constrain PC OS, processor vendor, and RAM type through form selects while retaining a text field for OS version and CPU generation.
- Normalize existing production PC values and preserve information that cannot be represented in a select field.

## Data Model

`inventory_pc_details` gains nullable `os_version VARCHAR(255)`.

Existing columns retain their API names:

| Column | New meaning | Allowed UI value |
| --- | --- | --- |
| `os_name` | Operating-system family | `Windows` or `Linux` |
| `os_version` | Distro/release/version text | free text |
| `cpu_model` | CPU vendor | `Intel` or `AMD` |
| `cpu_generation` | CPU model or generation text | free text |
| `ram_type` | RAM generation | `DDR3` or `DDR4` |
| `ram_gb` | RAM capacity | non-negative integer |

`inventory_assets.notes` remains physically present in legacy SQLite files for compatibility, but is removed from the ORM asset model, web forms, API asset representation and normal asset mutation payloads.

Inventory-session check notes remain unchanged; they are distinct from asset-card comments.

## Migration Rules

The migration is idempotent and only applies where needed.

1. For every asset with a non-empty legacy `notes` value:
   - if `description` is blank, use the legacy comment as the description;
   - otherwise append `\n\nКомментарий: ` and the legacy comment to the description;
   - set the legacy `notes` column to `NULL` after the transfer.
2. For every PC detail row:
   - normalize RAM case (`ddr3`/`Ddr3` to `DDR3`, `ddr4`/`Ddr4` to `DDR4`);
   - normalize processor vendor (`intrl` and `Intel` to `Intel`, `Amd`/`AMD` to `AMD`);
   - repair the known legacy split `cpu_model=11400`, `cpu_generation=i5` or `I5` to `Intel` and `i5 11400`;
   - split Windows data into `os_name=Windows` and a concise version (`Win10` to `10`, `Win11` to `11`, `Win7` to `7`, `Windows 10` to `10`);
   - split Linux data into `os_name=Linux` while preserving the original distribution string in `os_version`, such as `Alt Linux KDE 11.4` or `Astra Linux`;
   - preserve unrecognized values in the existing text fields and do not invent a selected family or vendor.

The production backfill is run after the schema migration in one short transaction, with a database backup created first.

## Form Layout

All asset forms use visible grouped blocks:

1. **Основные данные** — name, inventory number, status.
2. **Идентификация устройства** — manufacturer, model, serial number.
3. **Сеть** — IP, MAC, hostname when the asset type supports network identifiers.
4. **Операционная система** — PC only: Windows/Linux select and OS version text.
5. **Процессор** — PC only: Intel/AMD select and generation/model text.
6. **Оперативная память** — PC only: DDR3/DDR4 select and capacity in GB.
7. **Накопитель** — PC only: storage type and capacity.
8. **Параметры устройства** — type-specific controls such as printer connection/page counter, phone extension, monitor diagonal, or UPS power/battery date.
9. **Пользователь** — PC and phone assignee/login.
10. **Описание** — the sole free-form physical-device note.

Photos remain attached to the current device card. The location-return control is rendered after the card closes, so collapsing a device cannot hide navigation.

## Behaviour and Validation

- The selects submit canonical stored values (`Windows`, `Linux`, `Intel`, `AMD`, `DDR3`, `DDR4`).
- Empty selects remain nullable for incomplete manual capture.
- Directly submitted invalid select values return the existing draft-preserving validation error flow.
- Nmap/collection OS suggestions are normalized into the OS family and version fields before rendering a new PC form.
- Existing REST API callers see `os_version` in PC `details`; they no longer receive or accept the deprecated asset `notes` field.

## Verification

- Service tests cover PC detail validation and legacy-value normalization.
- Schema tests prove a pre-existing SQLite `inventory_pc_details` table gains `os_version` in place.
- Web tests prove grouped controls render, create/update routes persist their values, drafts survive validation errors, and the location control is outside `<details>`.
- Migration tests cover note transfer for blank and non-blank descriptions plus clearing the legacy note.
- Production verification checks the column, the final distribution of normalized PC values, no remaining asset notes, page health and a visually inspected authenticated form.

## Non-goals

- Do not remove Serial from device records.
- Do not alter inventory-session check notes.
- Do not infer hardware values not supported by existing data or collection evidence.
- Do not rebuild the SQLite table solely to physically drop the deprecated `notes` column.
