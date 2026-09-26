"""Netctl identity relations; no remote commands and no automatic confirmation."""
from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from ..models import utcnow
from .lookup import InventoryLookupError, normalize_mac
from .models import (InventoryAsset, InventoryAssetIdentifier, InventoryIdentifierType,
    InventoryNetctlBinding, InventoryExternalBindingStatus as Status)
from .revision import claim_revision, InventoryRevisionRequired
from .service import InventoryValidationError


class NetctlBindingConflict(InventoryValidationError):
    pass


def stable_key(host):
    key = str(host.get("device_key") or "")
    if not key.startswith("mac:"):
        raise NetctlBindingConflict("Недостаточная идентичность: IP и provisional legacy-ключ не подтверждают физическое устройство")
    try:
        key_mac = normalize_mac(key[4:])
        mac = normalize_mac(str(host.get("mac") or ""))
    except InventoryLookupError as exc:
        raise NetctlBindingConflict("Некорректный MAC сетевого устройства") from exc
    if key_mac != mac or mac in {"00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"} or int(mac[:2],16) & 1:
        raise NetctlBindingConflict("MAC наблюдения не согласуется с устойчивым ключом")
    return "mac:"+mac


def identity_index(hosts):
    result = defaultdict(list)
    for host in hosts:
        try:
            key = stable_key(host)
        except NetctlBindingConflict:
            continue
        public = {name:host.get(name) for name in ("device_key","mac","ip","hostname","display_name","status","last_seen_at")}
        if public not in result[key]:
            result[key].append(public)
    return result


def _anchors(db):
    result = defaultdict(set)
    for identifier in db.scalars(select(InventoryAssetIdentifier).join(InventoryAsset,
        InventoryAsset.id == InventoryAssetIdentifier.asset_id).where(
        InventoryAssetIdentifier.identifier_type == InventoryIdentifierType.MAC,
        InventoryAssetIdentifier.is_current.is_(True))):
        try:
            result["mac:"+normalize_mac(identifier.value)].add(identifier.asset_id)
        except InventoryLookupError:
            pass
    return result


def active_for_key(db, network_key):
    return db.scalar(select(InventoryNetctlBinding).join(InventoryAsset,
        InventoryAsset.id == InventoryNetctlBinding.asset_id).where(
        InventoryNetctlBinding.network_key == network_key,
        InventoryNetctlBinding.status == Status.CONFIRMED, InventoryNetctlBinding.ended_at.is_(None)))


def refresh_candidates(db, hosts, *, snapshot_id, observed_at, conflict_keys=()):
    """Consume one complete saved snapshot; caller owns its atomic transaction."""
    identities, anchors = identity_index(hosts), _anchors(db)
    rows = list(db.scalars(select(InventoryNetctlBinding).join(InventoryAsset,
        InventoryAsset.id == InventoryNetctlBinding.asset_id).execution_options(populate_existing=True)))
    by_key = defaultdict(list)
    for row in rows:
        by_key[row.network_key].append(row)
    by_pair = {(row.asset_id,row.network_key):row for row in rows if row.ended_at is None}
    confirmed = {row.network_key for row in rows if row.status == Status.CONFIRMED and row.ended_at is None}
    conflicts = set(conflict_keys)
    created = []
    for key, observations in identities.items():
        material = {"mac":key[4:], "card_ids":sorted(anchors.get(key,()))}
        ambiguous = len(observations)>1 or len(material["card_ids"])>1 or key in conflicts
        for row in by_key[key]:
            if row.network_key == key and row.ended_at is None:
                row.observation_json = observations[0]
                row.observed_at, row.observed_snapshot_id = observed_at, snapshot_id
                if row.status == Status.CANDIDATE:
                    row.evidence_json = {"material":material,"ambiguous":ambiguous}
        if key in confirmed:
            continue
        for asset_id in material["card_ids"]:
            if any(row.asset_id == asset_id and row.network_key == key and row.status in {Status.REJECTED, Status.ENDED}
                and row.evidence_json.get("material") == material for row in by_key[key]):
                continue
            if (asset_id,key) in by_pair:
                continue
            row = InventoryNetctlBinding(asset_id=asset_id,network_key=key,status=Status.CANDIDATE,
                evidence_json={"material":material,"ambiguous":ambiguous}, observation_json=observations[0],
                observed_at=observed_at, observed_snapshot_id=snapshot_id, created_by="inventory-netctl-sync")
            db.add(row)
            created.append(row)
    db.flush()
    return created


def _require_revision(expected):
    if type(expected) is not int or expected < 1:
        raise InventoryRevisionRequired("Откройте актуальную карточку: требуется её ревизия")


def confirm(db, network_key, asset_id, *, expected_revision, actor, reason, hosts, conflict_keys=(),
    snapshot_id=0, observed_at=None, reconsider=False):
    _require_revision(expected_revision)
    identities = identity_index(hosts)
    observations = identities.get(network_key,())
    if len(observations) != 1 or network_key in set(conflict_keys):
        raise NetctlBindingConflict("Устройство отсутствует в проверенном снимке или его идентичность неоднозначна")
    anchors = _anchors(db).get(network_key,set())
    if len(anchors)>1:
        raise NetctlBindingConflict("MAC совпадает с несколькими карточками. Устраните коллизию перед подтверждением")
    existing = active_for_key(db,network_key)
    if existing is not None:
        if existing.asset_id != asset_id:
            raise NetctlBindingConflict("Сетевое устройство уже связано с другой карточкой")
        return existing
    asset = db.get(InventoryAsset,asset_id)
    if asset is None or asset.deleted_at is not None:
        raise NetctlBindingConflict("Карточка не найдена или удалена")
    reason = str(reason or "").strip()
    if not reason or len(reason)>2000:
        raise NetctlBindingConflict("Укажите основание сравнения (до 2000 символов)")
    claim_revision(db,asset,expected_revision)
    # The write claim serializes SQLite manual writers. Recheck evidence and
    # ownership after obtaining it; preflight reads alone are not authoritative.
    anchors = _anchors(db).get(network_key,set())
    if len(anchors)>1:
        raise NetctlBindingConflict("MAC совпадает с несколькими карточками. Обновите сравнение")
    existing = active_for_key(db,network_key)
    if existing is not None:
        raise NetctlBindingConflict("Сетевое устройство уже подтверждено. Обновите сравнение")
    row = db.scalar(select(InventoryNetctlBinding).where(InventoryNetctlBinding.asset_id == asset_id,
        InventoryNetctlBinding.network_key == network_key, InventoryNetctlBinding.status == Status.CANDIDATE,
        InventoryNetctlBinding.ended_at.is_(None)))
    if row is None:
        rejected = db.scalar(select(InventoryNetctlBinding.id).where(
            InventoryNetctlBinding.asset_id == asset_id, InventoryNetctlBinding.network_key == network_key,
            InventoryNetctlBinding.status.in_([Status.REJECTED, Status.ENDED])))
        if rejected is not None and not reconsider:
            raise NetctlBindingConflict("Сопоставление ранее завершено или отклонено. Требуется явное повторное сравнение")
        row = InventoryNetctlBinding(asset_id=asset_id,network_key=network_key,status=Status.CANDIDATE,created_by=str(actor))
        db.add(row)
    row.status, row.confirmed_by, row.confirmed_at = Status.CONFIRMED, str(actor), utcnow()
    row.confirmation_reason, row.observation_json = reason, observations[0]
    row.observed_snapshot_id, row.observed_at = snapshot_id, observed_at or utcnow()
    row.evidence_json = {"material":{"mac":network_key[4:],"card_ids":sorted(anchors)},"manual_comparison":True}
    try:
        db.flush()
    except IntegrityError as exc:
        raise NetctlBindingConflict("Сетевой ключ уже подтверждён конкурентным запросом; обновите сравнение") from exc
    return row


def end(db, binding_id, *, expected_revision, actor, reason, reject=False):
    _require_revision(expected_revision)
    row = db.get(InventoryNetctlBinding,binding_id)
    if row is None:
        raise NetctlBindingConflict("Связь не найдена")
    if row.ended_at is not None:
        return row
    if reject and row.status != Status.CANDIDATE:
        raise NetctlBindingConflict("Отклонять можно только неподтверждённое сопоставление")
    asset = db.get(InventoryAsset,row.asset_id)
    if asset is None or asset.deleted_at is not None:
        raise NetctlBindingConflict("Карточка удалена")
    claim_revision(db,asset,expected_revision)
    row.status = Status.REJECTED if reject else Status.ENDED
    row.ended_at, row.ended_by, row.end_reason = utcnow(), str(actor), str(reason or "")[:2000]
    db.flush()
    return row
