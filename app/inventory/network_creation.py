"""Owned full-card draft context and atomic first Netctl confirmation."""
from datetime import datetime, timezone

from sqlalchemy import select

from .models import InventoryAsset, InventoryAssetIdentifier, InventoryIdentifierType
from .netctl_bindings import NetctlBindingConflict, confirm


def initial_flow(network_key):
    from .network_links import read_runtime_identity
    key, host = read_runtime_identity(network_key)
    return {'ready':True, 'status':'found', 'source':'netctl',
        'message':'Наблюдения Netctl предложены для полной карточки. Связь сохранится только после явного подтверждения.',
        'suggestions':{field:host.get(field) or '' for field in ('mac','ip','hostname')},
        'details':{}, 'network_creation':{'network_key':key,'observation':host}}


def possible_duplicates(db, flow):
    context = flow.get('network_creation') if isinstance(flow,dict) else None
    if not context:
        return []
    # A correlated predicate avoids duplicate cards for multiple source rows.
    key = context['network_key']
    identifier = select(InventoryAssetIdentifier.id).where(
        InventoryAssetIdentifier.asset_id == InventoryAsset.id,
        InventoryAssetIdentifier.identifier_type == InventoryIdentifierType.MAC,
        InventoryAssetIdentifier.normalized_value == key[4:],
        InventoryAssetIdentifier.is_current.is_(True)).exists()
    return list(db.scalars(select(InventoryAsset).where(identifier)
        .order_by(InventoryAsset.custom_name,InventoryAsset.id).limit(26)))


def validate_submit(flow, fields):
    context = flow.get('network_creation') if isinstance(flow,dict) else None
    if not context:
        return None
    if fields.get('network_confirmation') != '1':
        raise NetctlBindingConflict('Сравните возможные дубли и явно подтвердите создание карточки со связью')
    reason = fields.get('network_reason','').strip()
    if not reason or len(reason)>2000:
        raise NetctlBindingConflict('Укажите основание сравнения (до 2000 символов)')
    return context['network_key'], reason


def confirm_created(db, asset, *, key, reason, host, actor):
    # Details and identifiers can advance revision through storage triggers.
    db.flush()
    db.refresh(asset)
    return confirm(db,key,asset.id,expected_revision=asset.manual_revision,
        actor=actor,reason=reason,hosts=[host],observed_at=datetime.now(timezone.utc))
