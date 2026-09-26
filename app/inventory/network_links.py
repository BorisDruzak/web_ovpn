"""Explicit local Netctl relation management from either registry."""
from urllib.parse import urlencode
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select, func, or_
from sqlalchemy.orm import Session

from ..auth import require_user, verify_api_csrf
from ..audit import write_audit
from ..db import get_db
from ..config import get_settings
from ..netctl_client import run_netctl, NetctlError
from ..permissions import user_has_permission
from .models import InventoryAsset, InventoryNetctlBinding
from .netctl_bindings import stable_key, confirm, end, NetctlBindingConflict
from .revision import InventoryRevisionConflict, InventoryRevisionRequired

router = APIRouter()


def comparison_url(key, asset_id=''):
    return '/inventory/network-links?' + urlencode({'network_key':key,'asset_id':asset_id})


def read_runtime_identity(key):
    if not get_settings().network_observer_enabled:
        raise NetctlBindingConflict('Источник Netctl отключён. Сохранённые связи остаются в силе')
    key = stable_key({'device_key':key,'mac':key.removeprefix('mac:')})
    try:
        response = run_netctl(['runtime-assets','inspect',key],timeout=20)
    except NetctlError as exc:
        raise NetctlBindingConflict('Источник Netctl недоступен. Сохранённые связи остаются в силе') from exc
    runtime = response.get('runtime_asset')
    if not isinstance(runtime,dict) or not isinstance(runtime.get('asset'),dict):
        raise NetctlBindingConflict('Устойчивая идентичность не найдена в Netctl')
    asset = runtime['asset']
    if asset.get('asset_key') != key or asset.get('provisional') not in (False,0):
        raise NetctlBindingConflict('Provisional или несогласованная идентичность требует проверки')
    interfaces = runtime.get('interfaces')
    if not isinstance(interfaces,list) or not any(isinstance(item,dict) and item.get('mac') == key[4:] for item in interfaces):
        raise NetctlBindingConflict('Netctl не подтверждает интерфейс с указанным MAC')
    findings = runtime.get('findings')
    if not isinstance(findings,list):
        raise NetctlBindingConflict('Проверка коллизий Netctl недоступна')
    if any(not isinstance(item,dict) or (item.get('status') != 'resolved' and item.get('finding_type') in
        {'mac_identity_collision','historical_identity_conflict'}) for item in findings):
        raise NetctlBindingConflict('Netctl сообщает конфликт идентичности. Устраните коллизию перед подтверждением')
    ips = runtime.get('current_ip_observations',[])
    names = runtime.get('current_hostname_observations',[])
    if not isinstance(ips,list) or not isinstance(names,list) or any(not isinstance(item,dict) for item in ips+names):
        raise NetctlBindingConflict('Наблюдения Netctl некорректны')
    host = {'device_key':key,'mac':key[4:],'ip':ips[0].get('ip') if ips else None,
        'hostname':names[0].get('hostname') if names else None,'last_seen_at':ips[0].get('last_seen_at') if ips else None,
        'status':'unknown'}
    return key,host


def _page(request,db,user,key,asset_id='',q='',page=1,error=None,reason='',submitted_revision=None):
    from .web import _render
    host = None
    try:
        key,host = read_runtime_identity(key)
    except NetctlBindingConflict as exc:
        error = error or str(exc)
    selection = select(InventoryAsset)
    if q:
        escaped = q[:255].replace('\\','\\\\').replace('%','\\%').replace('_','\\_')
        selection = selection.where(or_(*(column.ilike('%'+escaped+'%',escape='\\') for column in
            (InventoryAsset.custom_name,InventoryAsset.inventory_number,InventoryAsset.serial_number,InventoryAsset.model))))
    if asset_id:
        selection = selection.where(InventoryAsset.id == asset_id)
    total = db.scalar(select(func.count()).select_from(selection.subquery())) or 0
    pages = max(1,(total+24)//25)
    page = min(max(1,page),pages)
    cards = list(db.scalars(selection.order_by(InventoryAsset.custom_name,InventoryAsset.id).limit(25).offset((page-1)*25)))
    links = list(db.scalars(select(InventoryNetctlBinding).join(InventoryAsset,
        InventoryAsset.id == InventoryNetctlBinding.asset_id).where(InventoryNetctlBinding.network_key == key)
        .order_by(InventoryNetctlBinding.created_at.desc()).limit(100)))
    revisions = dict(db.execute(select(InventoryAsset.id,InventoryAsset.manual_revision).where(
        InventoryAsset.id.in_({link.asset_id for link in links}))).all())
    return _render(request,'inventory_network_links.html',{'network_key':key,'host':host,'cards':cards,
        'links':links,'link_revisions':revisions,'q':q,'selected_asset_id':asset_id,'page':page,'pages':pages,'total':total,
        'error':error,'reason':reason,'submitted_revision':submitted_revision,
        'can_write':user_has_permission(user,'inventory:write'),'comparison_url':comparison_url},db)


@router.get('/inventory/network-links')
def compare_network_link(request: Request,network_key: str,asset_id: str='',q: str='',page: int=1,db: Session=Depends(get_db)):
    user = require_user(request,db)
    return _page(request,db,user,network_key,asset_id,q,page)


@router.post('/inventory/network-links/confirm')
def confirm_network_link(request: Request,network_key: str=Form(),asset_id: str=Form(),reason: str=Form(),
    confirmation: str=Form(default=''),expected_revision: int | None=Form(default=None),
    reconsider: bool=Form(default=False),csrf_token: str=Form(default=''),db: Session=Depends(get_db)):
    user = require_user(request,db)
    verify_api_csrf(request,csrf_token)
    try:
        if confirmation != asset_id:
            raise NetctlBindingConflict('Подтвердите сравнение выбранной физической карточки')
        key,host = read_runtime_identity(network_key)
        binding = confirm(db,key,asset_id,expected_revision=expected_revision,actor=user.username,
            reason=reason,hosts=[host],observed_at=datetime.now(timezone.utc),reconsider=reconsider)
        write_audit(db,request,user,'inventory-netctl-confirm','success',
            message=f'asset_id={asset_id} network_key={key}',target_client=binding.id,commit=False)
        db.commit()
    except (NetctlBindingConflict,InventoryRevisionConflict) as exc:
        db.rollback()
        response = _page(request,db,user,network_key,asset_id,error=str(exc),reason=reason,
            submitted_revision=expected_revision)
        response.status_code = 428 if isinstance(exc,InventoryRevisionRequired) else 409
        return response
    return RedirectResponse(comparison_url(key,asset_id),status_code=303)


@router.post('/inventory/network-links/{binding_id}/end')
def end_network_link(binding_id: str,request: Request,reason: str=Form(),expected_revision: int | None=Form(default=None),
    reject: bool=Form(default=False),csrf_token: str=Form(default=''),db: Session=Depends(get_db)):
    user = require_user(request,db)
    verify_api_csrf(request,csrf_token)
    try:
        binding = end(db,binding_id,expected_revision=expected_revision,actor=user.username,reason=reason,reject=reject)
        write_audit(db,request,user,'inventory-netctl-reject' if reject else 'inventory-netctl-end','success',
            message=f'asset_id={binding.asset_id}',target_client=binding.id,commit=False)
        db.commit()
    except (NetctlBindingConflict,InventoryRevisionConflict) as exc:
        db.rollback()
        raise HTTPException(428 if isinstance(exc,InventoryRevisionRequired) else 409,str(exc)) from exc
    return RedirectResponse(comparison_url(binding.network_key,binding.asset_id),status_code=303)
