"""Small presentation-only list context boundary; not an authorization shortcut."""
import re
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit

HOST_FILTER_KEYS = frozenset({'q','category','status','source','network','has_hostname','has_mac','seen_within','page','limit','inventory_link'})
LIST_QUERY_KEYS = {
    '/network/hosts': HOST_FILTER_KEYS,
    '/inventory': frozenset({'q','page'}),
    '/inventory/deleted': frozenset({'page'}),
    '/inventory/network-links': frozenset({'q','page','network_key','asset_id'}),
}
_LOCATION = re.compile(r'/inventory/locations/[0-9a-fA-F-]{36}\Z')


def safe_return_url(value: object, fallback: str = '/network/hosts') -> str:
    """Accept only known GET list destinations and bounded supported query values."""
    if not isinstance(value,str) or len(value)>4096 or value != value.strip():
        return fallback
    decoded = value
    for _ in range(4):
        decoded = unquote(decoded)
        if '\\' in decoded or any(ord(char)<32 or ord(char)==127 for char in decoded):
            return fallback
    try:
        parts = urlsplit(value)
        if parts.scheme or parts.netloc or parts.fragment or not parts.path.startswith('/'):
            return fallback
        allowed = LIST_QUERY_KEYS.get(parts.path)
        if allowed is None:
            if not _LOCATION.fullmatch(parts.path):
                return fallback
            allowed = frozenset({'q','page'})
        query = [(key,item) for key,item in parse_qsl(parts.query,keep_blank_values=True,max_num_fields=40)
            if key in allowed and len(item)<=255]
    except ValueError:
        return fallback
    return parts.path + ('?' + urlencode(query) if query else '')


def return_link(request, fallback: str = '/network/hosts', draft=None) -> str:
    value = request.query_params.get('return_url')
    if value is None and draft is not None:
        value = (draft.flow_json or {}).get('return_url')
    return safe_return_url(value, fallback)


def list_context(request) -> str:
    return safe_return_url(request.url.path + ('?' + request.url.query if request.url.query else ''))
