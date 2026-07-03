#!/usr/bin/env bash
set -euo pipefail

set -a
# shellcheck disable=SC1091
. /etc/openvpn-web/openvpn-web.env
set +a

cd /opt/openvpn-web
.venv/bin/python - <<'PY'
from sqlalchemy import select

from app.auth import verify_password
from app.config import get_settings
from app.db import init_db, session_scope
from app.models import WebUser

settings = get_settings()
init_db()
with session_scope() as db:
    users = list(db.scalars(select(WebUser)).all())
    user = db.scalar(select(WebUser).where(WebUser.username == settings.admin_username))
    print(f"settings_user={settings.admin_username}")
    print(f"settings_password_len={len(settings.admin_password)}")
    print(f"users={[(u.username, u.is_active, u.is_admin) for u in users]}")
    print(f"password_verifies={verify_password(settings.admin_password, user.password_hash) if user else None}")
PY
