import pytest


@pytest.fixture(autouse=True)
def reset_app_caches():
    try:
        from app.db import reset_engine_cache

        reset_engine_cache()
    except Exception:
        pass
    yield
    try:
        from app.db import reset_engine_cache

        reset_engine_cache()
    except Exception:
        pass
