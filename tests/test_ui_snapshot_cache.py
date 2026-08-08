from __future__ import annotations

import threading


def test_snapshot_cache_reuses_fresh_value(monkeypatch):
    from app.ui_snapshot_cache import SnapshotCache

    now = [10.0]
    monkeypatch.setattr("app.ui_snapshot_cache.time.monotonic", lambda: now[0])
    cache = SnapshotCache()
    calls = 0

    def load():
        nonlocal calls
        calls += 1
        return {"clients_count": 3}

    first = cache.get("dashboard", 5, load)
    second = cache.get("dashboard", 5, load)

    assert first.data == {"clients_count": 3}
    assert first.stale is False
    assert second.data == {"clients_count": 3}
    assert calls == 1


def test_snapshot_cache_refreshes_after_ttl(monkeypatch):
    from app.ui_snapshot_cache import SnapshotCache

    now = [10.0]
    monkeypatch.setattr("app.ui_snapshot_cache.time.monotonic", lambda: now[0])
    cache = SnapshotCache()
    values = iter(({"clients_count": 1}, {"clients_count": 2}))

    assert cache.get("dashboard", 5, lambda: next(values)).data == {"clients_count": 1}
    now[0] = 15.1
    assert cache.get("dashboard", 5, lambda: next(values)).data == {"clients_count": 2}


def test_snapshot_cache_preserves_last_good_on_error(monkeypatch):
    from app.ui_snapshot_cache import SnapshotCache

    now = [10.0]
    monkeypatch.setattr("app.ui_snapshot_cache.time.monotonic", lambda: now[0])
    cache = SnapshotCache()
    assert cache.get("dashboard", 5, lambda: {"openvpn": "active"}).stale is False
    now[0] = 16.0

    result = cache.get("dashboard", 5, lambda: (_ for _ in ()).throw(RuntimeError("sensitive output")))

    assert result.data == {"openvpn": "active"}
    assert result.stale is True
    assert result.errors == ["unavailable"]


def test_snapshot_cache_single_flight_waits_for_first_value():
    from app.ui_snapshot_cache import SnapshotCache

    cache = SnapshotCache()
    started = threading.Event()
    release = threading.Event()
    results = []
    calls = 0
    calls_lock = threading.Lock()

    def load():
        nonlocal calls
        with calls_lock:
            calls += 1
        started.set()
        assert release.wait(2)
        return {"connected_count": 7}

    def read():
        results.append(cache.get("dashboard", 5, load))

    first = threading.Thread(target=read)
    second = threading.Thread(target=read)
    first.start()
    assert started.wait(2)
    second.start()
    release.set()
    first.join(2)
    second.join(2)

    assert calls == 1
    assert [result.data for result in results] == [{"connected_count": 7}, {"connected_count": 7}]
