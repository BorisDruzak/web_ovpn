from __future__ import annotations

from dataclasses import dataclass, field

DIAGNOSTIC_COMPONENTS=frozenset({'runtime','systemd','ansible','controller_state','registration_state','deployment_assets'})
DIAGNOSTIC_REASONS=frozenset({'UNKNOWN','archive_command_failed','archive_command_unavailable','stderr_limit',
    'deadline_exceeded','source_changed','controller_sources_changed','archive_publication_failed','archive_hash_failed',
    'archive_destination_failed','bundle_publication_failed'})
DIAGNOSTIC_SIGNALS=frozenset({'file_changed','permission_denied','no_space','cannot_stat','file_removed'})

def validated_diagnostic(value):
    if (not isinstance(value,dict) or set(value)!={'component','reason','tar_returncode','zstd_returncode','signals'}
            or value['component'] is not None and (not isinstance(value['component'],str) or value['component'] not in DIAGNOSTIC_COMPONENTS)
            or not isinstance(value['reason'],str) or value['reason'] not in DIAGNOSTIC_REASONS
            or any(v is not None and (type(v) is not int or not -255<=v<=255) for v in (value['tar_returncode'],value['zstd_returncode']))
            or not isinstance(value['signals'],list) or len(value['signals'])>5
            or any(not isinstance(v,str) or v not in DIAGNOSTIC_SIGNALS for v in value['signals'])
            or value['signals']!=sorted(set(value['signals']))):raise ValueError('Invalid bounded backup diagnostic')
    return dict(value,signals=list(value['signals']))


@dataclass
class BackupError(Exception):
    code: str
    message: str
    exit_code: int = 1
    details: dict[str, object] = field(default_factory=dict)
    diagnostic: dict[str, object] | None = None

    def __str__(self) -> str:
        return self.message

    def to_dict(self) -> dict[str, object]:
        error: dict[str, object] = {
            "code": self.code,
            "message": self.message,
        }
        if self.details:
            error["details"] = dict(self.details)
        if self.diagnostic is not None:
            error['diagnostic']=validated_diagnostic(self.diagnostic)
        return {"status": "error", "error": error}
