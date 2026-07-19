from __future__ import annotations

from enum import StrEnum


class SnmpOutcome(StrEnum):
    SUCCESS_WITH_ROWS = "success_with_rows"
    SUCCESS_EMPTY = "success_empty"
    UNSUPPORTED_NO_SUCH_OBJECT = "unsupported_no_such_object"
    TIMEOUT = "timeout"
    AUTH_OR_VIEW_FAILURE = "auth_or_view_failure"
    PARSE_ERROR = "parse_error"
