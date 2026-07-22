from __future__ import annotations

from typing import Final, Literal


PlanStatus = Literal[
    "draft", "validated", "approved", "applying", "applied", "verified",
    "failed", "rolling_back", "rolled_back", "cancelled",
]
SubjectType = Literal["asset", "user", "infrastructure"]
OperationType = Literal["internet_access_set", "internet_policy_bootstrap"]

PLAN_STATUSES: Final = frozenset({
    "draft", "validated", "approved", "applying", "applied", "verified",
    "failed", "rolling_back", "rolled_back", "cancelled",
})
PLAN_TRANSITIONS: Final = {
    "draft": frozenset({"validated", "cancelled"}),
    "validated": frozenset({"approved", "cancelled"}),
    "approved": frozenset({"applying", "failed", "cancelled"}),
    "applying": frozenset({"applied", "failed", "rolling_back"}),
    "applied": frozenset({"verified", "failed", "rolling_back"}),
    "verified": frozenset({"rolling_back"}),
    "failed": frozenset({"rolling_back", "cancelled"}),
    "rolling_back": frozenset({"rolled_back", "failed"}),
    "rolled_back": frozenset(),
    "cancelled": frozenset(),
}
