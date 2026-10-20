"""Fixed public diagnostic codes for the published wallet helper only."""
WALLET_CODES=frozenset('kwallet_'+suffix for suffix in (
    'atomic_rename_unavailable','backup_unverified','claim_consumed','configuration_unverified',
    'daemon_exit_unverified','daemon_restarted','daemon_unverified','dbus_unverified',
    'empty_name_evidence_incomplete','evidence_changed','evidence_unverified','lock_unverified',
    'name_unverified','ownership_unverified','partial_repair_unverified','postcondition_unverified',
    'previous_mutator_active','previous_state_unverified','readiness_changed','repair_busy',
    'repair_outcome_unverified','rollback_unverified','rollback_verified','target_collision',
    'transition_unverified','writer_identity_unverified','writer_outcome_unverified',
    'helper_collision','helper_source_unverified','request_unverified','privilege_required',
    'machine_unverified','user_unverified','native_context_unverified','target_unverified',
)) | frozenset({'graphical_session_unavailable','graphical_session_ambiguous'})
