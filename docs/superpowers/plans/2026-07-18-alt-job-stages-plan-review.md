# ALT structured job stages plan review

Date: 2026-07-18

Applies to:

```text
docs/superpowers/plans/2026-07-18-alt-job-stages.md
```

Status: mandatory editorial corrections for execution.

The implementation design and task order remain unchanged. Apply these two corrections while executing Task 5:

1. `tests/alt_linux/test_config.py` is a modified file in Task 5 because the `Settings.from_env()` contract gains `ALT_DEPLOY_JOB_STAGE_HELPER` and `job_stage_helper_path`.
2. Include `tests/alt_linux/test_config.py` in the Task 5 commit:

```bash
git add \
  deploy/alt-linux/control/alt_deploy/config.py \
  deploy/alt-linux/control/alt_deploy/job_stage_helper.py \
  deploy/alt-linux/control/alt-job-stage \
  deploy/alt-linux/install-control-plane.sh \
  tests/alt_linux/test_job_stage_helper.py \
  tests/alt_linux/test_registry_cli.py \
  tests/alt_linux/test_config.py \
  tests/alt_linux/test_install_assets.py
```

The repeated installer assertion for the literal source path in Task 5 is redundant; execute it once. This does not change the tested contract.

No runtime action, job deletion, provisioning, or secret access is authorized by this review note.
