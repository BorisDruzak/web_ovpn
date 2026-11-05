"""Native continuation rechecks live state even when full tests are reusable."""
import json
from pathlib import Path
import subprocess

from support.installer_sandbox import InstallerSandbox, DEFAULT_ROLLBACK_BACKUP_ID, ALT_ROOT


def test_resume_argument_is_explicit_and_compatible_with_maintenance_review():
    command = ['bash', '-c', 'source "$1"; shift; parse_control_plane_args "$@" >/dev/null || exit $?; '
               'printf "%s|%s|%s" "$CONTROL_PLANE_BACKUP_ID" "$CONTROL_PLANE_MAINTENANCE_REVIEW" "$CONTROL_PLANE_RESUME_VERIFICATION"',
               'parse', str(ALT_ROOT/'install-control-plane-args.sh'), '--rollback-backup-id', DEFAULT_ROLLBACK_BACKUP_ID]
    for suffix in (['--resume-verification'], ['--resume-verification', '--maintenance-review', 'a'*64],
                   ['--maintenance-review', 'a'*64, '--resume-verification']):
        result = subprocess.run([*command, *suffix], capture_output=True, text=True)
        assert result.returncode == 0 and result.stdout.endswith('|1')
    assert subprocess.run([*command, '--resume-verification', '--resume-verification'], capture_output=True).returncode != 0


def test_known_live_blocker_prevents_even_starting_tests(tmp_path):
    sandbox = InstallerSandbox.create(tmp_path)
    result = sandbox.run_prechecks(INSTALLER_JOBS_JSON=json.dumps({'status': 'ok', 'count': 1, 'active_jobs': [{}]}))
    assert result.returncode != 0
    assert not any(any('verification_checkpoint.py' in a for a in c) for c in sandbox.commands())
    assert not InstallerSandbox.mutation_commands(sandbox.commands())


def test_resume_option_reaches_native_verification_and_live_guards_run_twice(tmp_path):
    sandbox = InstallerSandbox.create(tmp_path)
    result = sandbox.run_prechecks(RESUME_VERIFICATION='1')
    assert result.returncode == 0, result.stderr
    commands = sandbox.commands()
    verify = [c for c in commands if any('verification_checkpoint.py' in a for a in c)]
    assert len(verify) == 1 and '--resume' in verify[0]
    jobs = [i for i, c in enumerate(commands) if 'jobs' in c and 'active' in c]
    assert len(jobs) == 2 and jobs[0] < commands.index(verify[0]) < jobs[1]


def test_second_live_check_failure_after_reuse_prevents_rollout(tmp_path):
    sandbox = InstallerSandbox.create(tmp_path)
    counter = tmp_path/'counter'
    fake = sandbox.fake_bin/'sudo'
    text = fake.read_text()
    text = text.replace('case " $* " in', f'''if [[ " $* " == *" jobs active "* ]]; then
count=0; [[ ! -f {counter} ]] || count=$(cat {counter})
printf '%s' "$((count+1))" > {counter}
if (( count > 0 )); then exit 7; fi
fi
case " $* " in''')
    fake.write_text(text)
    before = sandbox.protected_snapshot()
    result = sandbox.run_library(RESUME_VERIFICATION='1')
    assert result.returncode != 0
    assert sandbox.protected_snapshot() == before
    assert not InstallerSandbox.mutation_commands(sandbox.commands())
