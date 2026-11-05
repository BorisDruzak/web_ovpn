"""The installer owns test selection; operators may force full, never skip."""
import subprocess

from support.installer_sandbox import InstallerSandbox, ALT_ROOT, DEFAULT_ROLLBACK_BACKUP_ID


def test_explicit_full_option_parses_and_rejects_duplicates():
    command = ['bash', '-c', 'source "$1"; shift; parse_control_plane_args "$@" >/dev/null || exit $?; '
               'printf "%s|%s" "$CONTROL_PLANE_FULL_VERIFICATION" "$CONTROL_PLANE_RESUME_VERIFICATION"',
               'parse', str(ALT_ROOT/'install-control-plane-args.sh'), '--rollback-backup-id', DEFAULT_ROLLBACK_BACKUP_ID]
    assert subprocess.run(command, capture_output=True, text=True).stdout == '0|0'
    result = subprocess.run([*command, '--full-verification', '--resume-verification'], capture_output=True, text=True)
    assert result.returncode == 0 and result.stdout == '1|1'
    assert subprocess.run([*command, '--full-verification', '--full-verification'], capture_output=True).returncode != 0
    assert subprocess.run([*command, '--component', 'directum'], capture_output=True).returncode != 0
    assert subprocess.run([*command, '--skip-tests'], capture_output=True).returncode != 0


def test_forced_full_and_resume_are_forwarded_without_skipping_live_guards(tmp_path):
    sandbox = InstallerSandbox.create(tmp_path)
    result = sandbox.run_prechecks(FULL_VERIFICATION='1', RESUME_VERIFICATION='1')
    assert result.returncode == 0, result.stderr
    commands = sandbox.commands()
    verify = [c for c in commands if any('verification_checkpoint.py' in a for a in c)]
    assert len(verify) == 1 and '--full' in verify[0] and '--resume' in verify[0]
    jobs = [i for i, c in enumerate(commands) if 'jobs' in c and 'active' in c]
    assert len(jobs) == 2 and jobs[0] < commands.index(verify[0]) < jobs[1]
    assert not InstallerSandbox.mutation_commands(commands)
