# ALT Workstation: Wayland default and Group Policy client

## Goal

Make Wayland the managed default Plasma session and make the existing ALT Group Policy client deployment complete and verifiable for the Yandex Browser pilot GPO.

## Scope

- Set `workstation_desktop_session` to `wayland`. The existing `workstation_base` role will validate `/usr/bin/startplasma-wayland` and render LightDM `user-session=plasma`.
- Install both required Group Policy packages: `gpupdate` and `alterator-gpupdate`.
- Verify `gpupdate-setup` is present before enabling the client, then run the existing machine policy update after domain join.
- Apply the configure playbook to the registered pilot workstation and verify: the LightDM default, `gpupdate-setup` activation, a successful machine policy update, and non-empty Yandex Browser managed-policy output.

## Out of scope

- Creating or editing GPOs on the domain controller. The existing `ALT - Yandex Browser - Pilot` GPO remains the sole pilot policy.
- Automating display power timeout or keyboard layout. No current Ansible role manages these settings; their target values and the desired system-versus-user scope have not been specified.
- Changing an already logged-in user's saved Plasma session selection. The managed LightDM default affects subsequent logins.

## Error handling

The Ansible role must fail before policy application when `gpupdate-setup` is unavailable. It must continue to fail when the machine policy update exits non-zero. The deployment verification must distinguish an empty browser policy from a non-empty applied policy.

## Acceptance criteria

1. New LightDM logins default to the Plasma Wayland desktop (`user-session=plasma`).
2. Both GPO prerequisite packages are installed and `gpupdate-setup` is executable.
3. The machine policy update completes successfully on the joined pilot computer.
4. The linked Yandex Browser GPO produces a non-empty managed policy file on the pilot computer.
5. Screen idle and keyboard layout remain unmanaged by this change.
