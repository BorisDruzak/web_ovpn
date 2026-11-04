# Inspected gpupdate/gpoa-lib 0.16.4-alt1 modules

These fixtures retain the vendor GPL headers. They were read from the matching
installed RPM pair on 2026-11-04; root `rpm -V gpupdate gpoa-lib` returned zero
with no differences. No local compatibility patches had been applied.

| Module | Package | SHA-256 |
| --- | --- | --- |
| services | gpupdate | b3cceeeb49349ca0e70694007f997d0d678f36066d1e2c79866653336baca3e5 |
| kde | gpoa-lib | 52838e1c47815d192c391f0be63157950c9e79a46cad997d3cb1ba8b4d9fa365 |
| shortcuts | gpupdate | 0498f7a2fa15aab0489f805a5fa785c9ded33d314e3ada3fb0f6141ff9f51eba |
| shortcut_model | gpupdate | 718f3aefd17e5ccc2e9161153e84e8ec43291fdb12abc00f60b8436018d5deef |

The services fixture reuses `../gpupdate-0.16.1/services.py.txt` because the bytes
are identical. KDE detection and shortcut restoration are vendor-fixed in this
release. The shortcut frontend delegates restoration to the inspected model.
