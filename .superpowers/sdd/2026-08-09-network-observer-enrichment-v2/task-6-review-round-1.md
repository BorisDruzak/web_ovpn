# Task 6 review findings — round 1

1. Fix `_nmap_os_evidence` token handling: Cisco IOS/IOS XE must not become Apple iOS PC evidence; Apple iOS/iPadOS must be intentionally handled. Add RED→GREEN direct probes and weak-hostname interaction tests.
2. Endpoint-agent evidence must reach V2 in production. The local adapter expects `device_type`/`os_family`, but real Endpoint Platform/SDK contracts do not expose them. Before modifying external `C:\Users\admin-2\Documents\endpoint`, inspect for an already-authoritative exposed field that can safely map; otherwise report the exact upstream contract change required. Do not invent classification values or change the external repository without user authorization.
