# CryptoPro browser extension automatic installation

The user requires the next workstation to install the CryptoPro Yandex extension
without manual browser-store confirmation. The prior release fixed gpupdate
forecasting and verification reuse; it did not restore this extension policy.

Use the current Opera extension `epebfcehmdedogndhlcacafjaacknbcm`, already
accepted by the approved CAdES native host, with the documented Opera update URL.
Publish a dedicated, exact `ExtensionSettings` entry with
`installation_mode=force_installed`. Keep the existing GosPlugin
ExtensionInstallForcelist and verified GPO handoff unchanged. Reject other
ExtensionSettings sources or a customized owned file before the shared
GosPlugin/browser-integration role's package writes;
never merge or overwrite unrelated browser policy. Verify the native origin
and read the written policy back independently. Browser download remains pending
until browser startup; a policy file is not proof of installation or signing.

Alternatives: restoring the old Chrome extension would reintroduce the explicitly
removed ID; adding another ExtensionInstallForcelist file would compete with the
GosPlugin/GPO list. The dedicated ExtensionSettings entry avoids both. Its
coexistence with GosPlugin must be checked in a fresh isolated browser profile.

Run focused RED/GREEN tests first, then one full immutable ALT verification before
controller release. Do not change employee profiles, restart their browsers,
replay Setup, edit GPOs, or weaken the full-test deployment gate. Existing
verification receipts cannot be reused across this source change.

References: [Yandex ExtensionSettings](https://browser.yandex.ru/support/browser-corporate/ru/policy/extension-settings)
and [ExtensionInstallForcelist](https://browser.yandex.ru/support/browser-corporate/ru/policy/extension-install-forcelist);
[CryptoPro's official Opera extension](https://addons.opera.com/ru/extensions/details/cryptopro-extension-for-cades-browser-plug-in/), matching the extension manually accepted
on the previous workstation. The new request supersedes the earlier removal only
for automatic installation of this current Opera extension.
