# ALT Linux deployment files

Working context and architecture: [`docs/ALT_LINUX_AUTOINSTALL.md`](../../docs/ALT_LINUX_AUTOINSTALL.md).

These files mirror the verified deployment configuration, but active secrets and ISO-derived files are intentionally excluded.

## Repository layout

```text
deploy/alt-linux/
├── api/
│   ├── register_api.py
│   └── process_pending.py
├── autoinstall/
│   ├── autoinstall.scm.example
│   ├── vm-profile.scm
│   └── create-install-scripts-tar.sh
├── bootstrap/
│   └── bootstrap.sh
├── inventory/
│   └── inventory-autoinstall.ini.example
├── ssh/
│   └── ssh-alt
└── systemd/
    ├── alt-deploy-http.service
    ├── alt-deploy-register.service
    ├── alt-deploy-process.service
    └── alt-deploy-process.path
```

## Initial server layout

Run on the deployment server as an administrator:

```bash
sudo install -d -o root -g root -m 0755 \
  /srv/alt-deploy \
  /srv/alt-deploy/metadata \
  /srv/alt-deploy/bootstrap \
  /srv/alt-deploy/packages \
  /srv/alt-deploy/logs

sudo install -d -o altserver -g altserver -m 0700 \
  /srv/alt-deploy/registration/pending \
  /srv/alt-deploy/registration/ready \
  /srv/alt-deploy/registration/failed

sudo install -d -o root -g root -m 0755 /opt/alt-deploy-api
```

Copy the files:

```bash
sudo install -m 0755 \
  deploy/alt-linux/bootstrap/bootstrap.sh \
  /srv/alt-deploy/bootstrap/bootstrap.sh

sudo install -m 0644 \
  deploy/alt-linux/autoinstall/vm-profile.scm \
  /srv/alt-deploy/metadata/vm-profile.scm

sudo install -m 0755 \
  deploy/alt-linux/autoinstall/create-install-scripts-tar.sh \
  /usr/local/sbin/create-alt-install-scripts-tar

sudo /usr/local/sbin/create-alt-install-scripts-tar

sudo install -m 0755 \
  deploy/alt-linux/api/register_api.py \
  /opt/alt-deploy-api/register_api.py

sudo install -m 0755 \
  deploy/alt-linux/api/process_pending.py \
  /opt/alt-deploy-api/process_pending.py

sudo install -m 0755 \
  deploy/alt-linux/ssh/ssh-alt \
  /usr/local/bin/ssh-alt
```

Prepare the active autoinstall file:

```bash
sudo cp \
  deploy/alt-linux/autoinstall/autoinstall.scm.example \
  /srv/alt-deploy/metadata/autoinstall.scm

sudoedit /srv/alt-deploy/metadata/autoinstall.scm
```

Replace both yescrypt placeholders. Never commit the active file with hashes.

Copy from the exact installation ISO:

```text
/Metadata/pkg-groups.tar
```

into:

```text
/srv/alt-deploy/metadata/pkg-groups.tar
```

Publish the Ansible public key:

```bash
sudo install -m 0644 \
  /home/altserver/.ssh/id_ed25519.pub \
  /srv/alt-deploy/bootstrap/ansible_authorized_keys

sudo -u altserver touch \
  /home/altserver/.ssh/known_hosts_autoinstall
sudo chmod 0600 \
  /home/altserver/.ssh/known_hosts_autoinstall
```

Install systemd units:

```bash
sudo install -m 0644 deploy/alt-linux/systemd/* \
  /etc/systemd/system/

sudo systemctl daemon-reload
sudo systemctl enable --now \
  alt-deploy-http.service \
  alt-deploy-register.service \
  alt-deploy-process.path
```

## Validation

```bash
bash -n /srv/alt-deploy/bootstrap/bootstrap.sh
python3 -m py_compile /opt/alt-deploy-api/register_api.py
python3 -m py_compile /opt/alt-deploy-api/process_pending.py

curl -fsS http://127.0.0.1:8087/index.txt
curl -fsS http://127.0.0.1:8088/health

systemctl is-active alt-deploy-http
systemctl is-active alt-deploy-register
systemctl is-active alt-deploy-process.path
```

## Boot parameter

Append to the stock ALT installer kernel command line:

```text
ai curl=http://192.168.100.17:8087/metadata/
```

The profile clears the first detected disk. Use a disposable test machine with one disk until disk selection is hardened.
