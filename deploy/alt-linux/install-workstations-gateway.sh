#!/bin/sh
set -eu
# Use only the root-owned, already guarded-installed controller package.
exec /usr/bin/python3 -I -c 'import sys; sys.path.insert(0, "/opt/alt-deploy-control"); from alt_deploy.gateway_install import main; raise SystemExit(main())' "$@"
