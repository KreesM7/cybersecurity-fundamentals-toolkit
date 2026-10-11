#!/usr/bin/env bash
# Toolkit source: MIT. Install external dependencies in the dedicated Ubuntu host.
set -euo pipefail
umask 077
if [[ $(id -u) != 0 ]]; then
  echo 'Run this provisioning script with sudo in Toolkit-MSF or your dedicated Ubuntu24.04 host.' >&2
  exit 1
fi
. /etc/os-release
if [[ ${ID:-} != ubuntu || ${VERSION_ID:-} != 24.04 ]]; then
  echo 'This provisioner supports Ubuntu24.04 only.' >&2
  exit 1
fi
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
project_dir=$(dirname -- "$script_dir")
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl gnupg openssl python3-venv nmap libmagic1
staging=$(mktemp -d)
trap 'rm -f -- "$staging/installer" "$staging/key.asc"; rmdir -- "$staging"' EXIT
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --max-time 60 \
  'https://raw.githubusercontent.com/rapid7/metasploit-omnibus/25a202b4e6226631cb0f24716b2fff0136312805/config/templates/metasploit-framework-wrappers/msfupdate.erb' \
  --output "$staging/installer"
printf '%s  %s\n' 'd12fea4d1339ebecb09d8cc36920d9f5e5e7e9fffbe092b1e1cd09255cc16825' "$staging/installer" | sha256sum --check --status
# Extract the reviewed public key; never execute the downloaded installer.
sed -n '/-----BEGIN PGP PUBLIC KEY BLOCK-----/,/-----END PGP PUBLIC KEY BLOCK-----/p' \
  "$staging/installer" > "$staging/key.asc"
fingerprint=$(gpg --batch --show-keys --with-colons "$staging/key.asc" | awk -F: '$1=="fpr" {print $10; exit}')
if [[ $fingerprint != 97B32012EA1176F053727A95C048F0B49DEEC457 ]]; then
  echo 'Unexpected Rapid7 signing key. Review the upstream key rotation before continuing.' >&2
  exit 1
fi
gpg --batch --yes --dearmor --output /usr/share/keyrings/metasploit-framework.gpg "$staging/key.asc"
chmod 644 /usr/share/keyrings/metasploit-framework.gpg
printf '%s\n' 'deb [signed-by=/usr/share/keyrings/metasploit-framework.gpg] https://downloads.metasploit.com/data/releases/metasploit-framework/apt lucid main' \
  > /etc/apt/sources.list.d/metasploit-framework.list
apt-get update
apt-get install -y metasploit-framework
python3 -m venv /opt/toolkit-scapy
python3 "$script_dir/build_worker_wheel.py"
(cd "$project_dir/worker" && /opt/toolkit-scapy/bin/python -m pip install --require-hashes -r requirements-provision.txt)
install -d -m 755 /opt/toolkit-msf
install -m 755 "$script_dir/start-msfrpc.py" /opt/toolkit-msf/start-msfrpc.py
install -m 644 "$script_dir/toolkit_rpc.rb" /opt/toolkit-msf/toolkit_rpc.rb
python3 -m venv /opt/toolkit-msf/venv
/opt/toolkit-msf/venv/bin/python -m pip install --require-hashes -r "$script_dir/requirements/pty.txt"
install -m 755 "$script_dir/pty-host.py" /opt/toolkit-msf/pty-host.py
install -m 755 "$script_dir/payload-host.py" /opt/toolkit-msf/payload-host.py
install -m 644 "$script_dir/toolkit_bridge.rb" /opt/toolkit-msf/toolkit_bridge.rb
install -m 644 "$script_dir/toolkit_bridge.rc" /opt/toolkit-msf/toolkit_bridge.rc
echo 'Installed. Start RPC as your ordinary user: python3 /opt/toolkit-msf/start-msfrpc.py'
echo 'The password is prompted privately; no daemon was started by provisioning.'
