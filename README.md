# wol-portal

Small web app to power LAN hosts on and off. Users log in with OpenID Connect and see a list of
hosts with their state: **online**, **offline**, **starting** or **shutting down**.

- **Power on** sends a Wake-on-LAN magic packet to the host's MAC address.
- **Shut down** connects over SSH (key auth) and runs the host's configured shutdown command.
- **State** is detected by a TCP connect to the host's SSH port every few seconds. A host is
  *starting* / *shutting down* from the moment an action is triggered until the probe flips, or a
  timeout (default 10 min) expires and an error is shown.

## Configuration

### Hosts (`hosts.yaml`)

See [config/hosts.example.yaml](config/hosts.example.yaml). Required per host: `name`, `ip`, `mac`,
`shutdown_command`, `ssh_key`. Optional: `ssh_user`, `ssh_port`, `allowed_groups`.
The shutdown command comes only from this file; clients cannot influence it. Private keys must not be
passphrase-protected.

### Environment

See [.env.example](.env.example). Important ones:

| Variable | Meaning |
|---|---|
| `WOLP_BASE_URL` | Public URL of the portal. Register `<base>/auth/callback` as redirect URI at your IdP |
| `WOLP_OIDC_ISSUER` / `_CLIENT_ID` / `_CLIENT_SECRET` | OIDC client registration |
| `WOLP_GROUPS_CLAIM` | Claim holding the user's groups (default `groups`; string or list) |
| `WOLP_ALLOWED_GROUPS` | Groups allowed to log in and view hosts |
| `WOLP_ADMIN_GROUPS` | Optional. If set, only these groups may power hosts on/off (others are view-only) |
| `WOLP_SESSION_SECRET` | ≥ 32 random bytes; encrypts the session cookie |
| `WOLP_KNOWN_HOSTS` | known_hosts file used to verify the hosts' SSH host keys (required) |
| `WOLP_WOL_BROADCAST` | Broadcast `addr:port`, e.g. `192.168.1.255:9` |

Authorization: a user needs a group in `WOLP_ALLOWED_GROUPS` (or `WOLP_ADMIN_GROUPS`). Power actions
require `WOLP_ADMIN_GROUPS` membership if that is set; a host's `allowed_groups` replaces that rule
for the host (admins may still control it). Without either, everyone with access may control all hosts.

TLS is expected to be terminated by a reverse proxy; cookies get the `Secure` flag when
`WOLP_BASE_URL` is `https://`.

## Run

```bash
cp .env.example .env && cp config/hosts.example.yaml hosts.yaml   # edit both
ssh-keyscan -H 192.168.1.20 >> known_hosts                          # verify fingerprints!
docker compose up -d --build
```

Host networking is used so the UDP broadcast reaches the LAN; the portal must sit in the same layer-2
segment as the hosts. Without Docker: `go build ./cmd/wol-portal` and export the variables.

## Host requirements

Wake-on-LAN enabled in BIOS/NIC (`ethtool -s <nic> wol g`), and an SSH account whose key is in
`authorized_keys` and that may run the shutdown command (e.g. `sysconf appliance poweroff -f`). The default SSH user is `wol-portal`.

## Development

```bash
go vet ./... && go test ./...
```
