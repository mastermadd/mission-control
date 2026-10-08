# JDLN Mission Control — internal edition

The existing Mission Control dashboard, with a local Node.js backend and SQLite database. Run it on your LAN and reach it remotely through a **private** Pangolin resource. No public inbound connection or separate gateway is required.

## Install

Use a dedicated Debian 12/13 or Ubuntu 24.04 VM, with outbound internet access for GitHub, Docker packages and the Node container image. Docker must be supported by the host; a Proxmox VM is simpler than a restricted LXC. The installer supports AMD64 and ARM64 through the Node image.

```bash
curl -fsSL https://raw.githubusercontent.com/mastermadd/mission-control/main/install.sh | sudo bash
```

The installer reads prompts from the terminal even when piped into Bash. It asks for an existing private LAN IPv4 address, dashboard URL, admin username/password, and an exact API host:port allowlist. Use the real dashboard URL you will browse: login and writes enforce that origin. The default is `http://<LAN-IP>:8080`. Use an internal HTTPS reverse proxy with a trusted certificate for encrypted browser connections; set that HTTPS origin during installation. Nothing modifies your router, DNS, Pangolin resources or public port forwards.

Docker and Compose are installed from Docker's official repository if missing. The application is built and tested locally from one exact Git commit before startup. Data stays under `/opt/mission-control/data`; configuration, password hash and encryption key under `/opt/mission-control/config`. Secrets are never uploaded to GitHub. The admin password is hashed with scrypt; integration credentials use AES-GCM. Cookie sessions are HttpOnly and SameSite=Strict, with Secure on HTTPS. Incoming ChatGPT identity headers are ignored.

Only approved endpoints can be used. Example allowlist: `192.168.5.3:3003,unifi.jdln.co.za:8443`. HTTP may be used for explicitly approved internal endpoints; HTTPS verification remains enabled. Controllers with a private certificate authority need their CA trusted by the application container; never disable verification.

## Move your hosted records

1. In the current ChatGPT dashboard choose **Export report**.
2. Sign in to the internal dashboard and choose **Import hosted workspace** at the bottom right.
3. Select the JSON export. Import is restricted to an empty workspace and drops unknown fields.
4. Customers, manual assets, alerts, tasks, activity and integration settings are imported. Credentials, cookies and live caches are deliberately excluded. Edit each integration and enter its credentials on your internal dashboard.
5. Change integration URLs to their approved internal addresses and test them. For Pangolin itself, use its actual Integration API host/port, not the dashboard port. Keep UniFi's valid HTTPS certificate verification enabled.

Keep using the hosted site until you verify the internal installation and imported records. The installer does not delete or change the hosted site. No live customer data is shipped in this repository.

## Updates, backups and rollback

```bash
sudo mission-control status
sudo mission-control update
sudo mission-control backup
sudo mission-control rollback
sudo mission-control targets
sudo mission-control logs
```

Update checks `main`, builds/tests the next image while the existing app is running, stops it briefly for a consistent database/configuration backup, starts the new version and checks container health. A failed startup automatically restores the previous database and app. Successful updates retain the previous image and a backup. Database migrations are tracked by name and checksum; applied migrations must never be edited.

Rollback asks for `RESTORE` and restores the entire pre-update database/configuration and image. **Records changed after the last update will be lost in the restored state.** A safety backup of the replaced state is made first. Backups contain keys and customer data; keep them private and copy them to your protected backup storage. They are not sent to GitHub. No automatic updates or image cleanup are enabled.

Use one installation per machine. The management command serializes maintenance with a file lock. Never remove `data` or rotate the encryption key during an update.

## Development workflow

GitHub is the deployment source. Changes go through a branch/PR; checks compile the API, exercise the local runtime and build the Docker image. Once the reviewed code is merged to `main`, run `sudo mission-control update` internally. ChatGPT does not need inbound access to your server. Do not put runtime secrets, exports or backups into Git.

```bash
npm ci --ignore-scripts
npm run build
npm test
bash -n install.sh mission-control
```

Docker runs as the non-root `node` user with a read-only application filesystem and dropped capabilities. Persistent directories belong to UID 1000. `/healthz` is a minimal health endpoint; application and API access requires a local session. The server polls integrations every 60 seconds, including while nobody has the UI open. Existing demo-only agent chat/dispatch remains unfinished; migration does not invent new agent functionality.
