# JDLN Mission Control — internal edition

The existing Mission Control dashboard, with a local Node.js backend and SQLite database. Run it on your LAN and reach it remotely through a **private** Pangolin resource. No public inbound connection or separate gateway is required.

## Install

Use a dedicated Debian 12/13, Ubuntu 24.04, or Kali Linux VM, with outbound internet access for GitHub, Docker packages and the Node container image. Docker must be supported by the host; a Proxmox VM is simpler than a restricted LXC. The installer supports AMD64 and ARM64 through the Node image.

```bash
curl -fsSL https://raw.githubusercontent.com/mastermadd/mission-control/main/install.sh | sudo bash
```

The installer reads prompts from the terminal even when piped into Bash. It asks for an existing private LAN IPv4 address, dashboard URL, admin username/password. Use the real dashboard URL you will browse: login and writes enforce that origin. The default is `http://<LAN-IP>:8080`. Use an internal HTTPS reverse proxy with a trusted certificate for encrypted browser connections; set that HTTPS origin during installation. Nothing modifies your router, DNS, Pangolin resources or public port forwards.

Docker and Compose are installed from Docker's official repository if missing. Kali uses Docker's Debian `trixie` repository, following [Kali's Docker installation documentation](https://www.kali.org/docs/containers/installing-docker-on-kali/). An existing working Docker/Compose installation is reused; the Docker service is started if needed. The application is built and tested locally from one exact Git commit before startup. Data stays under `/opt/mission-control/data`; configuration, password hash and encryption key under `/opt/mission-control/config`. Secrets are never uploaded to GitHub. The admin password is hashed with scrypt; integration credentials use AES-GCM. Cookie sessions are HttpOnly and SameSite=Strict, with Secure on HTTPS. Incoming ChatGPT identity headers are ignored.

Internal HTTP and HTTPS resources can be reached using IP addresses, DNS names, IPv6 addresses and custom ports. Existing loopback and metadata-service protections remain in place. No endpoint allowlist is required. HTTPS certificate verification remains enabled. Existing installations may retain an unused `allowedTargets` field in their configuration; it is ignored, and no configuration edits or credential changes are needed. Controllers with a private certificate authority need their CA trusted by the application container; never disable verification.

## Move your hosted records

1. In the current ChatGPT dashboard choose **Export report**.
2. Sign in to the internal dashboard and open the top-right user menu and choose **Import workspace**.
3. Select the JSON export. Import is restricted to an empty workspace and drops unknown fields.
4. Customers, manual assets, alerts, tasks, activity and integration settings are imported. Credentials, cookies and live caches are deliberately excluded. Edit each integration and enter its credentials on your internal dashboard.
5. Change integration URLs to their internal addresses and test them. For Pangolin itself, use its actual Integration API host/port, not the dashboard port. Keep UniFi's valid HTTPS certificate verification enabled.

Keep using the hosted site until you verify the internal installation and imported records. The installer does not delete or change the hosted site. No live customer data is shipped in this repository.

## Updates, backups and rollback

```bash
sudo mission-control status
sudo mission-control update
sudo mission-control backup
sudo mission-control rollback
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

## MikroTik native API

Select **MikroTik Native API** to monitor through RouterOS's binary API, without enabling WebFig/REST. Choose **Plain TCP** for the internal `api` service and enter `tcp://<router-IP>:8728`, or choose **TLS** for `api-ssl` and enter `tls://<router-hostname>:8729`. Custom ports and IPv6 are supported. Other HTTP/HTTPS integrations remain supported. MikroTik uses its native TCP protocol only.

Enable the chosen service in RouterOS **IP → Services** and allow the dashboard server through its address restrictions and firewall. Use a dedicated local account with a custom group containing `read,api` policies. Changing an existing integration to the native connector preserves its saved credentials when the fields are blank. Plain TCP transmits the account credentials without encryption; API-SSL verifies the server certificate and hostname. Certificate-less anonymous-DH API-SSL is not supported.

A poll opens one backend socket, uses the RouterOS 6.43+ login flow, runs `/system/identity/print`, `/system/resource/print` and `/interface/print` with explicit property lists, then closes it. RouterOS 7.15.1 is supported. No write/configuration/reboot commands are allowed. Timeouts, bounded response parsing, encrypted credential storage, 60-second polling, stale cache handling and customer-linked asset rules apply to both MikroTik connectors. Native connections resolve DNS on the server and reject loopback/metadata destinations before opening the socket. HTTP Pangolin resource tokens cannot be applied to this native TCP connection; connect to an internal address reachable from the dashboard server.

Native API tests generate a disposable TLS identity in memory. No TLS private keys or runtime credentials are committed to the repository.

Saved entries from the removed MikroTik REST connector are not polled. Open Edit to switch them to MikroTik Native API, confirm the API address/port and save; blank credential fields retain their existing encrypted values. Entries can also be removed directly.

## AdGuard Home connector

Choose **AdGuard Home** in Integrations, assign the customer and enter its web interface URL, optionally ending in `/control`. Internal HTTP and HTTPS are supported, including custom web ports. Use the web-interface username and password; the connector automatically chooses Direct and Basic authentication. Changing an existing generic AdGuard integration preserves its encrypted saved credentials when the fields are blank. HTTPS certificate verification remains enabled. If the service is protected by Pangolin HTTP resource authentication, enter that resource token separately.

A connection test must read both `GET /control/status` and `GET /control/stats` successfully. The backend allows these two read endpoints only; it cannot change protection, filtering rules, DNS settings, reset statistics or fetch query logs. Authentication is stored encrypted and never returned to the frontend. AdGuard accounts can have broader permissions than these two reads; the connector itself restricts all its requests to GET status/statistics.

Every 60 seconds the backend refreshes version, DNS running state, protection state, configured ports, web API start time (when reported), total queries, filtering-blocked queries, safe-browsing/parental-blocked totals, safe-search replacements and average processing time in milliseconds. Statistics represent AdGuard's configured reporting window, not the latest 60 seconds or necessarily today. Filtering percentage uses only filtering-blocked queries. Raw client/domain rankings, addresses, upstream details and browsing/query logs are not returned or cached. Older versions that omit DNS running state display Unknown rather than inventing a healthy/offline state.

The server appears as an integration-managed DNS asset in Overview, Customers, Infrastructure and Network. Network and View data show its status/statistics; confirmed stopped DNS or disabled protection generates an alert. Failed polls retain the previous successful data and mark it stale. Polls have timeouts, a lease prevents overlap, and configuration revisions discard late writes after edits or deletion. Removing the integration or its customer removes cached data and the derived DNS asset.
