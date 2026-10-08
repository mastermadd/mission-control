#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
IMAGE=${1:-mission-control:test}
WORK=$(mktemp -d)
CONTAINER=
cleanup(){ if [[ -n "$CONTAINER" ]]; then docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; fi; sudo rm -rf "$WORK"; }
trap cleanup EXIT
chmod 0755 "$WORK"
mkdir "$WORK/config" "$WORK/data"
chmod 0755 "$WORK/config" "$WORK/data"
sudo chown 1000:1000 "$WORK/config" "$WORK/data"
printf '%s' '{"username":"ci-admin","password":"ci-fixture-password-123","origin":"http://localhost:8080"}' | docker run --rm -i -v "$WORK/config:/config" "$IMAGE" node provision.mjs
# This verifies the real image user can read its scripts and its private generated configuration.
[[ $(stat -c '%a' "$WORK/config/config.json") == 600 ]]
CONTAINER=$(docker run -d --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true -v "$WORK/config:/config:ro" -v "$WORK/data:/data" "$IMAGE")
for attempt in $(seq 1 30); do
 status=$(docker inspect --format '{{.State.Health.Status}}' "$CONTAINER")
 if [[ "$status" == healthy ]]; then
  docker exec "$CONTAINER" node -e "if(process.getuid()===0)process.exit(1);fetch('http://127.0.0.1:8080/healthz').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"
  echo 'PASS: non-root provisioning, private configuration and production server health.'
  exit 0
 fi
 if [[ $(docker inspect --format '{{.State.Running}}' "$CONTAINER") != true ]]; then break; fi
 sleep 1
done
docker logs "$CONTAINER"
echo 'Production image failed to start.' >&2
exit 1
