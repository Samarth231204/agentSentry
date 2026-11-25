#!/usr/bin/env bash
# Runs ON the EC2 instance (first boot via user data, and on every `deploy.sh update`).
# Downloads the release from S3, builds the image, loads the keys from SSM, (re)starts the container,
# and sets up the run-results sync to S3.
set -euo pipefail

REGION="${REGION:?}"; BUCKET="${BUCKET:?}"; PREFIX="${PARAM_PREFIX:-/agentguard/}"
HOME_DIR=/opt/agentguard
mkdir -p "$HOME_DIR" && cd "$HOME_DIR"

echo "==> download release"
aws s3 cp "s3://$BUCKET/release/agentguard.tgz" release.tgz --region "$REGION" --only-show-errors
rm -rf AgentGuard.new && mkdir AgentGuard.new && tar -xzf release.tgz -C AgentGuard.new
rm -rf AgentGuard && mv AgentGuard.new/AgentGuard AgentGuard
# The demo target (VulnLab). Run results live in it (.agentguard/), so keep them across updates.
mkdir -p vuln-agent-lab && cp -a AgentGuard.new/vuln-agent-lab/. vuln-agent-lab/ && rm -rf AgentGuard.new

echo "==> build image"
docker build -q -t agentguard:latest AgentGuard

echo "==> keys from SSM ($PREFIX)"
umask 077
aws ssm get-parameters-by-path --path "$PREFIX" --with-decryption --region "$REGION" \
  --query 'Parameters[].[Name,Value]' --output text \
  | while IFS=$'\t' read -r name value; do printf '%s=%s\n' "${name#"$PREFIX"}" "$value"; done > env.tmp
printf 'AGENTGUARD_DEPLOYMENT=aws-ec2\n' >> env.tmp

echo "==> (re)start container"
docker rm -f agentguard >/dev/null 2>&1 || true
docker run -d --name agentguard --restart unless-stopped --env-file env.tmp -p 8765:8765 \
  -v "$HOME_DIR/vuln-agent-lab:/project" agentguard:latest >/dev/null
rm -f env.tmp

echo "==> run results -> s3://$BUCKET/runs/ every 5 minutes"
cat > /etc/systemd/system/agentguard-sync.service <<EOF
[Unit]
Description=Copy AgentGuard run results to S3
[Service]
Type=oneshot
ExecStart=/usr/bin/aws s3 sync $HOME_DIR/vuln-agent-lab/.agentguard/runs s3://$BUCKET/runs/ --region $REGION --only-show-errors --exclude "*.db-shm" --exclude "*.db-wal"
EOF
cat > /etc/systemd/system/agentguard-sync.timer <<EOF
[Unit]
Description=Copy AgentGuard run results to S3 every 5 minutes
[Timer]
OnBootSec=5min
OnUnitActiveSec=5min
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload && systemctl enable --now agentguard-sync.timer

for i in $(seq 1 60); do
  curl -fs http://127.0.0.1:8765/api/a2a >/dev/null && { echo "==> AgentGuard is up on :8765"; exit 0; }
  sleep 2
done
echo "AgentGuard did not answer on :8765" >&2; docker logs --tail 50 agentguard >&2; exit 1
