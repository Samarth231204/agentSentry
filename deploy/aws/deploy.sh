#!/usr/bin/env bash
# AgentGuard on AWS: one EC2 instance running the Docker image (dashboard + both A2A services).
#
#   deploy/aws/deploy.sh up        create everything (S3, SSM keys, IAM role, security group, EC2) and start
#   deploy/aws/deploy.sh update    upload the current code and rebuild/restart on the instance
#   deploy/aws/deploy.sh keys      copy .env into SSM again, then restart the container
#   deploy/aws/deploy.sh allow-ip  let your current IP reach the dashboard
#   deploy/aws/deploy.sh url       print the dashboard link with your login token
#   deploy/aws/deploy.sh status | start | stop | logs
#
# Layout: AgentGuard/ and the demo target vuln-agent-lab/ side by side (VULNLAB=... to change).
# Keys: SSM Parameter Store, SecureString, /agentguard/<NAME>. Run results: s3://<bucket>/runs/.
# Access: dashboard port 8765 from your IP only, plus a login token (AGENTGUARD_DASHBOARD_TOKEN in .env,
# created on first 'up' or 'keys'); no SSH port (shell: aws ssm start-session).
set -euo pipefail

REGION="${AWS_REGION:-ap-south-1}"
NAME=agentguard
TYPE="${INSTANCE_TYPE:-m7i-flex.large}"
PORT=8765
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
VULNLAB="${VULNLAB:-$REPO/../vuln-agent-lab}"
ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
BUCKET="${NAME}-${ACCOUNT}-${REGION}"
AWS=(aws --region "$REGION")

say() { printf '\033[1m==>\033[0m %s\n' "$*" >&2; }

instance_id() {
  "${AWS[@]}" ec2 describe-instances --filters "Name=tag:Name,Values=$NAME" \
    "Name=instance-state-name,Values=pending,running,stopping,stopped" \
    --query 'Reservations[].Instances[0].InstanceId' --output text | awk '{print $1}' | grep -v None || true
}

my_ip() { curl -fs https://checkip.amazonaws.com | tr -d '[:space:]'; }

bucket() {
  if ! "${AWS[@]}" s3api head-bucket --bucket "$BUCKET" 2>/dev/null; then
    say "S3 bucket $BUCKET"
    "${AWS[@]}" s3api create-bucket --bucket "$BUCKET" --create-bucket-configuration "LocationConstraint=$REGION" >/dev/null
  fi
  "${AWS[@]}" s3api put-public-access-block --bucket "$BUCKET" --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
  "${AWS[@]}" s3api put-bucket-encryption --bucket "$BUCKET" --server-side-encryption-configuration \
    '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
}

release() {
  say "package AgentGuard + $(basename "$VULNLAB") (no .env, no runs, no local plan)"
  local tmp; tmp="$(mktemp -d)"
  COPYFILE_DISABLE=1 tar -czf "$tmp/agentguard.tgz" -C "$(dirname "$REPO")" \
    --exclude '.env' --exclude '.env.local' --exclude '.git' --exclude '.venv' --exclude 'venv' \
    --exclude '.agentguard' --exclude '.claude' --exclude 'IMPLEMENTATION_PLAN.md' --exclude '__pycache__' \
    --exclude 'build' --exclude '*.egg-info' --exclude '.pytest_cache' --exclude '.DS_Store' \
    "$(basename "$REPO")" -C "$(dirname "$VULNLAB")" "$(basename "$VULNLAB")"
  if tar -tzf "$tmp/agentguard.tgz" | grep -E '(^|/)\.env$|IMPLEMENTATION_PLAN' ; then
    echo "refusing to upload: secrets or the local plan are in the package" >&2; exit 1
  fi
  "${AWS[@]}" s3 cp "$tmp/agentguard.tgz" "s3://$BUCKET/release/agentguard.tgz" --only-show-errors
  "${AWS[@]}" s3 cp "$HERE/install.sh" "s3://$BUCKET/release/install.sh" --only-show-errors
  rm -rf "$tmp"
}

ensure_token() {  # a random dashboard login token in .env, created once; never printed here
  if ! grep -qE '^AGENTGUARD_DASHBOARD_TOKEN=.+' "$REPO/.env"; then
    printf '\n# Dashboard login (open the dashboard once with ?token=<this>)\nAGENTGUARD_DASHBOARD_TOKEN=%s\n' \
      "$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')" >> "$REPO/.env"
    say "created AGENTGUARD_DASHBOARD_TOKEN in .env"
  fi
}

dashboard_url() {
  local ip token
  ip="$("${AWS[@]}" ec2 describe-instances --instance-ids "$(instance_id)" \
        --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)"
  token="$(grep -E '^AGENTGUARD_DASHBOARD_TOKEN=' "$REPO/.env" | tail -1 | cut -d= -f2-)"
  echo "http://$ip:$PORT/?token=$token"
}

keys() {
  ensure_token
  say "keys and settings from $REPO/.env -> SSM /agentguard/ (SecureString)"
  # boto3 cannot read `aws login` sessions directly; hand it the CLI's current credentials (this subshell only)
  ( eval "$(aws configure export-credentials --format env)"; python3 "$HERE/put_params.py" "$REPO/.env" "$REGION" )
}

role() {
  if ! aws iam get-role --role-name "$NAME-ec2" >/dev/null 2>&1; then
    say "IAM role $NAME-ec2"
    aws iam create-role --role-name "$NAME-ec2" --assume-role-policy-document \
      '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}' >/dev/null
    aws iam attach-role-policy --role-name "$NAME-ec2" --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
    aws iam create-instance-profile --instance-profile-name "$NAME-ec2" >/dev/null
    aws iam add-role-to-instance-profile --instance-profile-name "$NAME-ec2" --role-name "$NAME-ec2"
  fi
  aws iam put-role-policy --role-name "$NAME-ec2" --policy-name "$NAME-access" --policy-document "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [
      {\"Effect\": \"Allow\", \"Action\": [\"ssm:GetParametersByPath\", \"ssm:GetParameters\"],
       \"Resource\": \"arn:aws:ssm:$REGION:$ACCOUNT:parameter/agentguard/*\"},
      {\"Effect\": \"Allow\", \"Action\": \"ssm:GetParametersByPath\",
       \"Resource\": \"arn:aws:ssm:$REGION:$ACCOUNT:parameter/agentguard\"},
      {\"Effect\": \"Allow\", \"Action\": \"s3:GetObject\", \"Resource\": \"arn:aws:s3:::$BUCKET/release/*\"},
      {\"Effect\": \"Allow\", \"Action\": [\"s3:PutObject\", \"s3:GetObject\"], \"Resource\": \"arn:aws:s3:::$BUCKET/runs/*\"},
      {\"Effect\": \"Allow\", \"Action\": \"s3:ListBucket\", \"Resource\": \"arn:aws:s3:::$BUCKET\"}
    ]}"
}

security_group() {
  local vpc sg
  vpc="$("${AWS[@]}" ec2 describe-vpcs --filters Name=is-default,Values=true --query 'Vpcs[0].VpcId' --output text)"
  sg="$("${AWS[@]}" ec2 describe-security-groups --filters "Name=group-name,Values=$NAME" "Name=vpc-id,Values=$vpc" \
        --query 'SecurityGroups[0].GroupId' --output text)"
  if [ "$sg" = "None" ]; then
    sg="$("${AWS[@]}" ec2 create-security-group --group-name "$NAME" --vpc-id "$vpc" \
          --description "AgentGuard dashboard, allowed IPs only" --query GroupId --output text)"
  fi
  echo "$sg"
}

allow_ip() {
  local sg ip; sg="$(security_group)"; ip="$(my_ip)"
  "${AWS[@]}" ec2 authorize-security-group-ingress --group-id "$sg" --ip-permissions \
    "IpProtocol=tcp,FromPort=$PORT,ToPort=$PORT,IpRanges=[{CidrIp=$ip/32,Description=agentguard-user}]" >/dev/null 2>&1 \
    && say "dashboard port $PORT open to your current IP" || say "your current IP already has access"
}

user_data() {
  cat <<EOF
#!/bin/bash
set -euxo pipefail
dnf install -y docker
systemctl enable --now docker
export REGION=$REGION BUCKET=$BUCKET
aws s3 cp s3://$BUCKET/release/install.sh /opt/install.sh --region $REGION
bash /opt/install.sh > /var/log/agentguard-install.log 2>&1
EOF
}

create_instance() {
  local sg ami id
  sg="$(security_group)"
  ami="$("${AWS[@]}" ssm get-parameter --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 \
         --query Parameter.Value --output text)"
  say "EC2 $TYPE (Amazon Linux 2023, 30 GB gp3, IMDSv2) in $REGION"
  for i in $(seq 1 10); do  # a new instance profile takes a few seconds to become usable
    id="$("${AWS[@]}" ec2 run-instances --image-id "$ami" --instance-type "$TYPE" --security-group-ids "$sg" \
          --iam-instance-profile "Name=$NAME-ec2" --user-data "$(user_data)" \
          --metadata-options HttpTokens=required,HttpEndpoint=enabled \
          --block-device-mappings 'DeviceName=/dev/xvda,Ebs={VolumeSize=30,VolumeType=gp3,Encrypted=true,DeleteOnTermination=true}' \
          --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$NAME},{Key=project,Value=agentguard}]" \
          --query 'Instances[0].InstanceId' --output text 2>/dev/null)" && break
    sleep 6
  done
  [ -n "${id:-}" ] || { echo "could not start the instance" >&2; exit 1; }
  echo "$id"
}

wait_ready() {
  local id="$1" ip
  say "waiting for the instance and the first build (about 5-8 minutes)"
  "${AWS[@]}" ec2 wait instance-running --instance-ids "$id"
  ip="$("${AWS[@]}" ec2 describe-instances --instance-ids "$id" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)"
  for i in $(seq 1 90); do
    if curl -fs -m 4 "http://$ip:$PORT/healthz" >/dev/null; then
      say "AgentGuard is live. Open (keep this link private): $(dashboard_url)"; return 0
    fi
    sleep 10
  done
  echo "not answering yet; check: deploy/aws/deploy.sh logs" >&2; return 1
}

run_on_instance() {  # runs a shell command on the instance through SSM, prints its output
  local id cmd_id; id="$(instance_id)"
  cmd_id="$("${AWS[@]}" ssm send-command --instance-ids "$id" --document-name AWS-RunShellScript \
            --parameters "commands=[\"$1\"]" --timeout-seconds 1800 --query Command.CommandId --output text)"
  for i in $(seq 1 180); do
    local st; st="$("${AWS[@]}" ssm get-command-invocation --command-id "$cmd_id" --instance-id "$id" \
                   --query Status --output text 2>/dev/null || echo Pending)"
    case "$st" in Success|Failed|Cancelled|TimedOut)
      "${AWS[@]}" ssm get-command-invocation --command-id "$cmd_id" --instance-id "$id" \
        --query '[StandardOutputContent,StandardErrorContent]' --output text | tail -40
      [ "$st" = Success ]; return;;
    esac
    sleep 5
  done
}

case "${1:-}" in
  up)
    bucket; keys; role; release; allow_ip
    id="$(instance_id)"
    if [ -z "$id" ]; then id="$(create_instance)"; else say "instance $id exists; use 'update' to redeploy"; fi
    wait_ready "$id" ;;
  update)
    release
    say "rebuild and restart on the instance"
    run_on_instance "aws s3 cp s3://$BUCKET/release/install.sh /opt/install.sh --region $REGION && REGION=$REGION BUCKET=$BUCKET bash /opt/install.sh" ;;
  keys)
    keys
    run_on_instance "REGION=$REGION BUCKET=$BUCKET bash /opt/install.sh" ;;
  allow-ip) allow_ip ;;
  url) dashboard_url ;;
  start)
    id="$(instance_id)"; "${AWS[@]}" ec2 start-instances --instance-ids "$id" >/dev/null; wait_ready "$id" ;;
  stop)
    id="$(instance_id)"; "${AWS[@]}" ec2 stop-instances --instance-ids "$id" >/dev/null
    say "stopping $id (only the disk is billed while stopped)" ;;
  status)
    "${AWS[@]}" ec2 describe-instances --filters "Name=tag:Name,Values=$NAME" \
      --query 'Reservations[].Instances[].[InstanceId,InstanceType,State.Name,PublicIpAddress]' --output table ;;
  logs) run_on_instance "tail -30 /var/log/agentguard-install.log; docker ps; docker logs --tail 60 agentguard 2>&1" ;;
  *) sed -n 2,15p "$0"; exit 1 ;;
esac
