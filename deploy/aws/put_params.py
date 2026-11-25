"""Copies the keys and settings from a local .env into SSM Parameter Store (SecureString, /agentguard/<NAME>).

Values are sent with boto3, never printed and never put on a command line.
    python3 deploy/aws/put_params.py .env ap-south-1
"""

import sys
from pathlib import Path

import boto3

PREFIX = "/agentguard/"
# Settings that only make sense on a laptop are left out.
SKIP = {"AGENTGUARD_A2A_ATTACK_URL", "AGENTGUARD_A2A_REVIEW_URL"}


def read_env(path: Path) -> dict[str, str]:
    out = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip().removeprefix("export ").strip(), value.strip().strip('"').strip("'")
        if key and value and key not in SKIP:
            out[key] = value
    return out


def main() -> None:
    env_file, region = Path(sys.argv[1]), sys.argv[2]
    ssm = boto3.client("ssm", region_name=region)
    values = read_env(env_file)
    for key, value in values.items():
        ssm.put_parameter(Name=PREFIX + key, Value=value, Type="SecureString", Overwrite=True,
                          Description="AgentGuard setting (from .env)")
    print(f"{len(values)} parameters written under {PREFIX}: {', '.join(sorted(values))}")


if __name__ == "__main__":
    main()
