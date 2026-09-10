import click


@click.group()
def main() -> None:
    """AgentGuard — automated red-teaming for AI agent applications."""


if __name__ == "__main__":
    main()
