"""Shared .env loader for Skills scripts. No external dependencies."""
import os

def load_env():
    """Load .env file from Skills/ directory into os.environ."""
    skills_dir = os.path.dirname(os.path.abspath(__file__))
    env_path = os.path.join(skills_dir, ".env")
    if not os.path.exists(env_path):
        return
    with open(env_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if key and key not in os.environ:
                os.environ[key] = value

load_env()
