"""Check a provider key works.

    uv run python scripts/hello.py gemini              # list model IDs
    uv run python scripts/hello.py gemini <model-id>   # one short test call

Reads keys from .env. Prints no secrets.
"""

import os
import sys
import tomllib
from pathlib import Path

import openai
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent


def load_providers() -> dict:
    with open(ROOT / "config" / "providers.toml", "rb") as f:
        return tomllib.load(f)


def main(argv: list[str]) -> int:
    providers = load_providers()
    if len(argv) < 2 or argv[1] not in providers:
        print(f"usage: hello.py <{'|'.join(providers)}> [model-id]")
        return 2
    name = argv[1]
    cfg = providers[name]
    load_dotenv(ROOT / ".env")
    key = os.environ.get(cfg["api_key_env"])
    if not key:
        print(f"{cfg['api_key_env']} is not set (put it in .env)")
        return 1
    client = openai.OpenAI(api_key=key, base_url=cfg["base_url"])
    try:
        if len(argv) == 2:
            for m in client.models.list():
                print(m.id)
            return 0
        resp = client.chat.completions.create(
            model=argv[2],
            messages=[{"role": "user", "content": "Reply with the single word: ok"}],
            max_tokens=200,
        )
        print("model:", resp.model)
        print("reply:", (resp.choices[0].message.content or "").strip())
        print("usage:", resp.usage)
        return 0
    except openai.APIStatusError as e:
        print(f"API error {e.status_code}: {e.message}")
        return 1
    except openai.APIConnectionError as e:
        print(f"Connection error: {type(e).__name__}")
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
