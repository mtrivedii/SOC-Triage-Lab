import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_providers_config_is_sane():
    with open(ROOT / "config" / "providers.toml", "rb") as f:
        cfg = tomllib.load(f)
    assert set(cfg) == {"gemini", "groq"}
    for p in cfg.values():
        assert p["base_url"].startswith("https://")
        assert p["api_key_env"].endswith("_API_KEY")


def test_models_config_pins_one_model_per_provider():
    with open(ROOT / "config" / "models.toml", "rb") as f:
        models = tomllib.load(f)
    with open(ROOT / "config" / "providers.toml", "rb") as f:
        providers = tomllib.load(f)
    assert set(models) == set(providers)
    for m in models.values():
        assert m["model"] and "latest" not in m["model"] and "preview" not in m["model"]
        assert m["confirmed"]


def test_env_example_has_no_values():
    for line in (ROOT / ".env.example").read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            assert line.split("=", 1)[1].strip() == ""
