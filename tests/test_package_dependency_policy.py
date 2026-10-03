"""Package-install policy, separate from the stdlib-only certification journey."""
from pathlib import Path
import tomllib

from packaging.requirements import Requirement


def test_package_install_rejects_vulnerable_cryptography_versions() -> None:
    # The deployment venv installs pyproject.toml, independently of the image lock.
    manifest = Path(__file__).resolve().parents[1] / "pyproject.toml"
    dependencies = tomllib.loads(manifest.read_text(encoding="utf-8"))["project"]["dependencies"]
    requirement = next(
        item for item in map(Requirement, dependencies) if item.name == "cryptography"
    )
    for vulnerable in ("44.0.0", "49.0.0", "49.0.1"):
        assert not requirement.specifier.contains(vulnerable)
    assert requirement.specifier.contains("50.0.0")
