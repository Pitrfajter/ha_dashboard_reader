"""Minimal offline tests for the safe inventory module."""
import tempfile
from pathlib import Path
from safe_export import inspect_integration

def test_inventory():
    with tempfile.TemporaryDirectory() as root:
        folder = Path(root) / "custom_components" / "bosch_homecom"
        folder.mkdir(parents=True)
        (folder / "sensor.py").write_text("VALUE = 35\n")
        (folder / "secrets.yaml").write_text("password: dont-export")
        report = inspect_integration(root)
        assert report["ready"]
        assert len(report["files"]) == 1
        assert report["files"][0]["path"] == "sensor.py"
        (folder / "config.py").write_text("password = 'example-secret-value'")
        report = inspect_integration(root)
        assert not report["ready"]
        assert report["blocked_count"] == 1

if __name__ == "__main__":
    test_inventory()
    print("PASS")
