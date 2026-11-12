"""Contract tests: run with python -m unittest discover -s tests."""
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
import universal_diagnostics as d


class States:
    def get(self, key):
        if key == "sensor.test":
            return SimpleNamespace(state="on", last_updated=datetime.now(timezone.utc))
        return None


class DiagnosticsTests(unittest.TestCase):
    def setUp(self):
        d.ADAPTERS.clear()
        self.hass = SimpleNamespace(states=States())

    def test_no_arbitrary_endpoint(self):
        self.assertEqual(d.inspect(self.hass, "bosch", "/secret")["reason"],
                         "adapter_not_registered")

    def test_allowlist(self):
        d.register_adapter(d.Adapter("bosch", "http", lambda _: {},
            lambda _, path: {"value": 1, "token": "must-not-leak"},
            frozenset({"/status"})))
        self.assertEqual(d.inspect(self.hass, "bosch", "/other")["reason"],
                         "resource_not_allowlisted")
        self.assertNotIn("token", d.inspect(self.hass, "bosch", "/status"))

    def test_snapshot(self):
        self.assertEqual(d.snapshot(self.hass, ["sensor.test"])["entities"]["sensor.test"]["state"], "on")
        with self.assertRaises(ValueError):
            d.snapshot(self.hass, ["http://localhost/secrets"])

    def test_monitor(self):
        a = {"captured_at": "1", "entities": {"sensor.test": {"state": "off"}}}
        b = {"captured_at": "2", "entities": {"sensor.test": {"state": "on"}}}
        self.assertEqual(len(d.monitor_diff(a, b)["changes"]), 1)


if __name__ == "__main__":
    unittest.main()
