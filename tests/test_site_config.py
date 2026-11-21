import json
from pathlib import Path
import runpy
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CONFIG = runpy.run_path(str(ROOT / 'infra/site-config.py'))


class SiteConfigTests(unittest.TestCase):
    def setUp(self):
        self.sites = json.loads((ROOT / 'kubernetes/sites.json').read_text())

    def load(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'sites.json'
            path.write_text(json.dumps(self.sites))
            return CONFIG['load_sites'](path)

    def test_new_site_has_its_own_targets_and_uses_existing_template(self):
        self.sites['braga'] = {'ingestion_replicas': 3, 'sensor_port': 30443, 'api_port': 30503,
                               'metrics_port': 30603, 'gateway_port': 8081}
        sites = self.load()
        manifest = CONFIG['manifest']('braga', sites['braga'], 'k3s2', '192.0.2.2', '192.0.2.3')
        self.assertIn("namespace: 'braga'", manifest)
        self.assertIn('nodePort: 30443', manifest)
        self.assertIn('replicas: 3', manifest)
        self.assertNotIn('name: registry', manifest)
        self.assertIn("kubernetes.io/hostname: 'k3s-master'", manifest)
        self.assertNotRegex(manifest, r'@[A-Z_]+@')
        settings = CONFIG['global_prometheus'](sites)
        targets = settings['scrape_configs'][-1]['static_configs']
        self.assertIn({'targets': ['k3s-master.incus:30603'], 'labels': {'site': 'braga'}}, targets)

    def test_duplicate_port_is_rejected_before_deploy(self):
        self.sites['porto']['sensor_port'] = self.sites['lisboa']['api_port']
        with self.assertRaisesRegex(ValueError, 'porta repetida'):
            self.load()
