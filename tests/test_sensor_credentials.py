import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    'sensor_credentials', Path(__file__).resolve().parents[1] / 'infra/sensor-credentials.py')
manager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manager)


class CertificateEnrollmentTests(unittest.TestCase):
    def test_approved_csr_can_be_issued_renewed_and_revoked(self):
        site = 'lisboa'
        registry = {'metadata': {'resourceVersion': '1'}, 'data': {}}
        resources = {'sensor-digests': registry}

        def kube(namespace, action, *args, document=None):
            self.assertEqual(namespace, site)
            if action == 'get':
                return json.dumps(resources[args[1]]) if args[1] in resources else ''
            if action == 'create':
                resources[document['metadata']['name']] = document
                return ''
            self.assertEqual(action, 'patch')
            self.assertEqual(document['metadata'], registry['metadata'])
            for identity, value in document['data'].items():
                if value is None:
                    del registry['data'][identity]
                else:
                    registry['data'][identity] = value
            registry['metadata']['resourceVersion'] = str(int(registry['metadata']['resourceVersion']) + 1)
            return ''

        with tempfile.TemporaryDirectory() as work, patch.object(manager, 'kube', side_effect=kube):
            ca = manager.bootstrap_ca(site)
            self.assertEqual(manager.bootstrap_ca(site), ca)
            work = Path(work)
            csr, leaf, renewed = (work / name for name in ('sensor.csr', 'sensor.crt', 'renewed.crt'))
            manager.openssl('req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
                            '-nodes', '-subj', '/CN=claimed-id', '-addext', 'basicConstraints=CA:TRUE',
                            '-keyout', work / 'sensor.key', '-out', csr)
            device = manager.issue(site, csr, leaf)
            self.assertRegex(device, r'^pt\.lisboa\.sensor\.[a-f0-9]{20}$')
            subject = manager.openssl('x509', '-in', leaf, '-noout', '-subject', '-nameopt', 'RFC2253')
            self.assertEqual(subject.decode().strip(), f'subject=CN={device}')
            extensions = manager.openssl('x509', '-in', leaf, '-noout', '-ext', 'basicConstraints')
            self.assertIn(b'CA:FALSE', extensions)
            digest = hashlib.sha256(manager.openssl('x509', '-in', leaf, '-outform', 'DER')).hexdigest()
            self.assertEqual(registry['data'][device], manager.encoded('x509:' + digest))
            with self.assertRaises(ValueError):
                manager.update(site, device, '0' * 64, require=True)
            self.assertEqual(manager.issue(site, csr, renewed, device), device)
            self.assertNotEqual(registry['data'][device], manager.encoded('x509:' + digest))
            manager.update(site, device, require=True)
            self.assertEqual(registry['data'], {})
            with self.assertRaises(ValueError):
                manager.issue(site, csr, work / 'missing.crt', device)
            self.assertFalse((work / 'missing.crt').exists())

    def test_bad_csr_does_not_publish_a_credential(self):
        with tempfile.TemporaryDirectory() as work:
            work = Path(work)
            csr, leaf = work / 'sensor.csr', work / 'sensor.crt'
            csr.write_bytes(b'invalid request')
            with patch.object(manager, 'kube') as kube:
                kube.return_value = ''
                manager.bootstrap_ca('porto')
                issuer = kube.call_args.kwargs['document']
                kube.reset_mock()
                kube.return_value = json.dumps(issuer)
                with self.assertRaisesRegex(ValueError, 'OpenSSL x509'):
                    manager.issue('porto', csr, leaf)
                kube.assert_called_once_with('porto', 'get', 'secret', manager.CLIENT_CA, '-o', 'json')
            self.assertFalse(leaf.exists())
