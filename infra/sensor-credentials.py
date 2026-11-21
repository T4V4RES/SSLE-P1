#!/usr/bin/env python3
"""Gestor de sensores e emissão de certificados por um operador com acesso ao K3s."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
from tempfile import TemporaryDirectory

KUBECTL = ['incus', 'exec', 'k3s-master', '--mode=non-interactive', '--', 'k3s', 'kubectl']
CLIENT_CA = 'sensor-client-issuer'
CERT_PREFIX = 'x509:'
CERT_DAYS = 30


def kube(site, *args, document=None):
    result = subprocess.run([*KUBECTL, '-n', site, *args], text=True, capture_output=True,
                            input=None if document is None else json.dumps(document))
    if result.returncode:
        # Algumas mensagens kubectl incluem o corpo enviado. Evitar expor segredos.
        raise RuntimeError(f'kubectl {args[0]} falhou no namespace {site}')
    return result.stdout


def encoded(value):
    return base64.b64encode(value.encode()).decode()


def update(site, device, fingerprint=None, require=None):
    secret = json.loads(kube(site, 'get', 'secret', 'sensor-digests', '-o', 'json'))
    data = secret.get('data', {})
    if require is not None and (device in data) != require:
        raise ValueError('sensor já inscrito' if not require else 'sensor desconhecido')
    if device in data and fingerprint is not None:
        current = base64.b64decode(data[device]).decode()
        if current.startswith(CERT_PREFIX) != fingerprint.startswith(CERT_PREFIX):
            raise ValueError('o tipo de credencial do sensor não pode ser alterado')
    digest = None if fingerprint is None else encoded(fingerprint)
    if data.get(device) == digest:
        return
    patch = {'metadata': {'resourceVersion': secret['metadata']['resourceVersion']}, 'data': {device: digest}}
    kube(site, 'patch', 'secret', 'sensor-digests', '--type=merge', '--patch-file=/dev/stdin', document=patch)


def token_digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def bootstrap(site, device):
    existing = kube(site, 'get', 'secret', 'sensor-default', '--ignore-not-found', '-o', 'json')
    if existing:
        token = base64.b64decode(json.loads(existing)['data']['token']).decode()
    else:
        token = secrets.token_hex(32)
        kube(site, 'create', '-f', '-', document={'apiVersion': 'v1', 'kind': 'Secret',
             'metadata': {'name': 'sensor-default', 'namespace': site}, 'data': {'token': encoded(token)}})
    update(site, device, token_digest(token))


def register(site, device, output, credential, fingerprint, replace):
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(credential)
            handle.flush()
            os.fsync(handle.fileno())
        update(site, device, fingerprint, require=replace)
    except Exception:
        output.unlink()
        raise


def openssl(*args, stdin=None):
    result = subprocess.run(['openssl', *args], input=stdin if stdin is not None else b'',
                            capture_output=True)
    if result.returncode:
        raise ValueError(f'OpenSSL {args[0]} falhou na operação de certificados')
    return result.stdout


def bootstrap_ca(site):
    found = kube(site, 'get', 'secret', CLIENT_CA, '--ignore-not-found', '-o', 'json')
    if found:
        return base64.b64decode(json.loads(found)['data']['tls.crt'])

    with TemporaryDirectory() as work:
        cert, key = Path(work) / 'ca.crt', Path(work) / 'ca.key'
        openssl('req', '-new', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
                '-nodes', '-days', '365', '-subj', f'/CN=SSLE {site} Sensor CA',
                '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0',
                '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
                '-keyout', key, '-out', cert)
        certificate = cert.read_bytes()
        kube(site, 'create', '-f', '-', document={
            'apiVersion': 'v1', 'kind': 'Secret', 'type': 'kubernetes.io/tls', 'immutable': True,
            'metadata': {'name': CLIENT_CA, 'namespace': site},
            'data': {'tls.crt': base64.b64encode(certificate).decode(),
                     'tls.key': base64.b64encode(key.read_bytes()).decode()}
        })
    return certificate


def issue(site, request, output, device=None):
    renewal = device is not None
    if device is None:
        device = f'pt.{site}.sensor.{secrets.token_hex(10)}'
    if len(device) > 64:
        raise ValueError('identificador demasiado comprido para o certificado')
    with request.open('rb') as handle:
        csr = handle.read(16385)
    if not csr or len(csr) > 16384:
        raise ValueError('tamanho do pedido de certificado inválido')
    issuer = json.loads(kube(site, 'get', 'secret', CLIENT_CA, '-o', 'json'))['data']
    with TemporaryDirectory() as work:
        ca, key = Path(work) / 'ca.crt', Path(work) / 'ca.key'
        extensions, cert = Path(work) / 'extensions', Path(work) / 'sensor.crt'
        ca.write_bytes(base64.b64decode(issuer['tls.crt']))
        key.write_bytes(base64.b64decode(issuer['tls.key']))
        extensions.write_text('basicConstraints=critical,CA:FALSE\n'
                              'keyUsage=critical,digitalSignature\n'
                              'extendedKeyUsage=critical,clientAuth\n')
        openssl('x509', '-in', ca, '-checkend', str((CERT_DAYS + 1) * 86400), '-noout')
        # OpenSSL verifies the CSR signature before issuing. The manager sets the subject and extensions.
        openssl('x509', '-req', '-subj', f'/CN={device}', '-copy_extensions', 'none',
                '-CA', ca, '-CAkey', key, '-extfile', extensions,
                '-set_serial', f'0x01{secrets.token_hex(16)}', '-days', str(CERT_DAYS),
                '-sha256', '-out', cert, stdin=csr)
        openssl('verify', '-auth_level', '2', '-purpose', 'sslclient', '-CAfile', ca, cert)
        fingerprint = hashlib.sha256(openssl('x509', '-in', cert, '-outform', 'DER')).hexdigest()
        register(site, device, output, cert.read_bytes(), CERT_PREFIX + fingerprint, renewal)
    return device


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('site')
    commands = parser.add_subparsers(dest='action', required=True)
    commands.add_parser('bootstrap')
    commands.add_parser('bootstrap-ca')
    commands.add_parser('ca')
    commands.add_parser('list')
    commands.add_parser('revoke').add_argument('device')
    for mode in ('enroll', 'rotate'):
        command = commands.add_parser(mode)
        command.add_argument('device')
        command.add_argument('output', type=Path)
    for mode in ('issue', 'renew'):
        command = commands.add_parser(mode)
        if mode == 'renew':
            command.add_argument('device')
        command.add_argument('request', type=Path)
        command.add_argument('output', type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r'[a-z][a-z0-9-]{0,30}(?<!-)', args.site):
        parser.error('site inválido')
    default = f'pt.{args.site}.dc1.rack1.lab.sensor.temperature.01'
    if hasattr(args, 'device'):
        if not re.fullmatch(r'[A-Za-z0-9_-](?:[A-Za-z0-9_.-]{0,126}[A-Za-z0-9_-])?', args.device):
            parser.error('identificador de sensor inválido')
        if args.device == default:
            parser.error('o sensor de demonstração é gerido pela instalação')
    try:
        if args.action == 'bootstrap':
            bootstrap(args.site, default)
        elif args.action == 'bootstrap-ca':
            print(bootstrap_ca(args.site).decode(), end='')
        elif args.action == 'ca':
            config = json.loads(kube(args.site, 'get', 'configmap', 'ingestion-ca', '-o', 'json'))
            print(config['data']['ca.crt'], end='')
        elif args.action == 'list':
            secret = json.loads(kube(args.site, 'get', 'secret', 'sensor-digests', '-o', 'json'))
            print('\n'.join(sorted(secret.get('data', {}))))
        elif args.action == 'revoke':
            update(args.site, args.device, require=True)
        elif args.action in ('issue', 'renew'):
            device = issue(args.site, args.request, args.output, getattr(args, 'device', None))
            print(device)
        else:
            token = secrets.token_hex(32)
            register(args.site, args.device, args.output, (token + '\n').encode(),
                     token_digest(token), args.action == 'rotate')
            print(f'Credencial guardada em {args.output}')
    except (OSError, ValueError, KeyError, RuntimeError) as exc:
        parser.exit(1, f'{exc}\n')


if __name__ == '__main__':
    main()
