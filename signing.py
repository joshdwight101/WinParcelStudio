"""Authenticode signing for staged PowerShell scripts."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
from io import BytesIO
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile
from urllib.parse import urlsplit
from urllib.request import urlopen

from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID

SCRIPT_TYPES = {'.ps1', '.psm1', '.psd1', '.ps1xml', '.psc1', '.cdxml'}
DATA = Path(os.environ.get('XDG_DATA_HOME') or Path.home() / '.local/share')
SIGNER_DIR = DATA / 'winparcel-studio' / 'signer'
VERSION = '2.16'
RELEASE_DIGESTS = {
    'amd64': '109c711ac07fc2ce1e3756d6247d92bbf23e55c4aa809a4b34cca3c4f2913fc6',
    'arm64': 'fec690206a8b4306423b8be188ebd66bf3fc847f11ecc06a37ff34dd019c70d4',
}


@dataclass(frozen=True)
class SigningOptions:
    certificate: str
    password: str = field(repr=False)
    timestamp: str = ''


def signing_tool(required=True):
    private_tool = SIGNER_DIR / 'osslsigncode'
    system_tool = shutil.which('osslsigncode')
    for candidate in (str(private_tool) if os.access(private_tool, os.X_OK) else None, system_tool):
        if not candidate:
            continue
        try:
            output = subprocess.check_output([candidate, '--version'], text=True, timeout=10, stderr=subprocess.STDOUT)
        except (OSError, subprocess.SubprocessError):
            continue
        match = re.search(r'osslsigncode (\d+)\.(\d+)', output)
        if match and tuple(map(int, match.groups())) >= (2, 8):
            return candidate
    if required:
        raise ValueError('Install the signing tool first. PowerShell signing needs osslsigncode 2.8 or newer.')
    return None


def install_signing_tool():
    architecture = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    if architecture is None:
        raise ValueError('Install osslsigncode 2.8 or newer using your system package manager.')
    artifact = f'osslsigncode-{VERSION}-linux-{architecture}'
    with urlopen(f'https://github.com/mtrojnar/osslsigncode/releases/download/{VERSION}/{artifact}.tar.gz',
                 timeout=30) as response:
        data = response.read(25 * 1024 * 1024 + 1)
    if hashlib.sha256(data).hexdigest() != RELEASE_DIGESTS[architecture]:
        raise ValueError('The signing tool download did not match the expected checksum.')
    SIGNER_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=SIGNER_DIR) as work, tarfile.open(fileobj=BytesIO(data), mode='r:gz') as release:
        staged = Path(work)
        for name in ('osslsigncode', 'COPYING.txt', 'LICENSE.txt'):
            with release.extractfile(f'{artifact}/{name}') as original, (staged / name).open('wb') as target:
                shutil.copyfileobj(original, target)
        executable = staged / 'osslsigncode'
        executable.chmod(0o755)
        subprocess.run([str(executable), '--version'], check=True, capture_output=True, timeout=10)
        for name in ('COPYING.txt', 'LICENSE.txt', 'osslsigncode'):
            (staged / name).replace(SIGNER_DIR / name)
    return SIGNER_DIR / 'osslsigncode'


def certificate_details(options):
    cert_path = Path(options.certificate).expanduser().resolve(strict=True)
    if not cert_path.is_file() or cert_path.suffix.lower() not in {'.pfx', '.p12'}:
        raise ValueError('Choose a code-signing certificate bundle (.pfx or .p12).')
    if any(char in options.password for char in ('\n', '\r', '\0')) or len(options.password.encode()) > 1024:
        raise ValueError('Use a password without line breaks and up to 1024 UTF-8 bytes.')
    if options.timestamp:
        url = urlsplit(options.timestamp)
        if (url.scheme.lower() != 'https' or not url.hostname or url.username or url.password
                or url.fragment or any(char.isspace() for char in options.timestamp)):
            raise ValueError('Enter an HTTPS RFC 3161 timestamp URL.')
    with cert_path.open('rb') as source:
        data = source.read(8 * 1024 * 1024 + 1)
    if len(data) > 8 * 1024 * 1024:
        raise ValueError('Choose a certificate bundle smaller than 8 MiB.')
    try:
        key, certificate, _ = pkcs12.load_key_and_certificates(data, options.password.encode() or None)
    except ValueError as error:
        raise ValueError('Could not open the certificate bundle. Check the file and its password.') from error
    if key is None or certificate is None:
        raise ValueError('The bundle must contain a signing certificate and its private key.')
    try:
        purposes = certificate.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
    except x509.ExtensionNotFound:
        raise ValueError('The certificate must include the Code Signing purpose.') from None
    if ExtendedKeyUsageOID.CODE_SIGNING not in purposes:
        raise ValueError('The certificate does not include the Code Signing purpose.')
    try:
        usage = certificate.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    except x509.ExtensionNotFound:
        usage = None
    if usage is not None and not usage.digital_signature:
        raise ValueError('The certificate does not permit digital signatures.')
    if hasattr(certificate, 'not_valid_after_utc'):
        start, end = certificate.not_valid_before_utc, certificate.not_valid_after_utc
    else:
        start = certificate.not_valid_before.replace(tzinfo=timezone.utc)
        end = certificate.not_valid_after.replace(tzinfo=timezone.utc)
    if not start <= datetime.now(timezone.utc) < end:
        raise ValueError('The code-signing certificate is expired or not yet valid.')
    return cert_path, certificate.subject.rfc4514_string(), end.date()


def sign_script(tool, options, certificate, original, target, password_file):
    password_file.seek(0)
    descriptor = password_file.fileno()
    args = [tool, 'sign', '-pkcs12', str(certificate), '-readpass', f'/proc/self/fd/{descriptor}',
            '-h', 'sha256', '-in', str(original), '-out', str(target)]
    if options.timestamp:
        args.extend(('-ts', options.timestamp))
    run = subprocess.run(args, pass_fds=(descriptor,), capture_output=True, text=True, errors='replace', timeout=90)
    if run.returncode or not target.is_file():
        detail = (run.stderr or run.stdout).strip()[-650:]
        raise ValueError(f'Could not sign {original.name}. {detail or "The signer produced no file."}')
