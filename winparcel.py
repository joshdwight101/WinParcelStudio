#!/usr/bin/python3
"""WinParcel Studio's native Intune Win32 package builder and command line."""
import argparse
import base64
from getpass import getpass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from urllib.request import Request, urlopen
from xml.etree import ElementTree as ET
from zipfile import ZIP_DEFLATED, ZIP_STORED, ZipFile
from signing import SCRIPT_TYPES, SigningOptions, certificate_details, install_signing_tool, sign_script, signing_tool

NAME = 'WinParcel Studio'
VERSION = '1.1.0'
APP_ID = 'io.github.joshuadwight.WinParcelStudio'
DATA = Path(os.environ.get('XDG_DATA_HOME') or Path.home() / '.local/share')
CACHE = DATA / 'winparcel-studio' / 'microsoft'
REPOSITORY = 'microsoft/Microsoft-Win32-Content-Prep-Tool'
PAYLOAD = 'IntunePackage.intunewin'
PACKAGE_CONTENT = f'IntuneWinPackage/Contents/{PAYLOAD}'
PACKAGE_METADATA = 'IntuneWinPackage/Metadata/Detection.xml'
PE_NAME = 'IntuneWinAppUtil.exe'
BLOCK = 1024 * 1024


def latest_tool():
    with urlopen(Request(f'https://api.github.com/repos/{REPOSITORY}/releases/latest',
                         headers={'User-Agent': 'WinParcel-Studio'}), timeout=15) as response:
        tag = json.load(response)['tag_name']
    if not re.fullmatch(r'v[0-9]+(?:\.[0-9]+){1,3}', tag):
        raise ValueError('Microsoft returned an unrecognized release tag.')
    CACHE.mkdir(parents=True, exist_ok=True)
    installed = CACHE / tag
    installed.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=installed) as work:
        binary = Path(work) / PE_NAME
        uri = f'https://raw.githubusercontent.com/{REPOSITORY}/{tag}/{PE_NAME}'
        with urlopen(uri, timeout=20) as response:
            content = response.read(20 * BLOCK + 1)
        if not content.startswith(b'MZ') or len(content) > 20 * BLOCK:
            raise ValueError('The release did not return a Windows executable.')
        binary.write_bytes(content)
        binary.replace(installed / PE_NAME)
        pointer = Path(work) / 'latest'
        pointer.write_text(tag, encoding='ascii')
        pointer.replace(CACHE / 'latest')
    return installed / PE_NAME


def cached_tool():
    try:
        tag = (CACHE / 'latest').read_text(encoding='ascii').strip()
    except FileNotFoundError:
        raise ValueError('Download the Microsoft Content Prep Tool first.') from None
    if not re.fullmatch(r'v[0-9]+(?:\.[0-9]+){1,3}', tag) or not (CACHE / tag / PE_NAME).is_file():
        raise ValueError('The Microsoft tool cache is incomplete. Download it again.')
    return CACHE / tag / PE_NAME


def windows_component(name):
    base = name.split('.')[0].upper()
    return (not re.search(r'[<>:"/\\|?*\x00-\x1f]', name) and not name.endswith((' ', '.'))
            and base not in {'CON', 'PRN', 'AUX', 'NUL'}
            and not re.fullmatch(r'(?:COM|LPT)[1-9¹²³]', base))


def package_paths(source, setup, output, catalogs=None):
    root = Path(source).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError('Choose a source folder.')
    entry = Path(setup).expanduser()
    entry = entry if entry.is_absolute() else root / entry
    if not entry.is_file() or entry.is_symlink() or not entry.resolve().is_relative_to(root):
        raise ValueError('The setup file must be inside the source folder.')
    relative = entry.relative_to(root)
    if not all(windows_component(part) for part in relative.parts):
        raise ValueError('The setup path contains a name unsupported on Windows.')
    destination = Path(output).expanduser().resolve()
    if destination.is_relative_to(root):
        raise ValueError('Choose an output folder outside the source folder.')
    catalog_dir = Path(catalogs).expanduser().resolve(strict=True) if catalogs else None
    if catalog_dir and not catalog_dir.is_dir():
        raise ValueError('Choose a catalog folder.')
    return root, relative, destination / (entry.stem + '.intunewin'), catalog_dir


def source_files(root):
    def raise_error(error):
        raise error

    names = set()
    for directory, folders, files in os.walk(root, onerror=raise_error):
        for item in sorted(folders + files):
            path = Path(directory) / item
            relative = path.relative_to(root)
            name = relative.as_posix().casefold()
            if not windows_component(item) or name in names:
                raise ValueError(f'Windows filename conflict or invalid name: {relative}')
            names.add(name)
            if path.is_symlink() or not (path.is_dir() or path.is_file()):
                raise ValueError(f'Use regular files and directories in the source folder: {relative}')
            if path.is_file():
                yield path, relative.as_posix()


def msi_metadata(path):
    private_tool = DATA / 'winparcel-studio' / 'runtime' / 'msiinfo'
    tool = shutil.which('msiinfo') or (str(private_tool) if os.access(private_tool, os.X_OK) else '')
    if not tool:
        raise ValueError('Install msitools to package MSI files with the native engine.')
    def inspect(command, *args):
        return subprocess.run([tool, command, str(path), *args], check=True,
                              capture_output=True, text=True, timeout=25).stdout
    lines = inspect('export', 'Property').splitlines()
    props = dict(line.split('\t', 1) for line in lines[3:] if '\t' in line)
    summary = inspect('suminfo')
    package_code = re.search(r'^Revision number(?: \(UUID\))?:\s*(\{[0-9a-fA-F-]+\})', summary, re.M | re.I)
    if not props.get('ProductCode') or not props.get('ProductVersion'):
        raise ValueError('The MSI is missing its product code or version.')
    context = {'1': 'System', '2': 'Any'}.get(props.get('ALLUSERS'), 'User')
    tables = set(inspect('tables').splitlines())
    values = {'MsiProductCode': props['ProductCode'], 'MsiProductVersion': props['ProductVersion'],
              'MsiPackageCode': package_code[1] if package_code else '', 'MsiUpgradeCode': props.get('UpgradeCode', ''),
              'MsiExecutionContext': context, 'MsiIsMachineInstall': str(context in ('System', 'Any')).lower(),
              'MsiIsUserInstall': str(context in ('User', 'Any')).lower(),
              'MsiIncludesServices': str('ServiceInstall' in tables).lower(),
              'MsiIncludesODBCDataSource': str('ODBCDataSource' in tables).lower(),
              'MsiPublisher': props.get('Manufacturer', '')}
    return props.get('ProductName', path.name), values


def encrypt(source, encrypted):
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    key, mac_key, iv = os.urandom(32), os.urandom(32), os.urandom(16)
    digest = hashlib.sha256()
    authenticator = hmac.new(mac_key, iv, 'sha256')
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    pad = padding.PKCS7(128).padder()
    with source.open('rb') as original, encrypted.open('wb') as target:
        target.write(bytes(32) + iv)
        while chunk := original.read(BLOCK):
            digest.update(chunk)
            data = cipher.update(pad.update(chunk))
            authenticator.update(data)
            target.write(data)
        data = cipher.update(pad.finalize()) + cipher.finalize()
        authenticator.update(data)
        target.write(data)
        target.seek(0)
        target.write(authenticator.digest())
    return {label: base64.b64encode(value).decode('ascii') for label, value in
            (('EncryptionKey', key), ('MacKey', mac_key), ('InitializationVector', iv),
             ('Mac', authenticator.digest()), ('FileDigest', digest.digest()))}


def native_package(root, setup, staging, progress):
    name, msi = (setup.name, None)
    if setup.suffix.lower() == '.msi':
        name, msi = msi_metadata(root / setup)
    inner = staging / 'source.zip'
    progress('Compressing source files…')
    with ZipFile(inner, 'w', compression=ZIP_DEFLATED, strict_timestamps=False) as archive:
        for path, relative in source_files(root):
            archive.write(path, relative)
    progress('Encrypting package…')
    encrypted = staging / 'payload'
    crypto = encrypt(inner, encrypted)
    app = ET.Element('ApplicationInfo', {'xmlns:xsd': 'http://www.w3.org/2001/XMLSchema',
                                        'xmlns:xsi': 'http://www.w3.org/2001/XMLSchema-instance',
                                        'ToolVersion': '1.8.7.0'})
    for label, value in (('Name', name), ('UnencryptedContentSize', str(inner.stat().st_size)),
                         ('FileName', PAYLOAD), ('SetupFile', '\\'.join(setup.parts))):
        ET.SubElement(app, label).text = value
    info = ET.SubElement(app, 'EncryptionInfo')
    for label in ('EncryptionKey', 'MacKey', 'InitializationVector', 'Mac',
                  'ProfileIdentifier', 'FileDigest', 'FileDigestAlgorithm'):
        ET.SubElement(info, label).text = {'ProfileIdentifier': 'ProfileVersion1',
                                           'FileDigestAlgorithm': 'SHA256'}.get(label, crypto.get(label))
    if msi is not None:
        msi_info = ET.SubElement(app, 'MsiInfo')
        for label, value in msi.items():
            if value:
                ET.SubElement(msi_info, label).text = value
    ET.indent(app, space='  ')
    package = staging / (setup.stem + '.intunewin')
    with ZipFile(package, 'w', compression=ZIP_STORED) as archive:
        archive.write(encrypted, PACKAGE_CONTENT)
        archive.writestr(PACKAGE_METADATA, ET.tostring(app, encoding='utf-8').replace(b'\n', b'\r\n'))
    return package


def microsoft_command(*flags):
    binary = cached_tool()
    wine = shutil.which('wine') or shutil.which('wine64')
    if not wine:
        raise ValueError('Install Wine with a compatible .NET runtime to run the Microsoft tool.')
    return [wine, str(binary), *flags]


def microsoft_package(root, setup, staging, catalogs, quiet, progress):
    winepath = shutil.which('winepath')
    if not winepath:
        raise ValueError('Install Wine and winepath to run the Microsoft tool.')
    def win(path):
        return subprocess.check_output([winepath, '-w', str(path)], text=True, timeout=30).strip()
    args = ['-c', win(root), '-s', win(root / setup), '-o', win(staging), '-qq' if quiet == 2 else '-q']
    if catalogs:
        args += ['-a', win(catalogs)]
    progress('Running Microsoft Content Prep Tool…')
    result = subprocess.run(microsoft_command(*args), stdin=subprocess.DEVNULL,
                            capture_output=True, text=True, errors='replace')
    staged = staging / (setup.stem + '.intunewin')
    if result.returncode or not staged.is_file():
        raise ValueError((result.stderr or result.stdout or 'The Microsoft tool produced no package.')[-1400:].strip())
    return staged


def signing_preview(root, options):
    certificate, subject, expiration = certificate_details(options)
    if certificate.is_relative_to(root):
        raise ValueError('Move the certificate bundle outside the source folder before packaging.')
    scripts = []
    for path, relative in source_files(root):
        if path.samefile(certificate):
            raise ValueError('Remove the signing certificate bundle from the source folder.')
        if path.suffix.lower() in SCRIPT_TYPES:
            scripts.append(relative)
    if not scripts:
        raise ValueError('The source folder has no supported PowerShell files to sign.')
    return certificate, subject, expiration, scripts


def stage_signed_source(root, staging, options, progress):
    certificate, subject, _, scripts = signing_preview(root, options)
    tool = signing_tool()
    signed_root = staging / 'signed-source'
    pending = set(scripts)
    progress(f'Signing {len(scripts)} PowerShell files with {subject}…')
    with tempfile.TemporaryFile() as password:
        password.write(options.password.encode() + b'\n')
        for original, relative in source_files(root):
            if original.samefile(certificate):
                raise ValueError('Remove the signing certificate bundle from the source folder.')
            target = signed_root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if relative in pending:
                sign_script(tool, options, certificate, original, target, password)
                pending.remove(relative)
            elif original.suffix.lower() in SCRIPT_TYPES:
                raise ValueError('A script was added during signing. Build the package again.')
            else:
                shutil.copy2(original, target)
    if pending:
        raise ValueError('A script was removed during signing. Build the package again.')
    return signed_root


def build_package(source, setup, output, catalogs=None, backend='native', quiet=0, overwrite=False, progress=print,
                  signing=None):
    root, entry, final, catalog_dir = package_paths(source, setup, output, catalogs)
    if catalog_dir and backend == 'native':
        raise ValueError('Catalog folders require the Microsoft engine.')
    if final.exists() and not overwrite:
        raise FileExistsError(f'{final.name} already exists. Enable overwrite or choose another output folder.')
    final.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.winparcel-', dir=final.parent) as work:
        staging = Path(work)
        if signing:
            root = stage_signed_source(root, staging, signing, progress)
            if not (root / entry).is_file():
                raise ValueError('The setup file changed during signing. Build the package again.')
        if backend == 'microsoft':
            staged = microsoft_package(root, entry, staging, catalog_dir, quiet, progress)
        else:
            staged = native_package(root, entry, staging, progress)
        if overwrite:
            staged.replace(final)
        else:
            os.link(staged, final)
    return final


def main(argv=None):
    parser = argparse.ArgumentParser(description='Build Intune Win32 packages on Ubuntu.')
    parser.add_argument('-c', metavar='SOURCE', help='source folder containing installation files')
    parser.add_argument('-s', metavar='SETUP', help='setup file relative to the source folder, or an absolute path')
    parser.add_argument('-o', metavar='OUTPUT', help='output folder')
    parser.add_argument('-a', metavar='CATALOGS', help='catalog folder for the Microsoft engine')
    parser.add_argument('-q', action='store_true', help='overwrite and show progress without prompts')
    parser.add_argument('-qq', action='store_true', help='overwrite and keep stdout silent')
    parser.add_argument('-v', '--version', action='version', version=f'{NAME} {VERSION}')
    parser.add_argument('--overwrite', action='store_true', help='replace an existing output package')
    parser.add_argument('--backend', choices=['native', 'microsoft'], default='native')
    parser.add_argument('--download-microsoft', action='store_true', help='fetch the latest tagged Microsoft release')
    parser.add_argument('--sign-certificate', metavar='PFX', help='sign staged PowerShell files with a .pfx or .p12')
    parser.add_argument('--timestamp-url', metavar='HTTPS_URL', help='optional RFC 3161 timestamp authority for signing')
    parser.add_argument('--install-signing-tool', action='store_true', help='install the checksum-verified signer for this user')
    parser.add_argument('--microsoft-help', action='store_true', help='run the downloaded Microsoft tool with -h')
    parser.add_argument('--microsoft-version', action='store_true', help='run the downloaded Microsoft tool with -v')
    selected = parser.parse_args(argv)
    try:
        if selected.install_signing_tool:
            print(install_signing_tool())
            return
        if selected.download_microsoft:
            print(latest_tool())
            return
        if selected.microsoft_help or selected.microsoft_version:
            return subprocess.call(microsoft_command('-h' if selected.microsoft_help else '-v'))
        if selected.c is None and selected.s is None and selected.o is None and not (selected.q or selected.qq):
            selected.c = input('Source folder: ')
            selected.s = input('Setup file: ')
            selected.o = input('Output folder: ')
        if not all((selected.c, selected.s, selected.o)):
            parser.error('Provide -c, -s and -o.')
        quiet = 2 if selected.qq else int(selected.q)
        if selected.timestamp_url and not selected.sign_certificate:
            parser.error('--timestamp-url requires --sign-certificate.')
        signing = (SigningOptions(selected.sign_certificate, getpass('Certificate password: '), selected.timestamp_url or '')
                   if selected.sign_certificate else None)
        result = build_package(selected.c, selected.s, selected.o, selected.a, selected.backend,
                               quiet, overwrite=bool(quiet) or selected.overwrite,
                               progress=(lambda *_: None) if quiet == 2 else print, signing=signing)
        if quiet != 2:
            print(result)
    except (OSError, ValueError, subprocess.SubprocessError, ImportError, EOFError) as error:
        parser.exit(1, f'{error}\n')


if __name__ == '__main__':
    raise SystemExit(main())
