# WinParcel Studio

<img src="./io.github.joshuadwight.WinParcelStudio.svg" alt="WinParcel Studio icon" width="80">

WinParcel Studio prepares Microsoft Intune Win32 application packages on Ubuntu. Use the GTK app to select installer files, or build the same package from the terminal.

**Version 1.1.0 · Joshua Dwight**

## Install

```bash
bash install.sh
```

Open **WinParcel Studio** from the application menu. The installer adds the `winparcel` command to `~/.local/bin`. If that directory is outside your shell’s PATH, run `~/.local/bin/winparcel`.

## Build a package

1. Choose the source folder and its setup file. Include any scripts, transforms, or supporting files that the installer needs.
2. Choose an output folder outside the source folder.
3. Leave **Native Linux** selected and click **Build Package**. The native engine uses ZIP, AES-256-CBC and HMAC-SHA256. It uses Ubuntu’s `msitools` to read MSI properties.
4. In Intune, create a **Windows app (Win32)**, upload the resulting `.intunewin`, and configure installation, uninstallation, requirements, and detection rules.

```bash
winparcel -c ./source -s Install.ps1 -o ./packages
winparcel -c ./source -s setup.exe -o ./packages -q
winparcel -h
```

Use `-q` to replace existing output without prompts, `-qq` to also suppress standard output, and `-v` to show the local version. Use `--overwrite` to allow replacement independently of logging. Launch the command without file arguments to enter paths interactively.

## Sign PowerShell files before packaging

1. Turn on **Sign PowerShell files before packaging**. Choose a `.pfx` or `.p12` bundle containing a code-signing certificate and its private key. Keep the bundle outside the source folder.
2. Enter the certificate password if required. Click **Install Signing Tool** if prompted. This installs a checksum-verified osslsigncode release for your user account. An existing osslsigncode 2.8 or newer also works.
3. Optionally add an HTTPS RFC 3161 timestamp URL. Click **Review Signing** to check the signer, certificate expiry, and files. Then click **Build Package**.

WinParcel signs the package copies of `.ps1`, `.psm1`, `.psd1`, `.ps1xml`, `.psc1`, and `.cdxml`, including files in subfolders. Source files and vendor binaries retain their original contents. The selected certificate bundle and password stay outside the package. Target Windows devices must trust the signing certificate chain and publisher according to the device's policies. [PowerShell signing on Windows](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_signing)

```bash
winparcel --install-signing-tool
winparcel -c ./source -s Install.ps1 -o ./packages --sign-certificate ~/Certificates/signing.pfx
```

The terminal prompts for the password without echo. Add `--timestamp-url` to request an RFC 3161 timestamp.

## Microsoft engine

Use **Download Latest** to fetch the executable for Microsoft’s latest tagged GitHub release after reviewing its license. The download is cached per release. The optional Microsoft engine uses Wine and needs a compatible .NET Framework environment. Microsoft documents Windows and .NET Framework 4.7.2 for its tool. Use `--backend microsoft -a ./catalogs` for the official Win10 S-mode catalog switch. The GUI also exposes the downloaded executable’s **Help (-h)** and **Version (-v)**. The terminal equivalents are `--microsoft-help` and `--microsoft-version`.

The native packager reimplements the observable container format. The initial release was verified locally by decrypting and checking its package contents. Live Intune tenant uploads and the Wine engine depend on the target environment and should be validated there.

[Microsoft Win32 Content Prep Tool](https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool) · [Microsoft Intune packaging guide](https://learn.microsoft.com/en-us/intune/app-management/deployment/create-win32-package) · [Public container format notes](https://github.com/ThomasHoins/New-IntuneWin#format)
