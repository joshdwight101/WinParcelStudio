#!/usr/bin/python3
"""GTK administration window for WinParcel Studio."""
from pathlib import Path
import shlex
import subprocess
import sys
import threading

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Adw, Gio, GLib, GObject, Gtk

from signing import SigningOptions, install_signing_tool, signing_tool
from winparcel import APP_ID, DATA, NAME, VERSION, build_package, cached_tool, latest_tool, microsoft_command, signing_preview

SOURCE = Path(__file__).resolve().parent
GUIDE = SOURCE / 'USER-GUIDE.txt'
AUTHOR = 'Joshua Dwight'


def install_launcher(desktop=False):
    if desktop:
        directory = GLib.get_user_special_dir(GLib.UserDirectory.DIRECTORY_DESKTOP)
        target = Path(directory) if directory else Path.home() / 'Desktop'
    else:
        target = DATA / 'applications'
    target.mkdir(parents=True, exist_ok=True)
    file = target / f'{APP_ID}.desktop'
    entry = GLib.KeyFile()
    script = str(SOURCE / 'studio.py').replace('%', '%%')
    for symbol in ('\\', '"', '`', '$'):
        script = script.replace(symbol, '\\' + symbol)
    for key, value in {'Name': NAME, 'Type': 'Application', 'Categories': 'Utility;',
                       'Exec': f'/usr/bin/python3 "{script}"', 'Icon': str(SOURCE / f'{APP_ID}.svg'),
                       'StartupWMClass': APP_ID, 'Comment': 'Prepare Intune Win32 packages'}.items():
        entry.set_string('Desktop Entry', key, value)
    entry.set_boolean('Desktop Entry', 'Terminal', False)
    Gio.File.new_for_path(str(file)).replace_contents(
        entry.to_data()[0].encode(), None, False, Gio.FileCreateFlags.REPLACE_DESTINATION, None)
    file.chmod(0o755 if desktop else 0o644)
    return file


def button(label, handler, suggested=False):
    widget = Gtk.Button(label=label, valign=Gtk.Align.CENTER)
    if suggested:
        widget.add_css_class('suggested-action')
    widget.connect('clicked', handler)
    return widget


class Studio(Adw.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID)
        self.connect('activate', self.activate)
        self.busy = False

    def activate(self, *_):
        if self.get_active_window():
            self.get_active_window().present()
            return
        self.win = Adw.ApplicationWindow(application=self, title=NAME, default_width=860, default_height=780)
        Gtk.IconTheme.get_for_display(self.win.get_display()).add_search_path(str(SOURCE))
        self.win.set_icon_name(APP_ID)
        layout = Adw.ToolbarView()
        header = Adw.HeaderBar()
        brand = Gtk.Box(spacing=8)
        image = Gtk.Image.new_from_icon_name(APP_ID)
        image.set_pixel_size(32)
        brand.append(image)
        brand.append(Adw.WindowTitle(title=NAME, subtitle=f'{AUTHOR} · v{VERSION}'))
        header.set_title_widget(brand)
        self.add_menu(header, 'File', [
            ('Install in Application Menu', 'install-menu', lambda *_: self.install(False)),
            ('Install Desktop Shortcut', 'install-desktop', lambda *_: self.install(True)),
        ])
        self.add_menu(header, 'Help', [
            ('User Guide', 'guide', self.show_guide),
            ('About', 'about', self.about),
        ])
        self.build_button = button('Build Package', self.build, suggested=True)
        header.pack_end(self.build_button)
        layout.add_top_bar(header)
        page = Adw.PreferencesPage()
        layout.set_content(page)
        self.win.set_content(layout)

        files = Adw.PreferencesGroup(title='Package files')
        self.source = self.path_row(files, 'Source folder', True)
        self.setup = self.path_row(files, 'Setup file', False)
        self.output = self.path_row(files, 'Output folder', True)
        page.add(files)
        options = Adw.PreferencesGroup(title='Packaging options')
        self.engine = Adw.ComboRow(title='Packaging engine', model=Gtk.StringList.new(
            ['Native Linux', 'Microsoft Content Prep Tool via Wine']))
        options.add(self.engine)
        self.catalog = self.path_row(options, 'Catalog folder (optional)', True)
        self.catalog.set_visible(False)
        self.engine.connect('notify::selected', lambda *_: self.catalog.set_visible(self.engine.get_selected() == 1))
        self.mode = Adw.ComboRow(title='Command output', model=Gtk.StringList.new(
            ['Standard', 'Quiet (-q)', 'Silent (-qq)']))
        options.add(self.mode)
        self.overwrite = Adw.SwitchRow(title='Replace an existing package',
                                       subtitle='Quiet and Silent also replace the output package.')
        options.add(self.overwrite)
        copy_row = Adw.ActionRow(title='Terminal command')
        copy_row.add_suffix(button('Copy Command', self.copy_command))
        options.add(copy_row)
        page.add(options)

        signing = Adw.PreferencesGroup(title='PowerShell signing')
        self.signing_enabled = Adw.SwitchRow(title='Sign PowerShell files before packaging',
                                             subtitle='Applies to the copies in the package. The source files stay intact.')
        signing.add(self.signing_enabled)
        self.certificate = self.path_row(signing, 'Code-signing certificate (.pfx or .p12)', False)
        self.certificate_pw = Adw.PasswordEntryRow(title='Certificate password (if required)')
        signing.add(self.certificate_pw)
        self.timestamp_url = Adw.EntryRow(title='RFC 3161 timestamp URL (optional)')
        signing.add(self.timestamp_url)
        self.signer_row = Adw.ActionRow(title='Signing tool')
        self.install_signer = button('Install Signing Tool', self.download_signer)
        self.signer_row.add_suffix(self.install_signer)
        signing.add(self.signer_row)
        review = Adw.ActionRow(title='Check certificate and see which files will be signed')
        review.add_suffix(button('Review Signing', self.review_signing))
        signing.add(review)
        for row in (self.certificate, self.certificate_pw, self.timestamp_url, self.signer_row, review):
            self.signing_enabled.bind_property('active', row, 'visible', GObject.BindingFlags.SYNC_CREATE)
        self.signing_enabled.connect('notify::active', self.signing_changed)
        page.add(signing)

        tools = Adw.PreferencesGroup(title='Microsoft Content Prep Tool',
                                     description='The native engine works offline. The Microsoft engine requires Wine and .NET.')
        self.tool_row = Adw.ActionRow(title='Downloaded release', subtitle_lines=2)
        self.download = button('Download Latest', self.download_tool)
        self.tool_row.add_suffix(self.download)
        tools.add(self.tool_row)
        info = Adw.ActionRow(title='Microsoft tool information')
        info.add_suffix(button('Help (-h)', lambda *_: self.tool_info('-h')))
        info.add_suffix(button('Version (-v)', lambda *_: self.tool_info('-v')))
        tools.add(info)
        page.add(tools)
        self.status = Gtk.Label(wrap=True, xalign=0, selectable=True, margin_top=12,
                                margin_bottom=12, margin_start=16, margin_end=16, label='Choose the files to package.')
        layout.add_bottom_bar(self.status)
        self.update_tool()
        self.update_signer()
        self.win.present()

    def add_menu(self, header, title, entries):
        model = Gio.Menu()
        for label, name, callback in entries:
            action = Gio.SimpleAction.new(name, None)
            action.connect('activate', callback)
            self.add_action(action)
            model.append(label, f'app.{name}')
        header.pack_start(Gtk.MenuButton(label=title, menu_model=model))

    def path_row(self, group, label, folder):
        row = Adw.EntryRow(title=label)
        row.add_suffix(button('Browse…', lambda *_: self.choose(row, folder)))
        group.add(row)
        return row

    def choose(self, row, folder):
        action = Gtk.FileChooserAction.SELECT_FOLDER if folder else Gtk.FileChooserAction.OPEN
        chooser = Gtk.FileChooserNative.new(row.get_title(), self.win, action, 'Select', 'Cancel')
        if row == self.setup and self.source.get_text():
            chooser.set_current_folder(Gio.File.new_for_path(self.source.get_text()))
        if row == self.certificate:
            certificates = Gtk.FileFilter(name='PKCS#12 certificate bundles')
            for suffix in ('pfx', 'p12'):
                certificates.add_suffix(suffix)
            chooser.add_filter(certificates)
        def receive(dialog, result):
            if result == Gtk.ResponseType.ACCEPT and dialog.get_file().get_path():
                row.set_text(dialog.get_file().get_path())
            dialog.destroy()
        chooser.connect('response', receive)
        chooser.show()

    def update_tool(self):
        try:
            detail = cached_tool().parent.name
        except ValueError:
            detail = 'Available from Microsoft GitHub releases'
        self.tool_row.set_subtitle(detail)

    def run_task(self, work, finished):
        if self.busy:
            return
        self.busy = True
        self.build_button.set_sensitive(False)
        self.download.set_sensitive(False)
        self.install_signer.set_sensitive(False)

        def deliver(result, error):
            self.busy = False
            self.build_button.set_sensitive(True)
            self.download.set_sensitive(True)
            self.install_signer.set_sensitive(True)
            if error:
                self.status.set_text(str(error))
            else:
                finished(result)
            return GLib.SOURCE_REMOVE

        def worker():
            try:
                result = work()
            except (OSError, ValueError, subprocess.SubprocessError, ImportError, KeyError) as error:
                GLib.idle_add(deliver, None, error)
            else:
                GLib.idle_add(deliver, result, None)
        threading.Thread(target=worker, daemon=True).start()

    def inputs(self):
        source, setup, output = (entry.get_text().strip() for entry in (self.source, self.setup, self.output))
        if not all((source, setup, output)):
            raise ValueError('Choose a source folder, setup file, and output folder.')
        engine = 'microsoft' if self.engine.get_selected() else 'native'
        return source, setup, output, self.catalog.get_text().strip() if engine == 'microsoft' else '', engine

    def copy_command(self, *_):
        try:
            source, setup, output, catalog, engine = self.inputs()
            args = ['winparcel', '-c', source, '-s', setup, '-o', output, '--backend', engine]
            if catalog:
                args += ['-a', catalog]
            quiet = self.mode.get_selected()
            if quiet:
                args.append('-qq' if quiet == 2 else '-q')
            elif self.overwrite.get_active():
                args.append('--overwrite')
            if options := self.signing_options():
                args.extend(('--sign-certificate', options.certificate))
                if options.timestamp:
                    args.extend(('--timestamp-url', options.timestamp))
            self.win.get_clipboard().set(shlex.join(args))
            self.status.set_text('Command copied.')
        except ValueError as error:
            self.status.set_text(str(error))

    def build(self, *_):
        try:
            args = self.inputs()
            signing = self.signing_options()
        except ValueError as error:
            self.status.set_text(str(error))
            return
        quiet = self.mode.get_selected()
        overwrite = quiet > 0 or self.overwrite.get_active()
        self.status.set_text('Preparing package…')
        def progress(detail):
            if quiet != 2:
                GLib.idle_add(self.status.set_text, detail)
        self.run_task(lambda: build_package(*args, quiet=quiet, overwrite=overwrite, progress=progress, signing=signing),
                      lambda path: self.status.set_text(f'Package created · {path}'))

    def signing_options(self):
        if not self.signing_enabled.get_active():
            return None
        path = self.certificate.get_text().strip()
        if not path:
            raise ValueError('Choose a code-signing certificate bundle.')
        return SigningOptions(path, self.certificate_pw.get_text(), self.timestamp_url.get_text().strip())

    def signing_changed(self, *_):
        if not self.signing_enabled.get_active():
            self.certificate_pw.set_text('')

    def update_signer(self):
        ready = signing_tool(required=False) is not None
        self.install_signer.set_visible(not ready)
        self.signer_row.set_subtitle('PowerShell signing is available.' if ready else 'Install the Authenticode signer for this user.')

    def download_signer(self, *_):
        if self.busy:
            return
        self.status.set_text('Downloading and testing the signing tool…')
        self.run_task(install_signing_tool, self.signer_installed)

    def signer_installed(self, _path):
        self.update_signer()
        self.status.set_text('Signing tool ready.')

    def review_signing(self, *_):
        try:
            options = self.signing_options()
            source = self.source.get_text().strip()
            if not source:
                raise ValueError('Choose a source folder first.')
            root = Path(source).expanduser().resolve(strict=True)
            if not root.is_dir():
                raise ValueError('Choose a source folder.')
        except (OSError, ValueError) as error:
            self.status.set_text(str(error))
            return

        def review(result):
            _, subject, expiration, scripts = result
            self.show_text('Review Signing', f'Signer: {subject}\nValid through: {expiration}\n\n'
                           'Target Windows devices must trust the certificate and publisher.\n\n'
                           f'{len(scripts)} PowerShell files in this package:\n' + '\n'.join(scripts))

        self.run_task(lambda: signing_preview(root, options), review)

    def download_tool(self, *_):
        dialog = Adw.AlertDialog(heading='Download Microsoft Content Prep Tool?',
                                 body='Review Microsoft’s license and privacy terms before downloading the Windows executable.')
        dialog.set_extra_child(Gtk.LinkButton(
            uri='https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool#prerequisites',
            label='Microsoft license and privacy information'))
        dialog.add_response('cancel', 'Cancel')
        dialog.add_response('download', 'Accept and Download')
        dialog.set_response_appearance('download', Adw.ResponseAppearance.SUGGESTED)
        dialog.set_close_response('cancel')
        def responded(_dialog, response):
            if response == 'download' and not self.busy:
                self.status.set_text('Checking Microsoft GitHub releases…')
                self.run_task(latest_tool, self.download_finished)
        dialog.connect('response', responded)
        dialog.present(self.win)

    def download_finished(self, path):
        self.update_tool()
        self.status.set_text(f'Microsoft tool downloaded · {path.parent.name}')

    def tool_info(self, flag):
        def invoke():
            result = subprocess.run(microsoft_command(flag), capture_output=True, text=True,
                                    errors='replace', timeout=45, check=True)
            return result.stdout.strip() or result.stderr.strip()
        self.run_task(invoke, lambda content: self.show_text('Microsoft Content Prep Tool', content))

    def install(self, desktop):
        try:
            self.status.set_text(f'Launcher installed · {install_launcher(desktop)}')
        except (OSError, GLib.Error) as error:
            self.status.set_text(str(error))

    def show_guide(self, *_):
        self.show_text('User Guide', GUIDE.read_text(encoding='utf-8'))

    def show_text(self, title, content):
        window = Adw.Window(title=title, transient_for=self.win, default_width=670, default_height=520)
        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(Adw.HeaderBar())
        view = Gtk.TextView(editable=False, cursor_visible=False, wrap_mode=Gtk.WrapMode.WORD_CHAR,
                            left_margin=18, right_margin=18, top_margin=14, bottom_margin=14)
        view.get_buffer().set_text(content)
        toolbar.set_content(Gtk.ScrolledWindow(child=view, vexpand=True))
        window.set_content(toolbar)
        window.present()

    def about(self, *_):
        Adw.AboutDialog(application_name=NAME, application_icon=APP_ID, version=VERSION,
                        developer_name=AUTHOR, comments='Prepare Win32 application packages for Microsoft Intune.').present(self.win)


if __name__ == '__main__':
    if sys.argv[1:] == ['--install-launcher']:
        install_launcher()
    else:
        raise SystemExit(Studio().run(sys.argv))
