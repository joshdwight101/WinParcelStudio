#!/usr/bin/env bash
set -euo pipefail
source_dir="$(dirname "$(realpath "$0")")"
if [[ "${1:-}" != --skip-deps ]]; then
    sudo apt-get install -y python3 python3-gi gir1.2-gtk-4.0 gir1.2-adw-1 python3-cryptography msitools
fi
data_dir="${XDG_DATA_HOME:-$HOME/.local/share}"
bin_dir="${WINPARCEL_BIN_DIR:-$HOME/.local/bin}"
app_dir="$data_dir/winparcel-studio"
app_id=io.github.joshuadwight.WinParcelStudio
install -d "$app_dir" "$bin_dir" "$data_dir/icons/hicolor/scalable/apps"
install -m 755 "$source_dir/studio.py" "$source_dir/winparcel.py" "$source_dir/signing.py" "$app_dir/"
install -m 644 "$source_dir/$app_id.svg" "$source_dir/README.md" \
    "$source_dir/USER-GUIDE.txt" "$source_dir/changelog.md" "$app_dir/"
install -m 644 "$source_dir/$app_id.svg" "$data_dir/icons/hicolor/scalable/apps/"
ln -sfn "$app_dir/winparcel.py" "$bin_dir/winparcel"
/usr/bin/python3 "$app_dir/studio.py" --install-launcher
printf 'WinParcel Studio installed. Run %s/winparcel -h for terminal use.\n' "$bin_dir"
