#!/usr/bin/env bash
# Install, update or remove the MapleWood USD lab in a GOAD checkout.
#
#   ./install.sh /path/to/GOAD              install or update
#   ./install.sh --uninstall /path/to/GOAD  remove everything this script added
#
# What it touches in GOAD:
#   ad/MAPLEWOOD/                       the lab (replaced on every install)
#   ansible/mw-*.yml                    MapleWood playbooks
#   ansible/roles/mw_*                  MapleWood roles
#   playbooks.yml                       the MAPLEWOOD: entry (replaced on every install)
set -euo pipefail

usage() { sed -n '2,6p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }

mode=install
if [[ "${1:-}" == "--uninstall" ]]; then mode=uninstall; shift; fi
[[ $# -eq 1 ]] || usage
GOAD="$(cd "$1" && pwd)"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -f "$GOAD/goad.py" || ! -d "$GOAD/ad" || ! -f "$GOAD/playbooks.yml" ]]; then
  echo "error: $GOAD does not look like a GOAD checkout (goad.py, ad/ and playbooks.yml expected)" >&2
  exit 1
fi

# Rewrite playbooks.yml: remove our marked block (restoring the file exactly as it was),
# then optionally append a fresh one. Text-based so GOAD's comments and ordering are kept.
update_playbooks() {
  python3 - "$GOAD/playbooks.yml" "${1:-}" <<'PY'
import re, sys
path, fragment = sys.argv[1], sys.argv[2]
START, END = "# >>> maplewood-goad", "# <<< maplewood-goad"
text = open(path).read()
s = text.find("\n" + START)
if s != -1:
    m = re.match(re.escape(START) + r" \(added-eol=(\d)\)\n", text[s + 1:])
    added = int(m.group(1)) if m else 0
    e = text.find(END + "\n", s)
    tail = text[e + len(END) + 1:] if e != -1 else ""
    text = text[:s - added] + tail
if fragment:
    eol = text.endswith("\n")
    text += ("" if eol else "\n") + f"\n{START} (added-eol={0 if eol else 1})\n" + open(fragment).read() + END + "\n"
open(path, "w").write(text)
PY
}

if [[ "$mode" == "uninstall" ]]; then
  rm -rf "$GOAD/ad/MAPLEWOOD" "$GOAD"/ansible/mw-*.yml "$GOAD"/ansible/roles/mw_*
  update_playbooks ""
  echo "MapleWood USD removed from $GOAD"
  exit 0
fi

# Warn (don't fail) if someone edited district.yml without regenerating.
if python3 -c "import yaml" 2>/dev/null; then
  python3 "$HERE/generator/generate.py" --check >/dev/null \
    || echo "warning: generated files are out of date; run: python3 generator/generate.py" >&2
fi

rm -rf "$GOAD/ad/MAPLEWOOD"
cp -R "$HERE/lab/MAPLEWOOD" "$GOAD/ad/MAPLEWOOD"
cp "$HERE"/ansible/mw-*.yml "$GOAD/ansible/"
for role in "$HERE"/ansible/roles/mw_*; do
  rm -rf "$GOAD/ansible/roles/$(basename "$role")"
  cp -R "$role" "$GOAD/ansible/roles/"
done
update_playbooks "$HERE/ansible/playbooks.MAPLEWOOD.yml"

echo "MapleWood USD installed into $GOAD"
echo "Next: cd $GOAD && ./goad.sh -t install -l MAPLEWOOD -p virtualbox"
