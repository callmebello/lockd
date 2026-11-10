#!/bin/bash
# Release local; não instala o app e não abre o cofre.
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
DRY_RUN=false
case "${1:-}" in
  --dry-run) DRY_RUN=true; shift ;;
  --help|-h) echo 'Uso: scripts/release.sh [--dry-run]'; exit 0 ;;
esac
if [[ $# -ne 0 ]]; then echo 'Uso: scripts/release.sh [--dry-run]' >&2; exit 2; fi
source scripts/version.sh
PROFILE="${LOCKD_NOTARY_PROFILE:-lockd-notary}"
if $DRY_RUN; then
  export LOCKD_SIGN_IDENTITY="${LOCKD_SIGN_IDENTITY:-Apple Development: Gustavo Henrique Correia Ferreira (44LNP6HYTB)}"
  case "$LOCKD_SIGN_IDENTITY" in 'Apple Development: '*) ;; *) echo 'Dry-run exige Apple Development: nome (ID).' >&2; exit 2 ;; esac
  SUFFIX=-dry-run
else
  : "${LOCKD_SIGN_IDENTITY:?Defina LOCKD_SIGN_IDENTITY=Developer ID Application: nome (TEAMID). Consulte docs/RELEASE.md.}"
  case "$LOCKD_SIGN_IDENTITY" in 'Developer ID Application: '*) ;; *) echo 'Release exige Developer ID Application; Apple Distribution não serve.' >&2; exit 2 ;; esac
  SUFFIX=
fi
export LOCKD_VERSION="$LOCKD_RESOLVED_VERSION"
STEM="Lockd-${LOCKD_VERSION}-arm64${SUFFIX}"
DMG="dist/${STEM}.dmg"
MANIFEST="dist/${STEM}.version.json"
# Nunca deixe um checksum/manifesto anterior anunciar uma tentativa incompleta.
rm -f "$MANIFEST" "${DMG}.sha256"
bash scripts/build_app.sh
APP="$PWD/dist/Lockd.app"
WORK="$(mktemp -d "$PWD/dist/.release.XXXXXX")"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

notarize() {
  local file="$1" label="$2" result="dist/${STEM}-$2-notary.json" status
  # notarytool pode responder Invalid com exit 0: valide também o status JSON.
  if ! xcrun notarytool submit "$file" --keychain-profile "$PROFILE" --wait --output-format json > "$result"; then
    echo "Falha no serviço de notarização; resposta em $result. Consulte docs/RELEASE.md." >&2
    return 1
  fi
  status="$(plutil -extract status raw -o - "$result")"
  if [[ "$status" != Accepted ]]; then
    echo "Notarização $label: $status. Leia $result e obtenha o log com notarytool log (docs/RELEASE.md)." >&2
    return 1
  fi
}

if ! $DRY_RUN; then
  # Primeiro anexa o ticket ao app; só depois congela o conteúdo do DMG.
  ditto -c -k --keepParent "$APP" "$WORK/Lockd.zip"
  notarize "$WORK/Lockd.zip" app
  xcrun stapler staple "$APP"
  xcrun stapler validate "$APP"
fi
mkdir "$WORK/image"
ditto "$APP" "$WORK/image/Lockd.app"
ln -s /Applications "$WORK/image/Applications"
hdiutil create -volname Lockd -srcfolder "$WORK/image" -format UDZO -ov "$DMG"
codesign --force --sign "$LOCKD_SIGN_IDENTITY" --timestamp "$DMG"
codesign --verify --deep --strict --verbose=2 "$APP"
codesign --verify --strict --verbose=2 "$DMG"
if $DRY_RUN; then
  echo 'DRY-RUN: sem submissão nem tickets; Gatekeeper pode rejeitar Apple Development.'
  if spctl -a -vv --type execute "$APP"; then
    echo 'Gatekeeper local aceitou; isso não comprova distribuição em outro Mac.'
  else
    echo 'Gatekeeper rejeitou o app de desenvolvimento (esperado); release público NÃO validado.'
  fi
  if xcrun stapler validate "$DMG"; then
    echo 'Ticket presente; dry-run não comprova notarização deste build.'
  else
    echo 'Sem ticket no DMG de dry-run (esperado).'
  fi
else
  notarize "$DMG" dmg
  xcrun stapler staple "$DMG"
  xcrun stapler validate "$DMG"
  codesign --verify --deep --strict --verbose=2 "$APP"
  codesign --verify --strict --verbose=2 "$DMG"
  spctl -a -vv --type execute "$APP"
  spctl -a -vv --type open --context context:primary-signature "$DMG"
fi
shasum -a 256 "$DMG" > "${DMG}.sha256"
DIGEST="$(shasum -a 256 "$DMG" | awk '{print $1}')"
cat > "$MANIFEST" <<JSON
{"version":"$LOCKD_VERSION","build":"$LOCKD_RESOLVED_BUILD","architecture":"arm64","minimumMacOS":"14.0","dryRun":$DRY_RUN,"notarized":$($DRY_RUN && echo false || echo true),"artifact":"${STEM}.dmg","sha256":"$DIGEST"}
JSON
echo "OK: $DMG; ${DMG}.sha256; $MANIFEST"
