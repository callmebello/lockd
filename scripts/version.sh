#!/bin/bash
# Fonte única para CFBundleShortVersionString e CFBundleVersion.
LOCKD_RESOLVED_VERSION="${LOCKD_VERSION:-$(cat "$(dirname "${BASH_SOURCE[0]}")/VERSION")}"
if ! [[ "$LOCKD_RESOLVED_VERSION" =~ ^(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]?)\.(0|[1-9][0-9]?)$ ]]; then
  echo 'LOCKD_VERSION deve ser uma versão numérica MAJOR.MINOR.PATCH (até 9998.99.99; sem zeros à esquerda).' >&2
  return 1
fi
IFS=. read -r version_major version_minor version_patch <<< "$LOCKD_RESOLVED_VERSION"
if (( version_major > 9998 )); then
  echo 'MAJOR deve ser até 9998 para permitir CFBundleVersion com primeiro componente positivo.' >&2
  return 1
fi
LOCKD_RESOLVED_BUILD="$((version_major + 1)).${version_minor}.${version_patch}"
export LOCKD_RESOLVED_VERSION LOCKD_RESOLVED_BUILD
