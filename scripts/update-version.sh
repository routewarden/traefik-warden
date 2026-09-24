#!/usr/bin/env bash
# scripts/update-version.sh
# Usage:
#   ./scripts/update-version.sh              # Reads version directly from version.json
#   ./scripts/update-version.sh v0.2.5       # Updates version.json and syncs across all files
#   ./scripts/update-version.sh 0.2.5        # Supports semver without 'v' prefix

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION_FILE="${ROOT_DIR}/version.json"

# If a version argument was provided, update version.json first
if [ -n "${1:-}" ]; then
  RAW_VERSION="$1"

  # Ensure format has leading 'v'
  if [[ ! "$RAW_VERSION" =~ ^v ]]; then
    NEW_VERSION="v${RAW_VERSION}"
  else
    NEW_VERSION="${RAW_VERSION}"
  fi

  # Validate semver pattern (e.g. v1.2.3, v1.2.3-beta.1)
  if [[ ! "$NEW_VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
    echo "❌ Error: Invalid semantic version format: '$RAW_VERSION'"
    echo "Expected format: vMAJOR.MINOR.PATCH (e.g. v0.2.5)"
    exit 1
  fi

  # Write back to version.json
  cat <<EOF > "$VERSION_FILE"
{
  "version": "${NEW_VERSION}"
}
EOF
fi

# Ensure version.json exists
if [ ! -f "$VERSION_FILE" ]; then
  echo "❌ Error: ${VERSION_FILE} not found and no version argument provided."
  echo "Usage: $0 [version]"
  exit 1
fi

# Extract version from version.json (compatible with grep/sed without requiring jq)
TARGET_VERSION=$(grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' "$VERSION_FILE" | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$TARGET_VERSION" ]; then
  echo "❌ Error: Could not read 'version' key from ${VERSION_FILE}."
  exit 1
fi

echo "🔄 Synchronizing RouteWarden version: ${TARGET_VERSION} (from version.json)"

UPDATED_COUNT=0

# List of files to update
FILES=(
  "README.md"
  "VERSIONING.md"
  "examples/01-basic-sensitive-files/docker-compose.yml"
  "examples/02-global-entrypoint-shield/docker-compose.yml"
  "examples/03-ip-whitelist-vpn/docker-compose.yml"
  "examples/04-captcha-challenge/docker-compose.yml"
  "examples/05-kubernetes-ingressroute/README.md"
)

for REL_PATH in "${FILES[@]}"; do
  FILE_PATH="${ROOT_DIR}/${REL_PATH}"
  if [ -f "$FILE_PATH" ]; then
    # Replace CLI flag: --experimental.plugins.routewarden.version=vX.Y.Z
    sed -i '' -E "s|(--experimental\.plugins\.routewarden\.version=)v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?|\1${TARGET_VERSION}|g" "$FILE_PATH"

    # Replace YAML version property: version: vX.Y.Z
    sed -i '' -E "s|(version:[[:space:]]+)v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?|\1${TARGET_VERSION}|g" "$FILE_PATH"

    # Replace JSON version property (for VERSIONING.md documentation code blocks): "version": "vX.Y.Z"
    sed -i '' -E "s|(\"version\"[[:space:]]*:[[:space:]]*\")v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\")|\1${TARGET_VERSION}\3|g" "$FILE_PATH"

    echo "  ✓ Synchronized ${REL_PATH}"
    UPDATED_COUNT=$((UPDATED_COUNT + 1))
  fi
done

echo ""
echo "✨ Successfully synchronized version ${TARGET_VERSION} across ${UPDATED_COUNT} file(s)!"
echo "👉 Next steps:"
echo "   git diff"
echo "   git commit -am 'chore: release ${TARGET_VERSION}'"
echo "   git tag ${TARGET_VERSION}"
echo "   git push origin main --tags"
