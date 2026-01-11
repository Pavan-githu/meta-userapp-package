#!/bin/bash
# Version bump script for IoT Gateway Application
# Usage: ./bump_version.sh [major|minor|patch]

VERSION_FILE="version.h"
RECIPE_FILE="../iot-gateway-apps_0.1.bb"

if [ ! -f "$VERSION_FILE" ]; then
    echo "Error: $VERSION_FILE not found!"
    exit 1
fi

# Read current version
MAJOR=$(grep "#define VERSION_MAJOR" $VERSION_FILE | awk '{print $3}')
MINOR=$(grep "#define VERSION_MINOR" $VERSION_FILE | awk '{print $3}')
PATCH=$(grep "#define VERSION_PATCH" $VERSION_FILE | awk '{print $3}')

echo "Current version: $MAJOR.$MINOR.$PATCH"

# Determine what to bump
BUMP_TYPE=${1:-patch}

case $BUMP_TYPE in
    major)
        MAJOR=$((MAJOR + 1))
        MINOR=0
        PATCH=0
        ;;
    minor)
        MINOR=$((MINOR + 1))
        PATCH=0
        ;;
    patch)
        PATCH=$((PATCH + 1))
        ;;
    *)
        echo "Usage: $0 [major|minor|patch]"
        echo "  major: Increment major version (breaking changes)"
        echo "  minor: Increment minor version (new features)"
        echo "  patch: Increment patch version (bug fixes) [default]"
        exit 1
        ;;
esac

NEW_VERSION="$MAJOR.$MINOR.$PATCH"
echo "New version: $NEW_VERSION"

# Update version.h
sed -i "s/#define VERSION_MAJOR [0-9]*/#define VERSION_MAJOR $MAJOR/" $VERSION_FILE
sed -i "s/#define VERSION_MINOR [0-9]*/#define VERSION_MINOR $MINOR/" $VERSION_FILE
sed -i "s/#define VERSION_PATCH [0-9]*/#define VERSION_PATCH $PATCH/" $VERSION_FILE

echo "✓ Updated $VERSION_FILE"

# Update recipe file if it exists
if [ -f "$RECIPE_FILE" ]; then
    sed -i "s/^PV = \"[0-9.]*\"/PV = \"$NEW_VERSION\"/" $RECIPE_FILE
    echo "✓ Updated $RECIPE_FILE"
fi

echo ""
echo "Version bumped successfully to $NEW_VERSION"
echo ""
echo "Next steps:"
echo "  1. Review the changes: git diff"
echo "  2. Commit: git add version.h $RECIPE_FILE && git commit -m \"Bump version to $NEW_VERSION\""
echo "  3. Tag: git tag -a v$NEW_VERSION -m \"Release version $NEW_VERSION\""
echo "  4. Push: git push && git push --tags"
