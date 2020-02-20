#!/bin/sh
FIRST=""
if [ ! -f CHANGELOG.md ]; then
  #VERSION=$(find ./ -name .v.semver -exec cat {} \; | head -n1 | tr -d '\n')
  FIRST="-f"
fi

# supports passing of additional args to standard-version
npx standard-version@7.1.0 "$FIRST" --header '# CHANGELOG
' \
  "$@" \
  && echo "Sign-off commit and tags via 'git commit --amend --signoff' and 'git tag -sf v...'"
