#!/usr/bin/env bash
#
# Cut a release of the GameAnalytics JavaScript SDK.
#
# Steps, in order:
#   1. preflight   tools, branch, clean tree, in sync with origin, tag is free
#   2. install     npm ci
#   3. version     package.json, package-lock.json, src/device/GADevice.ts
#   4. build       npm run build, npm test
#   5. verify      the new version string really reached dist/
#   6. changelog   new entry under <!--(CHANGELOG_TOP)--> in README.md
#   7. release     commit, tag, push, gh release create [, npm publish]
#
# Everything up to step 7 is local and reversible. Step 7 is not: publishing a
# GitHub release triggers .github/workflows/slack-release-notify.yml, which
# posts to #public-sdk-releases.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

REMOTE="origin"
BRANCH="master"
VERSION_FILE="src/device/GADevice.ts"
CHANGELOG_FILE="README.md"
CHANGELOG_MARKER="<!--(CHANGELOG_TOP)-->"
DIST_FILES="dist/GameAnalytics.js dist/GameAnalytics.min.js dist/GameAnalytics.node.js dist/GameAnalytics.debug.js"

BUMP=""
NOTES=()
DRY_RUN=0
NPM_PUBLISH=0
ASSUME_YES=0
SKIP_TESTS=0

usage() {
    cat <<'EOF'
Usage: scripts/release.sh <patch|minor|major|X.Y.Z> [options]

Options:
  -m, --note TEXT     changelog bullet; repeat for several.
                      Defaults to the commit subjects since the last tag.
      --notes-file F  read bullets from F, one per line
      --dry-run       print every step, change nothing
      --skip-tests    skip `npm test` (needs Chrome)
      --npm-publish   also publish to the npm registry
  -y, --yes           do not ask for confirmation
  -h, --help          this text

Examples:
  scripts/release.sh patch --dry-run
  scripts/release.sh patch -m "bump dev dependencies"
  scripts/release.sh 5.2.0 -m "add X" -m "fix Y" --npm-publish
EOF
}

say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '    \033[1;32mok\033[0m %s\n' "$*"; }
warn() { printf '    \033[1;33m!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 not found in PATH"; }

run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    would run: %s\n' "$*"
    else
        "$@"
    fi
}

while [ $# -gt 0 ]; do
    case "$1" in
        patch|minor|major)
            [ -z "$BUMP" ] || die "version given twice: $BUMP and $1"
            BUMP="$1"; shift ;;
        -m|--note)
            [ $# -ge 2 ] || die "$1 needs a value"
            NOTES=("${NOTES[@]+"${NOTES[@]}"}" "$2"); shift 2 ;;
        --notes-file)
            [ $# -ge 2 ] || die "$1 needs a value"
            [ -f "$2" ] || die "no such file: $2"
            while IFS= read -r line; do
                line="${line#\* }"
                [ -n "$line" ] && NOTES=("${NOTES[@]+"${NOTES[@]}"}" "$line")
            done < "$2"
            shift 2 ;;
        --dry-run)     DRY_RUN=1; shift ;;
        --skip-tests)  SKIP_TESTS=1; shift ;;
        --npm-publish) NPM_PUBLISH=1; shift ;;
        -y|--yes)      ASSUME_YES=1; shift ;;
        -h|--help)     usage; exit 0 ;;
        -*)            die "unknown option: $1" ;;
        *)
            if printf '%s' "$1" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'; then
                [ -z "$BUMP" ] || die "version given twice: $BUMP and $1"
                BUMP="$1"; shift
            else
                die "unknown argument: $1"
            fi ;;
    esac
done

[ -n "$BUMP" ] || { usage; exit 1; }

# ---------------------------------------------------------------- 1. preflight
say "preflight"
for t in git node npm gh; do need "$t"; done

current_branch="$(git rev-parse --abbrev-ref HEAD)"
[ "$current_branch" = "$BRANCH" ] || die "on '$current_branch'; releases are cut from '$BRANCH'"
# Untracked files under dist/ are tolerated: the build regenerates dist/ and the
# release commit stages it. Anything else dirty is a real obstacle.
dirty="$(git status --porcelain | grep -v "^?? dist/" || true)"
[ -z "$dirty" ] || die "working tree is dirty; commit or stash first"

git fetch "$REMOTE" --quiet --tags
[ "$(git rev-list --count "HEAD..$REMOTE/$BRANCH")" = "0" ] || die "$BRANCH is behind $REMOTE/$BRANCH; pull first"
[ "$(git rev-list --count "$REMOTE/$BRANCH..HEAD")" = "0" ] || die "$BRANCH is ahead of $REMOTE/$BRANCH; push first"

gh auth status >/dev/null 2>&1 || die "gh is not authenticated; run 'gh auth login'"
[ "$NPM_PUBLISH" -eq 0 ] || npm whoami >/dev/null 2>&1 || die "not logged in to npm; run 'npm login' (or drop --npm-publish)"
ok "on $BRANCH, clean, in sync with $REMOTE"

CURRENT_VERSION="$(node -p 'require("./package.json").version')"
NEW_VERSION="$(node -e '
const [cur, bump] = process.argv.slice(1);
if (/^\d+\.\d+\.\d+/.test(bump)) { process.stdout.write(bump); process.exit(0); }
const m = cur.match(/^(\d+)\.(\d+)\.(\d+)/);
if (!m) { console.error("cannot parse current version: " + cur); process.exit(1); }
let a = +m[1], b = +m[2], c = +m[3];
if (bump === "major") { a++; b = 0; c = 0; }
else if (bump === "minor") { b++; c = 0; }
else { c++; }
process.stdout.write(a + "." + b + "." + c);
' "$CURRENT_VERSION" "$BUMP")"
TAG="v$NEW_VERSION"

git rev-parse -q --verify "refs/tags/$TAG" >/dev/null && die "tag $TAG already exists locally"
! git ls-remote --exit-code --tags "$REMOTE" "refs/tags/$TAG" >/dev/null 2>&1 || die "tag $TAG already exists on $REMOTE"
ok "$TAG is free"

if [ "${#NOTES[@]}" -eq 0 ]; then
    last_tag="$(git describe --tags --abbrev=0 2>/dev/null || true)"
    [ -n "$last_tag" ] || die "no previous tag to derive notes from; pass --note"
    say "no --note given, deriving bullets from commits since $last_tag"
    while IFS= read -r line; do
        [ -n "$line" ] && NOTES=("${NOTES[@]+"${NOTES[@]}"}" "$line")
    done < <(git log --no-merges --format='%s' "$last_tag..HEAD")
    [ "${#NOTES[@]}" -gt 0 ] || die "no commits since $last_tag; nothing to release"
fi

NOTES_MD=""
for n in "${NOTES[@]}"; do NOTES_MD="$NOTES_MD* $n"$'\n'; done

say "release plan"
printf '    version    %s -> %s\n' "$CURRENT_VERSION" "$NEW_VERSION"
printf '    tag        %s\n' "$TAG"
printf '    remote     %s\n' "$(git remote get-url "$REMOTE")"
if [ "$NPM_PUBLISH" -eq 1 ]; then printf '    npm        publish as %s\n' "$(npm whoami)"
else printf '    npm        skip (pass --npm-publish to enable)\n'; fi
printf '    notes\n'
printf '%s' "$NOTES_MD" | sed 's/^/      /'

if [ "$DRY_RUN" -eq 0 ] && [ "$ASSUME_YES" -eq 0 ]; then
    printf '\nThis pushes %s and publishes a GitHub release, which posts to Slack.\n' "$TAG"
    printf 'Continue? [y/N] '
    read -r reply
    case "$reply" in y|Y|yes|Yes) ;; *) die "aborted" ;; esac
fi

# ------------------------------------------------------------------ 2. install
say "installing dependencies"
run npm ci

# ------------------------------------------------------------------ 3. version
say "setting version to $NEW_VERSION"
run npm version "$NEW_VERSION" --no-git-tag-version --allow-same-version
run node -e '
const fs = require("fs");
const [file, version] = process.argv.slice(1);
const re = /(sdkWrapperVersion\s*:\s*string\s*=\s*"javascript\s+)\d+\.\d+\.\d+[^"]*(")/;
const src = fs.readFileSync(file, "utf8");
if (!re.test(src)) { console.error("sdkWrapperVersion pattern not found in " + file); process.exit(1); }
fs.writeFileSync(file, src.replace(re, "$1" + version + "$2"));
' "$VERSION_FILE" "$NEW_VERSION"
ok "package.json, package-lock.json, $VERSION_FILE"

# -------------------------------------------------------------------- 4. build
say "building"
run npm run build
if [ "$SKIP_TESTS" -eq 1 ]; then
    warn "tests skipped (--skip-tests)"
else
    say "testing"
    run npm test
fi

# ------------------------------------------------------------------- 5. verify
say "verifying dist/ carries $NEW_VERSION"
if [ "$DRY_RUN" -eq 0 ]; then
    for f in $DIST_FILES; do
        grep -q "javascript $NEW_VERSION" "$f" || die "$f does not contain 'javascript $NEW_VERSION'"
        ok "$f"
    done
else
    printf '    would grep: javascript %s in %s\n' "$NEW_VERSION" "$DIST_FILES"
fi

# ---------------------------------------------------------------- 6. changelog
say "adding changelog entry"
run node -e '
const fs = require("fs");
const [file, marker, version, ...notes] = process.argv.slice(1);
const src = fs.readFileSync(file, "utf8");
const i = src.indexOf(marker);
if (i === -1) { console.error("changelog marker not found in " + file); process.exit(1); }
if (src.includes("**" + version + "**")) { console.error("changelog already has an entry for " + version); process.exit(1); }
const entry = "\n**" + version + "**\n" + notes.map(n => "* " + n).join("\n") + "\n";
const at = i + marker.length;
fs.writeFileSync(file, src.slice(0, at) + entry + src.slice(at));
' "$CHANGELOG_FILE" "$CHANGELOG_MARKER" "$NEW_VERSION" "${NOTES[@]}"
ok "$CHANGELOG_FILE"

# ------------------------------------------------------------------ 7. release
say "committing $TAG"
run git add package.json package-lock.json "$VERSION_FILE" "$CHANGELOG_FILE" dist
run git commit -m "Release $TAG" -m "$NOTES_MD"
run git tag -a "$TAG" -m "$TAG"

say "pushing to $REMOTE"
run git push "$REMOTE" "$BRANCH"
run git push "$REMOTE" "$TAG"

say "creating GitHub release"
run gh release create "$TAG" --target "$BRANCH" --title "$TAG" --notes "$NOTES_MD"

if [ "$NPM_PUBLISH" -eq 1 ]; then
    say "publishing to npm"
    run npm publish --access public
fi

say "done"
if [ "$DRY_RUN" -eq 1 ]; then
    printf '    dry run: nothing was changed\n'
else
    printf '    %s\n' "$(gh release view "$TAG" --json url --jq .url)"
fi
