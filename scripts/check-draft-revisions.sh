#!/usr/bin/env bash
#
# Compares the draft revisions pinned in SPEC-MAP.md against what the WIMSE
# working group has actually published, and reports whether the editors'
# working copy has moved on since.
#
# Two different kinds of drift matter, and they are not the same thing:
#
#   * "pin drift" — a new revision has been published and SPEC-MAP.md still
#     names the old one. This is what the exit status reports, because a pin
#     that is silently out of date is a claim the implementation no longer
#     backs. Bumping it is a reviewed change; see the end of SPEC-MAP.md.
#
#   * "unreleased changes" — the editors' repository has commits on the draft
#     since the published revision was tagged. Nothing is wrong yet, but this
#     is the text the working group is discussing, and the cheapest moment to
#     react to a breaking change is before it ships.
#
# The published revision is read from the submission tags in the editors'
# repository rather than from the datatracker: the tags are what the editors
# push at submission time, they match the datatracker exactly, and reading
# them needs no second network dependency.
#
# Requires the `gh` CLI, authenticated. Read-only.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
spec_map="${repo_root}/SPEC-MAP.md"

# draft-name<TAB>editors-repository. The document lives at <draft-name>.md in
# that repository; four of the seven share one repository.
drafts=$(
	cat <<-'EOF'
		draft-ietf-wimse-arch	draft-ietf-wimse-arch
		draft-ietf-wimse-identifier	draft-ietf-wimse-identifier
		draft-ietf-wimse-workload-creds	draft-ietf-wimse-s2s-protocol
		draft-ietf-wimse-wpt	draft-ietf-wimse-s2s-protocol
		draft-ietf-wimse-http-signature	draft-ietf-wimse-s2s-protocol
		draft-ietf-wimse-mutual-tls	draft-ietf-wimse-s2s-protocol
		draft-ietf-wimse-workload-identity-practices	draft-ietf-wimse-workload-identity-practices
	EOF
)

# The revision SPEC-MAP.md pins, as a bare two-digit number. The table row is
# "| `draft-ietf-wimse-wpt` | -02 | ... |"; anything after the pinned-revisions
# table is ignored, since later tables mention the same draft names.
pinned_revision() {
	local draft=$1
	awk -v draft="$draft" '
		/^## Drafts in progress upstream/ { exit }
		$0 ~ "\\| `" draft "` \\|" {
			# Field 3 is the revision cell, written "-08".
			gsub(/[ \t-]/, "", $3)
			print $3
			exit
		}
	' FS='|' "$spec_map"
}

# The highest submission tag for a draft, as a bare two-digit number. Tags for
# the pre-adoption individual drafts (draft-sheffer-…, draft-salowey-…) do not
# match the prefix and are skipped.
published_revision() {
	local draft=$1 repo=$2
	# A draft with no submission tag yet is a state to report, not an error, so
	# grep's empty-match exit status must not reach `set -e` through `pipefail`.
	gh api "repos/ietf-wg-wimse/${repo}/tags" --paginate --jq '.[].name' |
		{ grep -E "^${draft}-[0-9]{2}$" || true; } |
		sed "s/^${draft}-//" |
		sort -n |
		tail -1
}

# Whether the draft's own file has been touched on `main` since that tag. The
# commit count is the whole branch, not just this file, which is why the two are
# reported separately: in the shared repository a draft can be untouched while
# `main` is far ahead. GitHub caps the compare file list at 300 entries, which
# no Internet-Draft repository comes close to.
unreleased_changes() {
	local draft=$1 repo=$2 rev=$3
	gh api "repos/ietf-wg-wimse/${repo}/compare/${draft}-${rev}...main" \
		--jq "if ([.files[].filename] | index(\"${draft}.md\")) then \"yes (main is \\(.ahead_by) commits ahead of the tag)\" else \"no\" end"
}

status=0
printf '| Draft | Pinned | Published | Unreleased changes |\n'
printf '| --- | --- | --- | --- |\n'

while IFS=$'\t' read -r draft repo; do
	[ -n "$draft" ] || continue

	pinned=$(pinned_revision "$draft")
	published=$(published_revision "$draft" "$repo")

	if [ -z "$published" ]; then
		printf '| `%s` | %s | **unknown** | — |\n' "$draft" "${pinned:--}"
		status=1
		continue
	fi

	changes=$(unreleased_changes "$draft" "$repo" "$published")

	if [ -z "$pinned" ]; then
		# Not every draft is pinned: the architecture and practices documents
		# are guidance, and SPEC-MAP.md records them with no crate.
		printf '| `%s` | — | -%s | %s |\n' "$draft" "$published" "$changes"
	elif [ "$pinned" != "$published" ]; then
		printf '| `%s` | **-%s** | **-%s (new)** | %s |\n' \
			"$draft" "$pinned" "$published" "$changes"
		status=1
	else
		printf '| `%s` | -%s | -%s | %s |\n' "$draft" "$pinned" "$published" "$changes"
	fi
done <<<"$drafts"

echo
if [ "$status" -ne 0 ]; then
	echo "A pin in SPEC-MAP.md is behind a published revision, or a draft's"
	echo "submission tag could not be read. For a pin, read the diff between"
	echo "revisions and bump it deliberately; see SPEC-MAP.md."
else
	echo "Every pin in SPEC-MAP.md names the current published revision."
	echo "A 'yes' above is not a failure: it means the working group is editing"
	echo "text this workspace has not seen yet."
fi

exit "$status"
