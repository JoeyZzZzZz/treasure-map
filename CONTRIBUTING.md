# Contributing to Treasure Map

Thanks for your interest. Bug reports, feature ideas, documentation fixes and pull requests are all
welcome. Treasure Map is a developer preview and changes quickly, so for anything larger than a
small fix, please open an issue first to talk it through — it saves you from building on something
that is about to move.

## Licensing of contributions

Treasure Map is licensed under the [Apache License 2.0](LICENSE). As section 5 of that license says,
anything you intentionally submit for inclusion (a pull request, a patch, a suggested change) is
licensed under the same Apache-2.0 terms, with no additional conditions. There is no CLA to sign.

By submitting a contribution you confirm that you have the right to do so — it is your own work, or
you have permission to contribute it under Apache-2.0. If you include code from elsewhere, keep its
license notice and say where it comes from in the pull request.

## Developer Certificate of Origin

Every commit in a pull request must be signed off: commit with `git commit -s`, which adds a
`Signed-off-by: Your Name <you@example.com>` line matching the commit's author. The sign-off
certifies the [Developer Certificate of Origin 1.1](https://developercertificate.org/) — in short,
that you wrote the change or otherwise have the right to submit it under the project's license. A
CI check verifies the sign-off on each commit of the pull request; to fix a missing one, run
`git commit --amend -s` (or `git rebase --signoff main` for several commits) and push again.

## Reporting bugs

Open an issue with:

- what you did, what you expected, and what happened instead;
- `tmap --version` and the output of `tmap doctor`;
- your OS (and whether it is WSL).

Please do not attach firmware images or anything you are not allowed to share.

## Suggesting features

Open an issue describing your use case and what you would like to see.

## Development setup

End users install with the one-line installer (see the README). To work on the code, use a clone
with an editable install:

```bash
git clone https://github.com/JoeyZzZzZz/treasure-map.git
cd treasure-map
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
./scripts/install-hooks.sh   # activates the git hooks in .githooks/
tmap init                    # finds or installs the Ghidra / BinExport / BinDiff toolchain
```

Before opening a pull request, run the same checks CI runs:

```bash
./scripts/ci-local.sh        # ruff, ruff format --check, mypy strict, pytest
```

A behaviour change should come with a test that fails without it. Unit tests never touch the
network or your real `~/.treasure-map`; the fixtures in `tests/conftest.py` take care of that.

## Keeping the repository vendor-neutral

The repository does not name specific device vendors or model numbers. A `pre-commit` and a
`commit-msg` hook (installed by `./scripts/install-hooks.sh`) check the staged diff and the commit
message against `.githooks/vendor-watchlist.example.txt`, a list of generic model-number patterns;
CI runs the same check on every push and pull request. If a check flags something, rephrase it in
generic terms. Maintainers can point the hooks at a fuller local list with
`TM_VENDOR_WATCHLIST=/path/to/list`.
