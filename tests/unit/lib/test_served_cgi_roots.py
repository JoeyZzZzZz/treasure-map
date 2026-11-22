# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Entry reach for a CGI file nothing names: the served-tree inference in the hunt layer.

A per-request CGI binary is reached by its own path, so no rootfs script invokes it, no other
binary execs it, and — when the front end builds the URL from a variable rather than writing the
file name — no web asset names it either. All three reference kinds come back empty and the
candidate's reachability reads ``unknown``, which sinks the whole binary's candidates below every
proven-reachable one.

The inference these tests pin: a CGI file placed inside a directory tree a NAMED CGI is served
from inherits that reading, with the co-location recorded in the site so a reader can disagree.
What must NOT happen is the expensive half — a tree seeded from a script or exec reference, from a
system directory, or from the inference's own output would hand web reachability to hundreds of
system binaries.

Every test below was checked by breaking the code it guards and watching it fail (the recipe and
the observed failure are in each docstring).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from treasure_map.lib.hunt.evidence import (
    EntryIndex,
    build_flow_evidence,
    load_entry_index,
    served_cgi_roots,
)
from treasure_map.lib.query.triage import (
    _ENTRY_KIND_LABELS,
    _dim_reachability,
    _entry_reach_status,
    _entry_web_triggers,
)
from treasure_map.lib.storage.connection import open_db

# The unpacked image prefix the binaries table records, with the rootfs root inside it — the real
# shape: an absolute host path for the binary, a rootfs-relative one for the inventory and for
# every web asset.
_IMG = "/srv/images/fw.bin.extracted/squashfs-root"


def _analysis(
    tmp_path: Path,
    *,
    binaries: tuple[str, ...],
    endpoints: tuple[tuple[str, str], ...] = (),
    scripts: tuple[tuple[str, str], ...] = (),
    uninventoried: tuple[str, ...] = (),
    image_prefix: str = _IMG,
) -> Path:
    """A real analysis.db (project schema) holding ``binaries`` at rootfs-relative paths.

    ``endpoints`` are (web asset path, endpoint) pairs, ``scripts`` (script path, command) pairs,
    and ``uninventoried`` the binaries deliberately left out of the file inventory.
    ``image_prefix`` is what the binaries table prefixes each path with — "" spells the binaries
    rootfs-relative, as a database built elsewhere may."""
    db = tmp_path / "analysis.db"
    conn = open_db(db)
    for i, rel in enumerate(binaries, start=1):
        conn.execute(
            "INSERT INTO binaries (id, name, path, sha256, file_type, ghidra_status, last_seen_at)"
            " VALUES (?, ?, ?, ?, 'executable', 'ok', '2026-01-01')",
            (
                i,
                rel.rsplit("/", 1)[-1],
                f"{image_prefix}/{rel}" if image_prefix else rel,
                f"{i:064d}",
            ),
        )
        if rel not in uninventoried:
            conn.execute(
                "INSERT INTO file_inventory (path, sha256, size, file_type, inventoried_as) "
                "VALUES (?, ?, 4, 'elf_exec', 'elf')",
                (rel, f"{i:064d}"),
            )
    for j, (asset, endpoint) in enumerate(endpoints, start=1):
        conn.execute(
            "INSERT INTO non_binary_files (id, kind, name, path) VALUES (?, 'web_asset', ?, ?)",
            (j, asset.rsplit("/", 1)[-1], asset),
        )
        conn.execute(
            "INSERT INTO web_endpoints (file_id, asset_type, method, path, source) "
            "VALUES (?, 'html', 'GET', ?, 'xhr')",
            (j, endpoint),
        )
    for k, (script, command) in enumerate(scripts, start=len(endpoints) + 1):
        conn.execute(
            "INSERT INTO non_binary_files (id, kind, name, path) VALUES (?, 'shell_script', ?, ?)",
            (k, script.rsplit("/", 1)[-1], script),
        )
        conn.execute(
            "INSERT INTO script_calls (file_id, command, line_number, args_pattern) "
            "VALUES (?, ?, 7, 'literal')",
            (k, command),
        )
    conn.commit()
    conn.close()
    return db


def _index(db: Path, exec_sites: dict[str, list[dict[str, object]]] | None = None) -> EntryIndex:
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        return load_entry_index(conn, exec_sites=exec_sites)
    finally:
        conn.close()


def _sites(index: EntryIndex, rel: str) -> list[dict[str, object]]:
    return index.sites_for(rel.rsplit("/", 1)[-1], f"{_IMG}/{rel}")


# ── the inference itself ─────────────────────────────────────────────────────────────


def test_a_cgi_in_a_named_cgis_tree_reads_as_a_web_entry(tmp_path: Path) -> None:
    """A CGI nothing names, in the tree a named CGI is served from, gets ONE inferred site; a
    shared library and an extensionless file in the same tree get none.

    Verified RED by dropping the ``.cgi`` extension test in ``_served_site`` (the ``.so`` and the
    extensionless binary are then promoted too): 1 failed.
    """
    db = _analysis(
        tmp_path,
        binaries=("web/named.cgi", "web/app/other.cgi", "web/helper.so", "web/plain"),
        endpoints=(("web/index.htm", "/named.cgi?action=check"),),
    )
    index = _index(db)
    inferred = _sites(index, "web/app/other.cgi")
    assert inferred == [
        {
            "kind": "web_endpoint",
            "basis": "inferred",
            "note": "co-located with proven CGI named.cgi under served root web",
        }
    ]
    assert _sites(index, "web/helper.so") == []
    assert _sites(index, "web/plain") == []


def test_a_named_cgi_keeps_exactly_its_named_site(tmp_path: Path) -> None:
    """The seed itself is not also inferred: its site is the real reference, with the endpoint and
    no ``basis`` — the one place the two can be told apart stays clean.

    Verified RED by offering the inference to every CGI (dropping the ``web_named`` guard): the
    seed then carries a second, inferred site: 1 failed.
    """
    db = _analysis(
        tmp_path,
        binaries=("web/named.cgi", "web/other.cgi"),
        endpoints=(("web/index.htm", "/named.cgi?action=check"),),
    )
    sites = _sites(_index(db), "web/named.cgi")
    assert len(sites) == 1
    assert sites[0]["kind"] == "web_endpoint"
    assert sites[0]["endpoint"] == "/named.cgi?action=check"
    assert "basis" not in sites[0]


def test_the_note_records_the_co_location_and_no_host_path(tmp_path: Path) -> None:
    """The note names the seed and the rootfs-relative tree — not the absolute host path it was
    matched on. The site is stored inside flow_evidence and an overlay judgement's basis compares
    it as text, so an image unpacked under a different directory must not move it.

    Verified RED by writing ``root.directory`` (the absolute path) into the note instead of
    ``root.rel_directory``: 1 failed.
    """
    db = _analysis(
        tmp_path,
        binaries=("web/named.cgi", "web/app/other.cgi"),
        endpoints=(("web/index.htm", "/named.cgi"),),
    )
    note = str(_sites(_index(db), "web/app/other.cgi")[0]["note"])
    assert note == "co-located with proven CGI named.cgi under served root web"
    assert _IMG not in note


def test_a_cgi_outside_every_served_tree_stays_unknown(tmp_path: Path) -> None:
    """No tree, no site: a CGI elsewhere in the image, and a CGI in a directory whose name merely
    STARTS with a served root's, both stay ``unknown`` — the honest reading, never "unreachable".

    Verified RED by matching the tree with ``startswith(root.directory)`` without the separator
    (``webx`` then matches root ``web``): 1 failed.
    """
    db = _analysis(
        tmp_path,
        binaries=("web/named.cgi", "other/elsewhere.cgi", "webx/sneak.cgi"),
        endpoints=(("web/index.htm", "/named.cgi"),),
    )
    index = _index(db)
    assert _sites(index, "other/elsewhere.cgi") == []
    assert _sites(index, "webx/sneak.cgi") == []
    evidence = build_flow_evidence(
        pseudocode="void f(char *p){ system(p); }",
        callees=["system"],
        sink_arg="p",
        entry_sites=_sites(index, "other/elsewhere.cgi"),
    )
    assert evidence["entry_reach"] == {"status": "unknown", "sites": []}


# ── the read layer grades it, and is not touched ─────────────────────────────────────


def test_the_inferred_site_grades_through_the_unchanged_read_layer(tmp_path: Path) -> None:
    """The site's ``kind`` is the EXISTING ``web_endpoint``, so the triage read layer's fixed
    kind->label table grades it with no change there: entry:web -> proven. It contributes no
    trigger label, having no endpoint to quote.

    A new kind (``web_subtree``) would need a row in ``_ENTRY_KIND_LABELS`` — i.e. a read-layer
    change — which is why the label table is pinned here too.

    Verified RED by changing the inferred site's kind to ``web_subtree``: the status falls back to
    ``unknown`` and the dimension to not-proven: 1 failed.
    """
    db = _analysis(
        tmp_path,
        binaries=("web/named.cgi", "web/other.cgi"),
        endpoints=(("web/index.htm", "/named.cgi"),),
    )
    sites = _sites(_index(db), "web/other.cgi")
    assert [s.get("basis") for s in sites] == ["inferred"]  # fixture precondition
    evidence = {"entry_reach": {"status": "found", "sites": sites}}
    assert _entry_reach_status(evidence) == "entry:web"
    assert _entry_web_triggers(evidence) == ()
    dim = _dim_reachability(_entry_reach_status(evidence))
    assert (dim.state, dim.value) == ("proven", "entry:web")
    assert _ENTRY_KIND_LABELS == (
        ("web_endpoint", "web"),
        ("script_call", "script"),
        ("exec_edge", "exec"),
    )


def test_a_served_cgi_a_script_also_launches_reports_both_kinds(tmp_path: Path) -> None:
    """The inference does not replace or suppress a real reference, and is not suppressed by one:
    a CGI both launched by a script and placed in a served tree reports entry:web+script.

    Verified RED by suppressing the inference whenever any site was already found: the status
    drops to ``entry:script``: 1 failed.
    """
    db = _analysis(
        tmp_path,
        binaries=("web/named.cgi", "web/both.cgi"),
        endpoints=(("web/index.htm", "/named.cgi"),),
        scripts=(("etc/init.d/rcS", f"{_IMG}/web/both.cgi"),),
    )
    sites = _sites(_index(db), "web/both.cgi")
    assert {str(s["kind"]) for s in sites} == {"script_call", "web_endpoint"}
    assert _entry_reach_status({"entry_reach": {"sites": sites}}) == "entry:web+script"


# ── what may NOT seed a tree ─────────────────────────────────────────────────────────


def test_a_system_directory_never_roots_a_tree(tmp_path: Path) -> None:
    """A web asset that names a binary living in a system directory does not make that directory a
    served tree — the blast radius there is every CGI in a system tree. A web root BELOW a system
    directory (``usr/www``) is still a tree: the refusal is by full path, not by prefix.

    Verified RED twice: dropping the ``_NEVER_SERVED_ROOTS`` test promotes the CGI in ``sbin``
    (1 failed); refusing any path whose first segment is a system directory drops ``usr/www``
    and with it the real promotion (1 failed).
    """
    db = _analysis(
        tmp_path,
        binaries=("sbin/helperd", "sbin/tool.cgi", "usr/www/named.cgi", "usr/www/other.cgi"),
        endpoints=(
            ("web/a.htm", "/helperd.cgi?act=1"),
            ("web/b.htm", "/named.cgi?act=2"),
        ),
    )
    index = _index(db)
    # Fixture precondition: the system-directory binary really is named by a web asset (that is
    # what would seed the tree), so the refusal below is the only thing stopping it.
    assert [s["kind"] for s in _sites(index, "sbin/helperd")] == ["web_endpoint"]
    assert {r.rel_directory for r in index._served_roots} == {"usr/www"}
    assert _sites(index, "sbin/tool.cgi") == []
    assert [s.get("basis") for s in _sites(index, "usr/www/other.cgi")] == ["inferred"]


def test_a_script_reference_never_roots_a_tree(tmp_path: Path) -> None:
    """Only a web asset's name match seeds a tree. A script-launched binary in a web directory
    leaves the tree unseeded — system directories are full of script-launched binaries, and this
    is the rule that keeps them out.

    The prescan is asked DIRECTLY, with an index that does hold the script calls: the probe index
    ``load_entry_index`` seeds it from is defence in depth (it cannot offer a script site at all),
    and a test that relied on it would pass even with the kind test gone.

    Verified RED by seeding from every site kind instead of the ``web_endpoint`` ones: the sibling
    CGI is then promoted off a boot script: 1 failed.
    """
    db = _analysis(
        tmp_path,
        binaries=("web/launched", "web/other.cgi"),
        scripts=(("etc/init.d/rcS", f"{_IMG}/web/launched"),),
    )
    index = _index(db)
    assert [s["kind"] for s in _sites(index, "web/launched")] == ["script_call"]  # precondition
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        assert served_cgi_roots(conn, index) == ()
    finally:
        conn.close()
    assert index._served_roots == ()
    assert _sites(index, "web/other.cgi") == []


def test_a_launch_edge_never_roots_a_tree(tmp_path: Path) -> None:
    """Nor does the third reference kind, which arrives from a different source (the hunt's own
    call provenance, injected into the index). Asked directly, for the same reason as above.

    Verified RED by seeding from every site kind: the sibling CGI is then promoted off a launch
    edge: 1 failed.
    """
    launched = f"{_IMG}/web/launched"
    db = _analysis(tmp_path, binaries=("web/launched", "web/other.cgi"))
    index = _index(db, exec_sites={launched: [{"kind": "exec_edge", "launcher_binary": "init"}]})
    assert [s["kind"] for s in _sites(index, "web/launched")] == ["exec_edge"]  # precondition
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        assert served_cgi_roots(conn, index) == ()
    finally:
        conn.close()
    assert index._served_roots == ()
    assert _sites(index, "web/other.cgi") == []


def test_an_inferred_site_never_roots_a_tree_of_its_own(tmp_path: Path) -> None:
    """One pass, no feedback: a promoted CGI does not turn its own directory into a tree. A deep
    CGI therefore cites the NAMED seed and the directory that seed is in, never the inferred
    sibling one level up.

    Verified RED by running the prescan a second time over an index carrying the first pass's
    roots: the deep CGI then cites ``mid.cgi`` under ``web/a`` and the root set grows to two:
    1 failed.
    """
    db = _analysis(
        tmp_path,
        binaries=("web/named.cgi", "web/a/mid.cgi", "web/a/b/deep.cgi"),
        endpoints=(("web/index.htm", "/named.cgi"),),
    )
    index = _index(db)
    assert [s.get("basis") for s in _sites(index, "web/a/mid.cgi")] == ["inferred"]  # precondition
    assert {(r.rel_directory, r.seed) for r in index._served_roots} == {("web", "named.cgi")}
    assert _sites(index, "web/a/b/deep.cgi")[0]["note"] == (
        "co-located with proven CGI named.cgi under served root web"
    )


def test_a_binary_the_inventory_cannot_place_does_not_root_a_tree(tmp_path: Path) -> None:
    """A seed whose place in the image cannot be established is dropped, not trusted: the system-
    directory refusal is a statement about the rootfs-relative path, and without one there is
    nothing to refuse it by.

    Verified RED by falling back to the absolute host path when the inventory cannot place the
    binary (that path is in no refusal list, so the tree forms): 1 failed.
    """
    db = _analysis(
        tmp_path,
        binaries=("web/named.cgi", "web/other.cgi"),
        endpoints=(("web/index.htm", "/named.cgi"),),
        uninventoried=("web/named.cgi",),
    )
    index = _index(db)
    # Fixture precondition: the seed still carries its named site — only its PLACE is unknown.
    assert [s["kind"] for s in _sites(index, "web/named.cgi")] == ["web_endpoint"]
    assert index._served_roots == ()
    assert _sites(index, "web/other.cgi") == []


def test_an_analysis_db_without_a_file_inventory_promotes_nothing(tmp_path: Path) -> None:
    """An analysis.db from before the file inventory existed degrades to the old behaviour — every
    named site still read, nothing inferred — instead of failing the hunt.

    Verified RED by deriving the rootfs-relative path from the binaries table when the inventory
    is unreadable (the tree forms again): 1 failed. Removing the ``OperationalError`` guard
    instead fails the test by raising, which is the other half of the same property.
    """
    db = _analysis(
        tmp_path,
        binaries=("web/named.cgi", "web/other.cgi"),
        endpoints=(("web/index.htm", "/named.cgi"),),
    )
    conn = open_db(db)
    conn.execute("DROP TABLE file_inventory")
    conn.commit()
    conn.close()
    index = _index(db)
    assert [s["kind"] for s in _sites(index, "web/named.cgi")] == ["web_endpoint"]
    assert index._served_roots == ()
    assert _sites(index, "web/other.cgi") == []


# ── which tree, and which seed, a site cites ─────────────────────────────────────────


def test_the_most_specific_served_tree_is_the_one_cited(tmp_path: Path) -> None:
    """Two nested trees: the note cites the nearest one, so the reader checks the directory the
    file actually sits in rather than an ancestor.

    Verified RED by sorting the matching trees by path instead of by depth (the ancestor is cited):
    1 failed.
    """
    db = _analysis(
        tmp_path,
        binaries=("www/named.cgi", "www/cgi/also.cgi", "www/cgi/other.cgi"),
        endpoints=(
            ("web/a.htm", "/named.cgi"),
            ("web/b.htm", "/cgi/also.cgi"),
        ),
    )
    index = _index(db)
    assert {r.rel_directory for r in index._served_roots} == {"www", "www/cgi"}  # precondition
    assert _sites(index, "www/cgi/other.cgi")[0]["note"] == (
        "co-located with proven CGI also.cgi under served root www/cgi"
    )


def test_one_seed_per_tree_chosen_by_name_not_by_row_order(tmp_path: Path) -> None:
    """Two named CGIs in one directory: the note cites the same one every time, by name. The site
    is stored text an overlay judgement's basis compares, so a row order change must not move it.

    Verified RED by keeping the LAST seed seen (``seed > kept``) instead of the first by name:
    the note cites ``zeta.cgi``: 1 failed.
    """
    db = _analysis(
        tmp_path,
        binaries=("web/zeta.cgi", "web/alpha.cgi", "web/other.cgi"),
        endpoints=(
            ("web/a.htm", "/zeta.cgi"),
            ("web/b.htm", "/alpha.cgi"),
        ),
    )
    first = _sites(_index(db), "web/other.cgi")
    assert first[0]["note"] == "co-located with proven CGI alpha.cgi under served root web"
    assert _sites(_index(db), "web/other.cgi") == first


def test_an_index_built_without_the_prescan_behaves_as_before(tmp_path: Path) -> None:
    """The inference has exactly one producer. An index built without it — every caller that
    predates it, and the probe the prescan itself is seeded from — reads named sites only.

    Verified RED by defaulting ``_served_roots`` to a tree covering the image: 1 failed.
    """
    index = EntryIndex(
        script_calls=[],
        web_endpoints=[("web/index.htm", "html", "GET", "/named.cgi", "xhr")],
    )
    assert _sites(index, "web/other.cgi") == []
    assert [s["kind"] for s in _sites(index, "web/named.cgi")] == ["web_endpoint"]


def test_a_binaries_table_spelled_rootfs_relative_still_places_its_seed(tmp_path: Path) -> None:
    """A database whose binaries table spells the path rootfs-relative (no unpacked-image prefix)
    has no suffix for the inventory join to confirm, so the exact path counts as placing the file.
    Otherwise the inference would be silently off there rather than honestly unavailable.

    Verified RED by dropping the equality arm of the join (no seed can be placed, so no tree
    forms): 1 failed.
    """
    db = _analysis(
        tmp_path,
        binaries=("web/named.cgi", "web/other.cgi"),
        endpoints=(("web/index.htm", "/named.cgi"),),
        image_prefix="",
    )
    index = _index(db)
    assert {r.rel_directory for r in index._served_roots} == {"web"}
    assert index.sites_for("other.cgi", "web/other.cgi")[0]["note"] == (
        "co-located with proven CGI named.cgi under served root web"
    )


def test_served_cgi_roots_on_an_empty_database_is_empty() -> None:
    """A database with no binaries table at all (the shape ``load_entry_index`` already tolerates)
    yields no trees rather than an error.

    Verified RED by removing the ``OperationalError`` guard in ``served_cgi_roots``: the call
    raises instead of returning (): 1 failed.
    """
    conn = sqlite3.connect(":memory:")
    assert served_cgi_roots(conn, EntryIndex([], [])) == ()
    conn.close()
