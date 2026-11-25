---
name: tmap-scan-review
description: Work through one firmware scan's candidate map with the Treasure Map (tmap) MCP server, unit by unit; the must-read set of one image usually spans many sessions, or tmap's batch driver. Use when asked to review, triage or audit a single firmware scan (one run, not a version diff) with Treasure Map or tmap.
---

# Reviewing one firmware scan with tmap

tmap scans one firmware and hands you a candidate map — tens of thousands of leads for a large
image. `list_candidates` RANKS them, which says what to read first and never what may be left
unread. This skill is the other half: the scan review profile cuts the run into four bands and two
tiers, hands the must-read part out in work units, and counts what is still unread. tmap draws no
conclusion and produces no attack: every judgment is yours.

## The four bands

Every candidate is in exactly one, cut above the ranking (nothing here changes a rank):

- **`exec`** — a command / format-string / file-path sink, no proven-safe fact, and a dangerous
  source was read: either a value store key a web form writes, or an analyzer-marked parameter
  whose charset is unconstrained or unread. Something outside could reach it and be interpreted.
- **`write`** — a memory-copy or formatter sink, same conditions: something outside could reach it
  and overrun.
- **`unresolved`** — one of those sink families, not proven safe, and at least one dimension the
  analysis could not resolve. This is NOT a weaker finding than the two above: it is an UNREAD
  axis. A reachability of `unknown` never means unreachable.
- **`tail`** — a proven-safe fact: a compile-time-constant value at the sink. Measured on every
  corpus, that is the WHOLE of this band, and every member of it still carries at least one unread
  axis — nothing reaches the tail by being plain, only by being lifted out of the must-read set by
  the demotion iron law. Counted in the declaration, not handed out. Still readable and judgeable
  by hand.

Entering a band asks only "could this be written to, or executed". It does NOT ask how much it
would matter: `format` sits at the lowest IMPACT tier and is still a `write` band member, because a
formatter writing into a fixed buffer is a memory-write lead. Grading stays in the ranking.

## The two tiers

- **Tier 1 (must read)** = `exec` + `write` + the `unresolved` members whose sink is a command,
  format-string or file-path one. Read "there is a reason to think this is dangerous". No budget,
  no top-N: the set is large on purpose.
- **Tier 2** = the rest of `unresolved` — a memory-write family with an unread axis, the weakest
  signal left, plus any sink class this read layer does not recognise. Not handed out until tier 1
  is done; always counted in the declaration. A person asks for it (`--until complete`).

Why the `unresolved` members with an RCE-class sink are in tier 1 and not tier 2: the sink is the
one axis that IS resolved for them. An unread source on a `system()` call is a worse place to stop
reading than an unread source on a `memcpy`.

## The loop

This describes a unit as the BATCH DRIVER hands it out. There is no tool for asking the server for
the next scan unit this version, and `tmap review scan <run_id>` prints counts only — no unit ids
and no refs. So in an interactive session there is no step 1 to do: either a person runs the driver
(below), or you are working from refs you already have, in which case steps 2–4 still apply to each
of them.

1. You are handed ONE unit: a list of candidate `evidence_ref`s from one binary, at most 16.
2. For EVERY ref in the unit, call `explain_candidate(evidence_ref=...)`. Then read whatever else
   you need: `get_pseudocode`, `get_sink_provenance`, `get_callees`, `get_xrefs`, `get_strings`,
   `get_nvram_key_flow`.
3. Judge EVERY ref with `annotate(evidence_ref=..., verdict=..., rationale=...)`.
4. Then stop. Do not judge anything outside the unit.

## Rules

- **Reading a candidate means calling `explain_candidate` ON THAT REF.** Reading the whole
  function it sits in does NOT clear its read gate — `get_pseudocode`, `get_disassembly` and
  `get_callees` answer the gate for a DIFF subject's function anchor, and a scan candidate's
  anchor is not one of those. This is the opposite of the habit the diff side builds, so it is
  worth saying plainly: 16 candidates in one function still need 16 `explain_candidate` calls.
  A verdict written before its own ref was explained reads `needs_recheck` — not disposed — and
  the unit comes back.
- **An unjudged candidate is UNREAD, which is not "nothing found".** Never report a scan as
  showing nothing because the part you read showed nothing. Quote the declaration's counts.
- `excluded` on a must-read (tier 1) candidate REQUIRES `exclusion_why`: what stops the input from
  reaching the sink at all. Both dismissal verdicts move a candidate out of the dangerous view by
  the same amount, so on a candidate somebody was told to read, the cheaper word is not the
  cheaper way out. Off the must-read set a sentence of `rationale` is still enough.
- `safe` REQUIRES `block_source` + `block_point` + `block_why`, and the third is the load-bearing
  one: why the block covers EVERY path in and cannot be worked around. A wrong `safe` only comes
  back when the code changes, never because the judgment was wrong.
- `exploitable` should carry `chain` (citing code) and two or more `verification_gaps` — what is
  still to be confirmed on real hardware. `inconclusive` is an honest answer and stays in view.
- **Stopping rule**: tier 1 empty for your scope, then stop. Tier 2 only when a person asks for
  it. Stop only at a unit boundary — every ref of the unit in hand judged.
- Quote the declaration's numbers verbatim when you report: the four band counts, tier 1
  disposed / not disposed, the tier 2 group count, and the named gaps. Do not re-derive them.
- The `controllable` source branch (a value-store key a web form writes) is NOT exercised by the
  reference truth set this profile was measured against — two of the three corpora hold no such
  candidate at all. It is in the predicate because dropping it would lose that whole family of
  leads, not because it has been validated end to end.

## Running the whole thing

One image's must-read set is far larger than one agent context, so a person drives it:

```
tmap review scan <run_id>                                  # the declaration, read-only
tmap review scan <run_id> --agent claude-code              # tier 1, one launch per unit
tmap review scan <run_id> --agent claude-code --until complete   # the second tier too
```

**Sharding.** `--worker <i> --workers <n>` splits the units by id, so `n` shells work disjoint
slices of the same run with no coordination. A reasonable starting value is **`--workers 4`** on a
machine with 8 or more cores — this is an EXPERIENCE value, not a measurement: the per-launch
throughput of this profile has not been measured, and the number should be replaced with a measured
one once it has. Each worker holds its own agent process and its own decompiler reads, so the
ceiling in practice is memory and disk, not CPU. Run one worker first and watch it before fanning
out.

The declaration says how many units are left and WHICH BINARIES the unread part sits in, never how
long it will take or how many sessions it needs: that would be the fact layer making a prediction it
has no basis for. If your context fills, stop at a unit boundary and say so.

**Working a shard** (`--worker i --workers n`): the declaration's band counts, its tail and its
second-tier group figures are the WHOLE RUN's — the keys `run_wide` names — while the tier counts
are your shard's. Quote them as what they are; the printed lines say `(whole run)` for you.
