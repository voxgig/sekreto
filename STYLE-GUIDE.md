# Documentation style guide

How the Voxgig Sekreto documentation is written. This guide is normative
for the root [`README.md`](./README.md) and [`DOCS.md`](./DOCS.md) and
for every port's `README.md` — 25 pages, the ones a reader lands on from
GitHub, npm, pkg.go.dev, PyPI and the rest. It exists so that a page
written next year sounds like a page written this year, and so that a
reviewer can point at a rule instead of arguing taste.

It is a port of [jostraca/jostraca](https://github.com/jostraca/jostraca)'s
guide, by way of [voxgig/struct](https://github.com/voxgig/struct)'s,
which share an author and a house voice with this project. The structure
and most of the rules are those projects'. Where this one differs — the
spaced em dash, the working-document set, the shape of the four parts —
the difference is recorded with the measurement behind it, because a
divergence nobody wrote down reads later as drift.

Three sources feed the guide, in a fixed priority order. The same order is
encoded in [`.vale.ini`](./.vale.ini), and every rule switched off there
names the reason and the count it produced:

    house voice  ->  Google  ->  Vale defaults

1. **This file.** Where it rules, it rules. The house voice is Richard
   Rodger's blog register, and the places it wins are listed with their
   reasons rather than left as silent exceptions: the spaced em dash,
   first-person plural in tutorials, British spellings, and quotation
   punctuation outside the quotes.
2. The [Google developer documentation style
   guide](https://developers.google.com/style) for everything this file
   does not cover: second person, present tense, active voice,
   sentence-style capitalisation in headings, serial commas, one idea per
   sentence.
3. [Vale](https://vale.sh) defaults, which mostly means spelling.

Two gates check it, and both run in CI:

| Gate | Runs | Checks |
|---|---|---|
| `vale --minAlertLevel=error $(python3 tools/check_prose.py --files)` | `make scan-prose`, `.github/workflows/docs.yml` | Google's rules plus the banned list, at the levels set in `.vale.ini` |
| `python3 tools/check_prose.py` | `make scan-prose`, `make test`, and the same workflow | the banned list, the em-dash spacing and ration, the first-person rules, no emoji, no citations of a working document, that every relative link resolves, and that the page set is complete |

The banned list is read from one file by both, so they cannot drift. The
page set comes from one function, `tools/check_prose.py --files`, for the
same reason: a gate reading a smaller set than the other is a gate that
reports green on a page nobody checked.

A Google rule sitting at `warning` rather than `error` was tried at error
level first and found wrong for these pages; `.vale.ini` records what it
produced and why it was demoted.

## The structure: four parts, as sections rather than files

The documentation is a four-part guide — a tutorial, how-to recipes, a
reference, and an explanation — but this project has 23 ports and one
`DOCS.md`, so the parts are **sections spread over three kinds of page**
rather than four files, and the rules attach to the section:

| Part | Where | May | May not |
|---|---|---|---|
| Tutorial | the quick start at the top of `README.md`, before `## Built in, or a plugin`; there is no numbered tutorial section yet | teach step by step, show output for every step, defer detail with a link | argue design, list every kind, assume the reader's goal |
| How-to | `README.md` `## Providers` and `## Testing`; a port's `## Use` and `## Testing` | solve one named task, assume competence, link the reference | teach basics, explain design, drift into a second task |
| Reference | `DOCS.md`, from `## Names` to `## The shared spec`; a port's `## API` and `## Layout` tables | state facts exhaustively and dryly, pin claims to spec groups and tests | narrate, persuade, teach |
| Explanation | `README.md` `## Built in, or a plugin` and `## Secret names`; a port's `## Notes` or `## Notes on the translation` | argue, compare, admit trade-offs, tell the design's story | be the only place a fact lives |

`README.md` is the doorway as well as the home of two of those parts: it
routes, gives the quick start, and states no fact of its own that
`DOCS.md` does not also state.

One fact appears in all four parts at different altitudes — met in the
tutorial, used in a how-to, specified in the reference, argued in the
explanation — but the normative statement lives in `DOCS.md` and
everything else links to it.

**Documentation never names the framework.** The four parts come from
`Diátaxis`, and that is a fact about how these pages were planned, not
one a reader needs in order to read them. Say **tutorial**, **how-to**,
**reference** and **explanation**, which are ordinary words that describe
themselves, and let the structure do the explaining. This guide and the
contributor guides are where the name belongs, because there it answers a
question somebody is actually asking.

### The canonical page owns the behaviour

This project has a second axis upstream does not: 23 ports of one
library. The rule that falls out of it is the documentation half of the
rule the code already follows.

**Behaviour is documented once, in `DOCS.md`.** A port's `README.md`
documents that port: its spelling of the API (the `## API` table), its
build and its toolchain, its layout, how its tests run, and any place it
diverges. A port page that re-explains what `getfrom` does, or which
`kv` version `hashicorp` assumes, has taken on a copy of a fact that
goes stale the day the canonical changes, and there are 22 other copies
of it that will not be updated in the same commit.

**A divergence is stated where it happens, and pointed at the record.**
The record is the spec (`spec/def/*.aon`, and the fourteen groups
`DOCS.md` lists under `## The shared spec`) and the port's own tests. A
port page names the divergence, says what this port does, and names the
spec group or the test that pins it. The design notes under `doc/` and
`docs/` are where a divergence was argued, and they are not citable —
see the next section.

## Documentation does not cite a working document

**A documentation page never sends a reader to a plan, a review, a
design argument, or an agent instruction file.** Those are working
documents: written for the people changing this repository, argued rather
than stated, and stale the moment the code moves past them. A reader who
follows a link out of the documentation and lands in one has been handed
the project's notes in place of an answer.

The banned set, by name:

| Document | What it is |
|---|---|
| `AGENTS.md`, `CLAUDE.md` | instructions to contributors and agents working in the repository (there is no `CLAUDE.md` yet; the name is guarded in advance) |
| `doc/design/more-ports.md` | the plan that brought the port count to twenty-three, with what it predicted and what it did not |
| `doc/design/real-stores.md` | the argument for testing against the real stores, and the log of what that suite found |
| `doc/design/review-2026-08.md` | a code review, findings numbered `SK-1` onward, revised as they are fixed |
| `docs/design/plugin-providers.md` | the plan for moving the provider kinds onto voxgig/plugin, with a status line and a propagation order |
| any `*_PLAN.md` or `*_REVIEW.md`, and `BUILD_LOG.md` | the shapes this project has not needed yet, guarded in advance |

The ban covers the name as much as the link. "The full checklist is in
`AGENTS.md`" fails for the same reason the URL does: the reader still
cannot act on the sentence without leaving the documentation.

State the fact instead. "The core imports no plugin in any form, and a
`Sekreto` can build only the kinds its constructor was handed" is what a
reader needs, and a link to the plan that also says so adds nothing to
it. Where the fact belongs in the documentation and is missing, write it
into the section that owns it rather than pointing outside.

The rule runs one way. Working documents cite each other and cite the
documentation freely, because a design note that does not show its
working is not a design note. Only the direction out of documentation is
closed.

### What stays linkable, and why

| Linkable | Because |
|---|---|
| source, tests, and the spec: `spec/sekreto.aon`, `spec/def/*.aon`, the generated `spec/sekreto.json`, `test/integration.sh`, `test/realstores.sh`, `test/checks.sh` | code is the thing a claim is pinned to, and the spec is the contract every port runs |
| this guide | normative rather than exploratory, and it names the working documents in order to ban them |
| the other READMEs and `DOCS.md` | documentation themselves |

The rule behind the split: **a specification is citable, an argument is
not.** A reader sent to `spec/def/` gets a case they can run. A reader
sent to `review-2026-08.md` gets somebody's findings, mid-fix.

`tools/check_prose.py` enforces this over the 25 reader-facing pages.
Vale does not, because Vale cannot tell a working document from a page.

## The voice

The house voice is Richard Rodger's blog register, adapted per section.
The portable part of that voice is its *rhythm*, not its stock phrases.
Ten habits, with the register they apply in:

1. **Open with a concrete fact or a plainly stated problem, then a short
   dry beat.** Tutorial and how-to sections. Reference sections open by
   stating what the thing is.
2. **Introduce code with a short colon-terminated sentence** — "Two
   suites, and both matter:", "The whole module graph, for every binary
   the Makefile builds:". Never "The following code snippet
   demonstrates". Everywhere.
3. **After a code block, point at the one interesting thing.** Do not
   recap the code. Everywhere.
4. **Parentheses carry definitions, caveats, and at most one dry aside per
   section.** Tutorial and how-to sections. In reference sections,
   parentheses carry facts only — a type, a default, a spec group.
5. **A trade-off gets bolted on with a dash, and the dash earns its
   place.** One per paragraph at most, never two in a sentence. The gate
   enforces the one-aside-per-line half of that; the paragraph half is
   a review matter.
6. **Alternate one long explanatory sentence with one short verdict
   sentence.** The short sentence is the payoff. Everywhere.
7. **Talk to the reader as "you", and route them** ("If you only want
   the Go spelling, skip to…"). "We" appears only in a tutorial, walking
   through code together, and there is no tutorial section yet, so it
   appears nowhere. "I" appears nowhere.
8. **Show that the code is real.** Nothing executes the listings on
   these pages, so a listing is a claim, and a claim's home is the spec:
   a sentence that says what a call returns names the spec group that
   pins it (`resolve`, `getfrom`, `sigv4`, and the rest of the fourteen
   under `## The shared spec`), and a sentence that says a port can reach
   a store names the `test/integration.sh` or `test/realstores.sh` check
   that proves it. A claim with neither is reviewed by hand and said so.
9. **Jokes are self-directed or about the industry's mundanity, and the
   register goes fully serious the moment correctness or a user's data is
   on the table.** Never joke about the reader, another language, another
   port, or a secret that reached the wrong store.
10. **Close by handing the reader something**: a link, a next step, one
    sentence. No summary paragraphs that restate the page.

Exclamation marks: at most one per page, in a tutorial section only, on a
genuine payoff.

## Banned phrases and patterns

These read as generated filler. Do not use them, in any document,
including commit messages that quote the docs.

**The list itself lives in
[`.vale/styles/config/vocabularies/Sekreto/reject.txt`](./.vale/styles/config/vocabularies/Sekreto/reject.txt)**,
one regular expression per line. That file is the single source of truth:
Vale reads it in CI, and `tools/check_prose.py` reads the same file rather
than keeping a second copy, so the two gates cannot disagree about what is
banned. Add a phrase there and both pick it up. What follows is a reader's
summary of it, not a second list; every phrase is shown as code so that
quoting a banned phrase in this guide does not fail the gate.

The list is upstream's, unchanged, and it draws on two sources: that
project's original house list, and [claudisms.ai](https://claudisms.ai/),
a catalogue of the patterns that mark machine-written prose. **It was
measured against these pages before it was adopted.** Two entries fired,
four times: `quietly` three times (`DOCS.md`, `README.md`, and the OCaml
page, each describing a failure that reports nothing, which is what
`silently` is for) and `load-bearing` once (the Dart page, about the
`FutureOr` distinction). All four were rewritten, and nothing was dropped
from the list to make it pass.

**Filler and false emphasis**: `worth noting` · `important to note` ·
`it cannot be overstated` · `at its core` · `when it comes to` ·
`let's break it down` · `here's where it gets interesting` ·
`the point is` · `because it matters`.

**Inflated vocabulary**: `delve` · `dive into` · `robust` · `seamless` ·
`comprehensive` · `holistic` · `intricate` · `leverage` · `foster` ·
`shed light on` · `pave the way` · `pivotal` · `transformative` ·
`game-changing` · `cutting-edge` · `groundbreaking` · `testament to` ·
`paradigm shift` · `realm` · `landscape of` · `underscores the` ·
`lean into` · `throughline` · `double-click on` · `mature setup`.

**Consultant register**: `north star` · `key takeaways` ·
`best practices` (name the practice instead) · `at the end of the day` ·
`pressure-test` · `right-size` · `strategic imperative` ·
`three things to know` · `dispatches from` · `best operators` ·
`lessons learned`.

**Metaphor inflation**: `load-bearing` · `heavy lifting` ·
`is doing the work` · `different physics` · `hits hardest` ·
`quietly` (say `silently`, which is the term of art for a failure that
reports nothing).

**The contrast frame and its cousins**: `not just` · `not only X but Y` ·
`it's not about` · `the whole game` · `the entire point` ·
`the only thing that matters`. Say what the thing is.

**False singularity**: `the right way/answer/tool/question` ·
`the best thing you can do` · `if I had to pick` · `what struck me` ·
`stuck with me` · `struck a chord` · `hit a nerve` ·
`we've seen this movie before`.

**Reflective pose**: `sit with` · `worth exploring/considering/asking` ·
`keeps coming back to` · `that's the tell` · `where I landed`.

**Invented observation about people**: `most people` ·
`everyone I've worked with` · `a lot of folks` · `nobody I know`. If it
did not happen, do not claim to have noticed it.

**Signposting**: `let's explore` · `now let's turn to` · `moving on to` ·
`in today's rapidly evolving` · `reflecting a broader trend` ·
`great question`.

**`honest`, and every form of it**, is banned differently from the rest.
The word is fine English; it is on the list because it had become a tic
across the repositories that share this list, where it flattered a
sentence rather than said anything the sentence did not already say. It
had not reached these pages when the list arrived.

**The gate is absolute, and the lack of an inline exemption is the
point.** There is no `allow` comment and no suppression the second gate
would honour, because an escape hatch that exists is an escape hatch that
gets used. A use the author wants kept is approved by changing
`reject.txt`: one line, in one file, visible in review, which is where an
approval belongs.

### What is not banned, and why

Several entries on claudisms.ai are deliberately absent, because they name
things this project documents. A gate that fires on the subject matter is
a gate people learn to switch off. The same standard governs
`Sekreto.WordChoice`, which carries three of Google's substitutions and
leaves the rest at warning.

| Not banned | Because |
|---|---|
| `canonical` | It is this project's word for the TypeScript source every port is a port of. |
| `real` | `the real stores`, `a real boru vault`, `a real Vault` are the distinction the whole testing story turns on: a mock is a claim, a real server is the thing. |
| `silently` | The term of art for the failure mode the library is built to avoid — a chain falling through to a weaker store without saying so. It is what `quietly` is rewritten to. |
| `shape` | The spec's format is a *shape* omni unifies every entry with, and `describe()` has one; it is the domain's own word. |
| `hold`, `carry`, `hands` | A store holds a secret, a port carries its own JSON parser, the constructor is handed the plugins it may build. |
| `lives` | `the normative statement lives in DOCS.md` is this guide, one section up. |

The rule behind the list: ban the phrase that adds nothing, never the word
that names a thing.

**Matching spans a line wrap.** These pages hard-wrap, and most of the
list is multi-word, so the gate joins each paragraph before matching:
`worth\nnoting` fails exactly as `worth noting` does. Upstream records
that the day its gate started reading paragraphs it found two phrases that
had been passing since the gate was written, each saved only by where its
line happened to break.

**Patterns** (not mechanically checkable, enforced at review):

- Announcing structure before delivering it ("There are three things to
  understand").
- Restating the question before answering it.
- A closing one-liner that restates the thesis.
- Stacked short declaratives (four or more in a row).
- Superlative self-ranking ("the most important thing", "the part that
  matters most").
- A list of `**Bold term**: explanation` pairs, which is the single most
  recognisable machine-written list. Write sentences, or a table.

## Punctuation rulings

**The em dash is spaced here**: `a dash — like this`. This is the one
place where the guide contradicts both Google and jostraca, and it is the
Voxgig convention rather than drift — 327 spaced dashes across the 25
pages when the gate was written, and not one unspaced. Rewriting 327
dashes to satisfy a rule the prose has never once broken would be the
tail wagging the dog. `Google.EmDash` is therefore off, and
`tools/check_prose.py` `em-dashes-are-spaced` enforces the convention in
the other direction: an unspaced dash fails.

Dashes stay **rationed to one aside per line**: either a single dash
before a trailing clause, or one matched pair around a parenthetical,
never both and never two asides. Three on a line is the stacking the
ration exists to stop. Prefer a comma or parentheses when the aside is
mild. A heading such as `hashicorp — HashiCorp Vault — plugin hashicorp`
is a table row written as a heading, not an aside, and the ration does
not apply to it.

The rest:

- In a link list, separate the link from its gloss with a full stop, not a
  dash:

  ```markdown
  - [DOCS.md](DOCS.md). The full API, provider by provider.
  ```

- **Every relative link must resolve, and stay inside the repository.**
  `tools/check_prose.py` checks the path, not the anchor, since a heading
  slug depends on the renderer; it reads both `[text](target)` and
  `[text][label]` with its definition. A target that resolves on a Linux
  runner but climbs out of the checkout resolves nowhere on GitHub or in a
  published package, so it fails too. The check found no dead link the
  day it was written. What it did find was four citations of working
  documents — three in the root `README.md`, one on the Lean page — and
  50 check-mark emoji cells in the two port tables, all rewritten.
- No emoji in documentation. A table cell that used to hold a check mark
  says `yes`.
- Sentence-style capitalisation in headings (Google style), except where
  the heading names a proper noun or a code identifier: `HashiCorp Vault`,
  `` `env` — built in ``.
- British spellings (`-ise`, `-isation`) for new prose. Google style is US
  English and so is the dictionary; this is one of the places the house
  voice wins, and
  [`accept.txt`](./.vale/styles/config/vocabularies/Sekreto/accept.txt)
  carries the British forms — **listed one by one**, never matched by
  suffix, because `\w+ise` accepts any word ending in those three letters
  and punches a hole straight through the spelling gate. A US spelling
  already on a page is not a defect, and a filename keeps whatever
  spelling it was created with.
- Quotation punctuation goes **outside** the quotes, against US
  convention, because putting a period inside a quoted `code span` is
  actively wrong when the quote is a literal.
- A number and its unit are separated: `10 seconds`, `404 responses`,
  never `10s` or `404s`. `Google.Units` is at error level, and the seven
  hits it produced were all on the Zig page's timing measurements and one
  `404s` in `DOCS.md`.

## Terminology

- The project is **sekreto**, lowercase, as the pages and the package
  names write it; **Voxgig Sekreto** is its formal name. The packages are
  `@voxgig/sekreto`, `@voxgig/sekreto-js`, `voxgig_sekreto`,
  `github.com/voxgig/sekreto/go` and their per-ecosystem spellings.
  Capitalised `Sekreto` is the class, and only the class.
- **canonical** — the TypeScript source in `typescript/src/` and
  `typescript/plugins/`. Every other language is a **port** of it. Never
  "reference implementation"; the spec is the reference.
- **the spec** — `spec/sekreto.aon` and the case files under `spec/def/`,
  compiled to `spec/sekreto.json`. It is the **contract**: a port that
  disagrees with it is wrong. A **spec group** is one of its fourteen
  named sets; an entry within one is a **case**. Never "the test suite",
  which is a port's own runner, and never "the corpus", which is struct's
  word for its own contract.
- **a secret** is a value with a **secret name** — dot-separated
  `[a-z0-9_]+` segments, `api.token`. Never "key", which is what a store
  calls its side of the mapping (`envkey`, `awsparam`).
- **kind**, **provider**, **store** are three altitudes, not synonyms. A
  **kind** is a type of source (`env`, `hashicorp`). A **provider** is the
  code that reads one kind. A **store** is a configured provider in a
  chain, addressed by name (`hashicorp`, `prod`), and it is what `getfrom`
  and `stores()` name. Say **store** when the reader is choosing where a
  secret comes from.
- **built in** and **plugin** — four kinds are built in (`env`, `memory`,
  `dotenv`, `file`: they read at most a local file); the other ten are
  plugin kinds, voxgig/plugin definitions under `plugins/` that a
  `Sekreto` can build only if its constructor was handed them. Never
  "core provider" for a plugin kind.
- **transparent** and **directed** — `get` and `try` ask the chain and
  the caller never learns which store answered; `getfrom` and `tryfrom`
  ask one named store. Adding a method to one half means adding its twin
  to the other.
- **a miss** and **a failure** are different, and the difference is the
  library's hardest edge. A miss is "this store does not hold it" and the
  chain carries on; a failure is "this store could not answer" and it
  raises. Never "error" for a miss.
- **boru**, **omni**, **aontu**, **secretspec** stay lowercase in prose,
  as their projects write them; **SecretSpec** capitalised is the
  program, `secretspec` is the kind that reads it. **Infisical**,
  **HashiCorp Vault**, **LocalStack** keep their vendors' casing.
- **the real stores** — HashiCorp Vault, LocalStack, self-hosted
  Infisical, a Key Vault emulator and a real boru, in containers, which
  `test/realstores.sh` runs against. Everything `test/integration.sh`
  stands up is a **mock**, and a mock is a claim about the real thing.
- **omni isolation** — the property `tools/omni_isolation.py` proves: no
  shipped manifest names voxgig/omni, because only the tests depend on
  it. **parity** is the property the spec proves: the same answers from
  every port. Not "consistency".

## Templates, part by part

**Tutorial section**: goal sentence → snippet → output → the one
observation → forward link. Every step's output shown.

**How-to section**: the task as a heading in imperative or "-ing" form;
one sentence of situation; the recipe; one paragraph of what to watch for;
links to the reference for the constructs.

**Reference section** (`DOCS.md`, and a port's `## API`): definition,
then behaviour, then edge cases, then a pinned example. Every claim that
has a spec group names it.

**Explanation section** (a port's `## Notes`): the question, the answer,
the argument, the trade-off admitted. May quote history when the history
is the argument. In a port's pages this is where a divergence is
explained, and it names the spec group or the test that pins what this
port does.

## Updating this guide

Change it the way behaviour changes: in the same commit as the first page
that follows the new rule, with the reasoning in the commit message.

To ban a phrase, add the regular expression to
[`reject.txt`](./.vale/styles/config/vocabularies/Sekreto/reject.txt)
and summarise it in the preceding list. Both gates pick it up from that
one file; there is no second list to update, and `tools/check_prose.py`
names this file, so a drift is a build failure with a pointer.

To change a Google rule's level, edit [`.vale.ini`](./.vale.ini) and write
down what the rule produced on a clean run. "It was noisy" is not a
reason; "it wants `CLI` spelled out as `command-line tool`, on pages
about command-line tools whose own documentation calls them a CLI — 58
hits" is. A rule demoted without that note reads later as an oversight,
and gets re-promoted by someone repeating the work.

To widen what the gates read, change the configuration block at the top
of `tools/check_prose.py`. Both gates take their file set from it, so
widening it once widens both — and a page added to the repository without
being added there is a page neither gate has ever read.
