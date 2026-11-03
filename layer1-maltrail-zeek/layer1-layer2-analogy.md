# A simple analogy — Layer 1 (and groundwork for designing Layer 2)

A note separate from `README.md` (which holds the technical/verification history). This file contains a
"plain language" analogy used to explain the notebook `layer1_experiment.ipynb`, kept separate so it can
easily be reused as a way of thinking when designing Layer 2.

Every analogy term is followed by its real technical term in parentheses, so it can be traced back to
the actual code/concept.

## The big picture

We have several **CCTV recordings of internet traffic** (pcaps) and want to test two "security guards"
with different styles, to see who catches what.

## Guard #1 — Maltrail: a gatekeeper with a blacklist book

It works like the gatekeeper of a housing complex who has a **book of names/addresses of known
criminals** (40 blacklist sources merged into one big book, `trails.csv`). He watches the CCTV
recordings, and whenever something matches his blacklist, he writes it in his report book (the `.log`
file).

- **The blacklist has 2 kinds of entries**: (a) "if you see THIS address/name, flag it immediately" —
  shown in the log as `(static)`; (b) "if you see a certain PATTERN" (e.g. downloading an `.exe` file
  directly, or a suspicious User-Agent name) — shown as `(heuristic)`, which requires him to "remember"
  several earlier events, not just match a single line.
- **The secret Tor door**: one of the blacklists is "exit doors of a secret tunnel" (Tor exit nodes) —
  not necessarily malicious, but often used by criminals to hide their identity, so flagged as
  "suspicious". The gatekeeper writes reports for this case in a different style (quoting several
  sources at once), which briefly confused our report-reading robot — fixed on 25 August 2026 (see
  README.md).

## Guard #2 — Zeek: a telephone operator who logs EVERY call

This guard has a completely different style: he is **NOT looking for criminals**. He is like an operator
who logs EVERY call — who called whom, for how long, how much "talking" — without judging whether the
content is malicious. The result is `conn.log`: a list of ALL network conversations, neutral, as they
are.

## The notebook flow, cell by cell

- **Environment check** — checking the bag before a picnic: are the required tools (Zeek, Python, etc.)
  on the laptop?
- **Section A (working folders)** — preparing empty cupboards: one for raw recordings, one for guard 1's
  reports, one for guard 2's reports, one for the final summary.
- **Section B (manifest & download)** — the shopping list of CCTV recordings: 3 KNOWN to contain criminals
  (Zeus, Tinba, Dridex — all "bank password thieves"), 2 safe ones (BitTorrent, Skype) as a comparison,
  plus an addition on 25 August (`iot23_capture1`, an IoT malware family). This cell actually downloads
  them and checks that the file sizes match.
- **Section C (guard #1 at work)** — C.1 install the guard, C.2 prepare his working rules
  (`maltrail.local.conf`), C.3 have him watch each recording and write reports, C.4 transcribe his
  handwriting into a neat table (the reading robot / regex).
- **Section D (guard #2 at work)** — D.1 run Zeek per recording, D.2 transcribe `conn.log` into a table
  as well.
- **Section E (summary)** — combine both guards' reports into one table: for each recording, how much
  guard 1 and guard 2 reported.
- **Section F (plan, not yet done)** — note: our "good" and "bad" recordings are currently separate (not
  recorded in the same complex at the same time). Ideally we would have ONE recording of a complex that
  contains a mix of good and bad at once (candidate: CTU-13) — to learn the difference more fairly.

## Groundwork for Layer 2 — using the same analogy

This is the most relevant part to keep. Guard #2 (Zeek) has already logged ALL conversations, but nobody
JUDGES yet which are normal and which are odd — he is only a clerk, not a judge. **Layer 2 is like
guard #3: someone who learns the residents' habits and becomes suspicious when a resident drastically
changes habits — even if their name is not in any blacklist.**

Some design decisions already discussed, translated into the same language (this is a SUMMARY of
existing project notes, not new decisions):

- **Not a gate, but input for judgement**: guard #3 is NOT used as "may pass / may not pass". Guard #1's
  (Maltrail's) report history is one of the INPUTS he weighs (a feature), not an absolute condition. This
  keeps guard #3 from automatically "catching suspicion" just because guard #1 flagged something in the
  past (the *cold-start contamination* resolution).
- **The focus is narrowed to "residents inside the complex" (insider threat)**: not recognising EVERYONE
  in the outside world (hard, the population is unbounded), but learning the habits of residents who are
  ALREADY KNOWN (one complex/campus/home) — a small, bounded population, so "learning their habits" is
  more realistic.
- **How to learn habits**: not observing once a month and drawing one big conclusion, but observing SHORT
  time windows (a few minutes) many times, and checking whether a resident's habits are STABLE from one
  time window to the next, or jump around. The residents whose habits suddenly jump are the suspicious
  ones — not residents whose habits are merely "different from everyone else's average".
- **Inputs being considered** (not final, not yet tested one by one): how much they "talk" compared with
  "listen" (bytes in/out ratio), how many different "phone numbers" they call (port entropy), how REGULAR
  their calls are (e.g. exactly every 30 seconds — a robot pattern, not a human — an indication of
  *beaconing*), how many different connections they open, the average length of each connection, and
  whether they mostly "call out" or "get called".

## Limits of this analogy — so it does not oversimplify

The analogy makes the story easier, but some things are LOST if we stop here — important to remember
when actually designing Layer 2:

- Guards #1 and #2 are programs in the real world, not people — they can log things wrongly because of
  bugs in the program itself, not just "seeing wrong". A real example: the number of guard #1's reports on
  the EXACT SAME Zeus recording turned out to differ between runs (16, 13, 13, 18) — not because the
  recording differed, but because the program silently used the process's wristwatch (wall clock) instead
  of the recording's own time, combined with the way it split work across 16 "assistants" at once. This is
  a separate investigation, fully documented in README.md and the project notes — the point here:
  **"guard reports" are not a stable absolute truth**, and must be handled carefully as a Layer 2 input
  feature, not just as "history" assumed to be correct.
- A "resident of the complex" is not necessarily one device = one person. The IoT-23 recording, for
  example, is full of one device contacting hundreds/thousands of different addresses (probably a botnet
  scanning pattern) — counted naively, this one "resident" can dominate the data unreasonably.
- Our recordings are currently separate (see section F) — so the "resident habits" that can be learned
  now are limited to each recording, not across time within the same complex. This is a population
  limitation that is recorded and not yet resolved (see the status in the project notes), not something
  this analogy pretends to solve.
