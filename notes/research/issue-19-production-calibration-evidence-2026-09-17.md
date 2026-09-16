# Issue #19 production-path calibration — 2026-09-17

Status: completed failed performance checkpoint; issue #19 remains open.

This is sanitized evidence. It contains no candidate value or key, credential, authority, receipt,
challenge description, raw model text, tool payload, or private host path.

## Registration and protocol

The exact protocol was registered in issue comment
[`#issuecomment-5700906522`](https://github.com/jerome-queck/incypher-rapido/issues/19#issuecomment-5700906522)
before fresh state creation. It used source `87712b886069cc1545febe04c38b2a1ca001493c`
and ARM64 image
`rapido@sha256:c932e2a80eb209a93eca42afec3b3b7b7d81f66fe495d8042e9848749799fd62`.

The executed registration set an 800-second outer ceiling and retained 1,800-second lane budgets.
After the run, the owner clarified that this inverted the intended calibration values: the outer run
should have been 1,800 seconds and each agent lane 800 seconds. This run is therefore diagnostic,
not the requested production-performance calibration. The exact roster was five active challenges,
four peers per challenge, a configured P20 cap, one Daybreak/xhigh Lead and Luna max/xhigh/max
Specialists, typed same-run memory, two episodes, dynamic concurrency one, submissions and managed
instances enabled, no fallback, and container limits of 8 CPUs, 24 GiB RAM, and 256 PIDs.

The numeric performance checkpoint was at least 3/5 current-run candidate-validating solves from the
normal first wave. Cumulative issue acceptance remained at least four autonomous solves including
the existing three, with at least one new HTTP-200 `correct`. No threshold changes after this run.

## Result

The run ID was `0bf65d4d8c774bd9adc10d91726ccc1e`. It ended `deadline` after 803.514
seconds, including cleanup, without operator steering, fallback, or manual candidate handling.

- The durable controller admitted 60 initial jobs: 15 Daybreak/xhigh Leads, 15 Luna/xhigh
  Specialists, and 30 Luna/max Specialists. It marked 20 started: five Leads, five Luna/xhigh, and
  ten Luna/max.
- Actual model execution reached only four lanes on one dynamic challenge: one Daybreak/xhigh Lead,
  two Luna/max Specialists, and one Luna/xhigh Specialist. Three completed with candidate proposals;
  one was cancelled by the outer deadline.
- The three retained proposals represented one private identity. Their completed lanes committed all
  166 tool observations with none omitted; 161 observations were marked source-bound and five were
  not. The cancelled manifest contained no partial observation.
- No Verifier episode started. Candidate verifications, submission intents, and submissions were all
  zero. Consequently the run scored 0 current-run solves and failed the registered 3/5 checkpoint.
- Typed memory projected four times without rejection, but every projection contained zero records.
  No follow-on episode existed to consume the completed peer work.
- One instance create/ready/cleanup cycle completed and its durable instance row ended `removed`.
  Fifty-six jobs closed `interrupted`; the executed fourth lane closed `cancelled`; three jobs closed
  `candidate`. No job or effect remained pending. However, all 15 global challenge rows incorrectly
  remained `queued`, and the deadline path emitted no partial per-challenge outcome.

## Diagnosed constraints

The five-challenge configuration did not produce five simultaneously executing challenges. The
catalogue is dynamic-first. Five workers each claimed a dynamic challenge and marked its four jobs
started before acquiring a one-slot dynamic semaphore. Four challenge workers then waited while
holding active slots; only the semaphore holder created four model attempts. This is a scheduler
occupancy defect, not a model, quota, RAM, or tool-capacity result.

Two separate barriers prevented submission. The controller waited for the whole peer group before
routing, and the adaptive submit path had no producer-candidate branch: it selected only an already
verified candidate before it examined Board attempt limits. The Board challenge contract exposes
per-challenge attempt limits, so unlimited and limited challenges should not share that delay policy.

Additional solve-throughput findings were:

- the first private candidate completed at 152.224 seconds and the same identity reached two-agent
  agreement at 466.369 seconds, but no lane-completion action existed;
- one Luna/xhigh lane ran 778.449 seconds with zero tools, with no progress watchdog or replacement;
- the shared instance remained ready for 781.945 seconds, including 337.138 seconds after agreement;
- producer-to-Verifier and Recovery routes always allocate four lanes, although one independent
  Verifier is sufficient for a producer candidate;
- ordinary stalled/unsolved work has no typed Recovery route, so producer memory is structurally
  unavailable unless a narrow existing failure route dispatches a successor; and
- Board qualification used 37 serialized GETs and delayed queue start by 16.512 seconds.

Operator-observed samples peaked at 125.8 MiB RAM, 74 PIDs, and 10.74% Docker CPU. These samples are
not evidence of productive P20 saturation because only four model attempts actually launched. No
OOM, quota, rate-limit, or overload failure was observed.

## Lifecycle audit

SQLite integrity was `ok` with zero foreign-key violations. The exact run workspace had zero bytes
after exit, the container was absent, and separate supervisor authentication remained present.
An independent Daybreak/xhigh audit performed two authenticated post-run GET-only rounds. Both
returned coherent HTTP 404/inactive responses for all nine dynamic challenges, with no endpoint or
timestamps and zero writes. It confirmed the roster, effects, evidence, memory, database, workspace,
and container facts above; no fallback occurred.

## Decisions before another performance run

1. Measure the Board's safe concurrent dynamic-instance boundary with a bounded create/check/delete
   ladder. Each dynamic challenge owns exactly one just-in-time instance shared by all its agents;
   never retain idle instances.
2. Add one unified instance manager. Let every challenge start local/static analysis immediately.
   A dynamic challenge acquires one just-in-time shared instance only for its live phase; challenges
   without a lease retain local progress, and instance completion or `correct` immediately releases
   capacity. Preserve durable episode and enqueue order.
3. On challenges with no Board attempt limit, immediately submit each source/provenance-qualified
   candidate without waiting for peers or Verifiers. Continue private retention and independent
   verification for evidence. On limited-attempt challenges, retain verification and remaining-attempt
   protection.
4. Feed completed local/static findings into the instance-enabled follow-on agents as typed same-run
   memory. Ensure a hard challenge can also start a bounded Recovery episode; measure actual nonzero
   records and contribution.
5. Add a bounded no-progress watchdog, truthful attempt/job state, immediate sibling cancellation on
   `correct`, early instance release, and role-specific successor lane counts (one Verifier; bounded
   Recovery fan-out).
6. Re-run the requested checkpoint after focused verification with a 1,800-second outer run and
   800-second agent lanes. Do not start the 19,800-second acceptance run without owner authorization.

Original issue #19 completion still requires a separately registered fresh unattended 19,800-second
all-15 run, at least one new HTTP-200 `correct`, cumulative autonomous solves of at least four, proof
that a new mechanism contributed, durable sanitized evidence, exact-state deletion, and honest close.
