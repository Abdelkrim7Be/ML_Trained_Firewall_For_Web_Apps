# What end to end testing found

Part 1 evaluated the model against held out slices of its own corpus and reported
0.80 recall at a 0.1% false positive rate. Part 2 put the same model in front of a
web application and sent it the traffic a real site receives. The gap between
those two exercises is the most useful thing in this repository.

## The model keys on the word "users"

`/users/42/profile` is refused, with a score of **0.9996**.

That is not an attack. It is one of the most common URL shapes on the web, and
this firewall would block it.

The cause is visible by holding the payload fixed and changing one token:

| Request | Score | Verdict |
|---|---|---|
| `id=1' OR 1=1--` | 0.481 | allowed |
| `id=1' OR 1=1-- users` | 0.992 | refused |
| `id=1'; DROP TABLE accounts--` | 0.459 | allowed |
| `id=1'; DROP TABLE users--` | 0.938 | allowed, barely |
| `id=1' UNION SELECT password--` | 0.867 | allowed |
| `id=1' UNION SELECT password FROM users--` | 1.000 | refused |

And from the other direction, on paths with no payload at all:

| Path | Score |
|---|---|
| `/users/42/profile` | 0.9996 |
| `/user/42/profile` | 0.265 |
| `/accounts/42/profile` | 0.003 |
| `/api/users` | 0.550 |
| `/api/customers` | 0.000 |

The model has not learned what SQL injection looks like. It has substantially
learned that the token `users` means attack.

### Why the corpus could not show this

ECML/PKDD 2007 was sanitised before release: every URL, parameter name and
parameter value was replaced with a randomly generated string. Its attack payloads
were left intact, because mangling them would have destroyed the labels.

The result is a corpus where real English words appear almost exclusively inside
attacks. `users`, `password`, `select`, `admin` are attack vocabulary and nothing
else, because the benign half is `/lqlehaRus4/wREtSesTncl9tln/nI/u8ti8/`. A model
trained on it cannot learn otherwise, and no split of that corpus can reveal the
problem, because the held out benign traffic is randomised too.

This is what the part 1 numbers were pointing at without naming:

- 0.147 recall on CSIC 2010, a different corpus
- 0.209 recall on attack types held out of training
- corpus discrimination accuracy of 1.000, meaning the two corpora share almost no
  surface structure

Those were symptoms. This is the mechanism.

## Attacks that get through

Working SQL injections this model scores below its operating point:

| Payload | Score |
|---|---|
| `1' OR 1=1--` | 0.481 |
| `1' AND SLEEP(5)--` | 0.227 |
| `1' UNION SELECT password--` | 0.867 |
| `1'; DROP TABLE users--` | 0.938 |

`1' OR 1=1--` is the most widely known SQL injection payload there is, and it is
missed. Note the pattern: the misses are the payloads that do not happen to
mention a table name the corpus taught the model to recognise.

These are asserted in `tests/e2e/test_full_stack.py::test_known_misses_are_still_missed`
rather than left out of the suite, so a change in either direction is visible.

## What this does not undermine

The firewall itself behaves correctly. The end to end suite passes 57 checks
covering blocking, origin isolation, obfuscation handling, concurrency,
persistence across restart, graceful shutdown, structured logging, live streaming
and runtime control. Everything the proxy is responsible for works.

The normalisation chain in particular does its job. Every obfuscation of a payload
the model can recognise is still recognised: URL encoding, double encoding, inline
comments, case flipping and tab separation all normalise back to the same string.

The problem is upstream of all of it, in the data.

## What would fix it

Not a better model, and not more trees. The training data has to contain benign
traffic that looks like benign traffic: real paths, real parameter names, real
English words in requests that are not attacks. Concretely:

1. Generate traffic against a real application, taking benign requests from normal
   use and attack requests by injecting payloads from a curated list into the same
   request templates. Identical shape either side, so the only difference is the
   payload.
2. Hold out payloads rather than rows, so the model cannot memorise specific
   strings and be scored on them.
3. Re-run the same end to end suite. `/users/42/profile` passing is the acceptance
   criterion.

## Why the defaults are what they are

This finding is the argument for every conservative choice in the firewall:

- **Detect mode by default.** Enforcing this model on a real site on day one would
  refuse traffic to every URL containing `users`. Detect mode surfaces that in the
  review queue on the first afternoon and costs nothing.
- **The threshold is a control.** The operator can see, over their own traffic,
  what a different operating point would do before applying it.
- **Every decision is explainable.** The decode trace and the feature contributions
  are what make this diagnosable in minutes rather than never. The top contributor
  on `/users/42/profile` is the n-gram `users`, which says the whole story out loud.

A firewall that could not explain itself would have shipped this quietly.


---

# What the second round of end to end testing found

The first round tested whether the model's verdicts reach the origin correctly.
The second attacked the firewall itself, pushed protocol edge cases, and ran it
under sustained load.

## The control plane had no authentication

The proxy and the console share a port. That is a deliberate design choice, one
process and one thing to deploy, but it means every client of the protected
application could also reach `/_waf`. There was no token, so:

```
POST /_waf/mode {"mode": "detect"}     ->  200
GET  /item?id=1' UNION SELECT ...      ->  200   the firewall is now off
```

Disabling the firewall was a single unauthenticated request, which is a far
cheaper attack than evading the classifier. **Fixed.** Everything under `/_waf`
now requires a token except liveness and readiness, which orchestrators have to be
able to poll. `WAF_ADMIN_TOKEN` sets it; if it is unset one is generated at
startup and written to the log so a local run still works. The comparison is
constant time so a wrong token cannot be discovered a character at a time.

Asserted in `test_hardening.py::test_control_plane_rejects_unauthenticated_callers`
and `::test_disabling_the_firewall_requires_the_token`.

## Padding a query with junk parameters evades the model

The payload is untouched. Only the number of unrelated parameters around it
changes:

| Padding parameters | Score | Verdict |
|---|---|---|
| 0 | 1.000 | refused |
| 100 | 0.9997 | refused |
| 140 | 0.998 | refused |
| 200 | 0.928 | **allowed** |
| 400 | 0.892 | **allowed** |

The tipping point is around 150 parameters.

Padding with prose instead does not work. Five thousand characters of filler
leaves the score at 1.000. That contrast identifies the mechanism: each new
parameter name contributes fresh character n-grams, and the vectoriser's
normalisation spreads the document's weight across all of them, so the attack's
own n-grams lose relative weight. Repeated text adds length without adding
distinct n-grams.

The fix is not a threshold change. It is to score each parameter value on its own
as well as the request as a whole, and take the maximum, so a payload cannot be
diluted by things sitting next to it. That is a model serving change and is not
implemented here.

Asserted in `test_hardening.py::test_heavy_parameter_padding_evades_this_model`.

## Scoring was blocking the event loop

`engine.decide` is synchronous CPU work and was being called directly from the
async request handler, so every request froze the event loop for the duration of
scoring. Concurrent traffic queued behind it. **Fixed** by moving it to a worker
thread, which genuinely overlaps because numpy and LightGBM release the GIL for
the expensive parts.

## Throughput ceiling: roughly 80 requests per second per process

Measured with connection reuse against a warmed instance:

| Concurrent clients | Throughput | p50 | p99 |
|---|---|---|---|
| 1 | 65 rps | 15 ms | 20 ms |
| 4 | 81 rps | 49 ms | 61 ms |
| 12 | 83 rps | 131 ms | 1231 ms |
| 24 | 57 rps | 188 ms | 2192 ms |

Throughput is flat past four concurrent clients and latency degrades sharply
after that, which is the GIL: scoring is Python and Cython heavy and does not
parallelise across threads within one process.

Server side scoring stays around 8 ms throughout. The gap between that and the
end to end latency at high concurrency is queueing, not the model.

**What this means for deployment.** One process serves roughly 80 requests per
second. Past that, run several behind a load balancer; SQLite in WAL mode tolerates
multiple writers. The catch is that the console's live stream and the decision
cache are per process, so each console would see only the traffic its own worker
handled. Fixing that properly means moving the event bus and the cache out of
process, which is beyond what this project is demonstrating.

These numbers were measured on a machine with a load average around 20 from
unrelated work, so treat them as a floor.

## A note on how the first attempt at this suite was wrong

The load tests originally created a new HTTP client for every request. That
measures TCP and TLS setup rather than the firewall, capped throughput at about a
fifth of the real figure, and produced read timeouts that looked like a server
defect. The fixture now shares a pooled client. It is worth recording because the
failure mode was convincing: a benchmark that is wrong in this direction makes a
healthy system look broken, and the temptation is to go and optimise the wrong
thing.
