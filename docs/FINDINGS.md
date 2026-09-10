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


---

# Measured against a million real requests

Everything above used either the training corpus or payloads chosen by hand. This
section uses neither. `mlwaf.waf.benchmark` scores the model against the
[NASA Kennedy Space Center HTTP trace](https://ita.ee.lbl.gov/html/contrib/NASA-HTTP.html),
two months of requests to a real public web server in 1995, and against community
maintained attack payload lists including libinjection's bypass corpus. Neither
was involved in training, and neither was assembled by anyone with an interest in
this model looking good.

## False positive rate on real traffic: 1.60%

21,167 distinct requests from the trace. **339 were refused.**

Part 1 reported a false positive rate of 0.1%, chosen deliberately against a
budget. On real traffic it is **sixteen times worse**.

At 1.6%, roughly one legitimate request in sixty is blocked. On a site serving a
million requests a day that is sixteen thousand refusals, every day, none of them
attacks.

The requests it refuses are not unusual:

```
0.9995  GET /shuttle/missions/sts-78/news/
0.9995  GET /shuttle/missions/sts-77/news/
0.9995  GET /shuttle/missions/sts-76/news/
0.9995  GET /shuttle/missions/sts-69/test/
```

## The cause, stated plainly

Counting which words appear in the refused requests answers it immediately:

| Token | Appearances among refused requests |
|---|---|
| shuttle | 336 |
| missions | 326 |
| sts | 287 |
| images | 87 |
| movies | 68 |
| sounds | 59 |
| news | 55 |
| docs | 39 |

None of these has anything to do with SQL injection. They are simply the words
that appear in the URLs of a website about space shuttles.

The earlier finding about the token `users` was not a quirk. It was one instance
of the general case: **this model treats an ordinary English word in a URL as
evidence of an attack.** ECML/PKDD's benign requests were sanitised into random
strings like `/lqlehaRus4/wREtSesTncl9tln/`, so during training the only place a
real word ever appeared was inside an attack payload. The model learned exactly
what it was shown.

No amount of held out corpus evaluation could have found this, because the held
out benign traffic is randomised too. It took traffic from outside the corpus, and
the cheapest possible source of it was a thirty year old public trace.

## Recall on outside payloads

| Payload family | Recall | Source |
|---|---|---|
| SQL injection | **0.784** | 759 payloads, including libinjection's bypass corpus |
| XSS | **0.826** | 1,936 payloads |

Recall holds up better than the false positive rate, and lands close to the 0.80
measured on the corpus. That is the shape of the problem: the model is reasonable
at recognising attacks and very bad at recognising that ordinary traffic is not
one.

Some misses are instructive. `" or "" "` scores 0.944, just under the line.
Several XSS payloads that avoid conventional syntax entirely, such as
`$=document,$=$.URL,$$=unescape,$$$=eval,$$$($$($))`, score near zero.

## What this changes

Nothing about the firewall, which behaves correctly throughout. It changes what
can honestly be claimed about the model:

- On traffic resembling its training corpus: 0.80 recall at 0.1% false positives.
- On real traffic: 0.78 to 0.83 recall at **1.6%** false positives.

The second pair is the one that matters, and it is not a deployable operating
point. The fix is the one named earlier and it has not changed: the training data
needs benign traffic that looks like benign traffic. A model cannot learn that
`/shuttle/missions/` is ordinary if it has never seen an ordinary URL.

Reproduce with `make benchmark`.


---

# Fixing it: a corpus where benign traffic looks benign

The diagnosis said the training data was the problem, so the data was rebuilt.
`mlwaf.synth` takes real paths from four public web server traces, roughly five
million requests, and builds both classes on top of them:

    benign   GET /shuttle/missions/sts-78/news/?qt=hubble
    sqli     GET /shuttle/missions/news/1992/h02.13.92?utm_source=1' OR 1=1--

The same paths carry both labels, so `shuttle` appears as often in an attack as in
ordinary traffic and carries no signal. The only thing separating the classes is
the payload, which is the thing the model is supposed to learn.

Two holdouts, not one. Paths are partitioned across train, validation and test, and
so are payloads, so an attack in the test split is built from a URL the model has
never seen carrying a payload it has never seen.

## The result

Same benchmark, same NASA trace, same 2,695 community payloads.

| | Trained on ECML | Trained on real traces |
|---|---|---|
| **False positives on real traffic** | 339 of 21,167, **1.60%** | 9 of 21,167, **0.0425%** |
| SQL injection recall | 0.784 | **0.953** |
| XSS recall | 0.826 | **0.997** |
| Recall at 0.1% FPR, held out | 0.803 | **0.970** |
| Unseen attack types | 0.209 | **0.760** |
| macro F1 | 0.916 | 0.984 |

**Thirty eight times fewer false positives, and better recall at the same time.**

That both directions improved together is the part worth dwelling on. A threshold
change trades one against the other; only a fix to the underlying representation
moves both. The model was never short of capacity. It was short of an example of
what ordinary traffic looks like.

The cases that started this investigation:

| Request | ECML model | Corpus model |
|---|---|---|
| `/users/42/profile` | 0.9996 refused | 0.0000 allowed |
| `/shuttle/missions/sts-78/news/` | 0.9995 refused | 0.0000 allowed |
| `id=1' OR 1=1--` | 0.512 allowed | 1.0000 refused |
| `id=1' AND SLEEP(5)--` | 0.182 allowed | 1.0000 refused |

Nine of nine correct, against five of nine before.

## What is left, and why it is a different kind of problem

Every one of the nine remaining false positives is the same endpoint:

```
/htbin/wais.pl?orbital+elements+OR+keplerian+OR+keps
/htbin/wais.pl?fuel+AND+vacuum+OR+space
/htbin/wais.pl?(kempler elements) and (sts70)
/htbin/wais.pl?challenger+or+51L
```

A search form that accepts boolean operators. `x OR y` is a legitimate query to
that application and is also the shape of an injection, and no amount of training
data resolves that from the request alone: the two are genuinely
indistinguishable without knowing what the endpoint does.

This is not the earlier failure in a smaller form. `shuttle` was a corpus artefact
and should never have carried signal. Boolean search syntax carries real signal
that happens to be ambiguous. The honest handling is an endpoint exception, which
is exactly what the console's review queue and feedback mechanism exist to
produce.

The remaining missed payloads are mostly degenerate single characters (`!`, `_`,
`"&"`) that do nothing on their own, plus a handful of genuinely clever ones: a
base64 `data:` URI using UTF-7, and `eval(name)`, which contains no attack syntax
at all and gets its payload from the window name.

## What this does not fix

The corpus is generated, and generated data has its own shape. The benign requests
use a hand written list of parameter names and values, so they are more regular
than real application traffic. The traces are old, mostly static file serving, and
carry few POST bodies, so bodies in the corpus are synthesised rather than
observed. The next improvement is traffic captured from a real application, and
the harness for that already exists as the Docker demo.


---

# Scorecard: three models, eight datasets

One number at a time has misled this project repeatedly. `mlwaf.scorecard` scores
every model on every dataset at once, which is the only view that has not.

| Dataset | ECML | Real traces, per request | Real traces, per value |
|---|---|---|---|
| NASA real traffic (false positives) | 2.48% | 0.00% | **0.00%** |
| CSIC benign, unseen site (false positives) | 0.20% | 20.56% | **0.92%** |
| Adversarial benign probes (false positives) | 12.50% | 25.00% | **4.17%** |
| SQL injection payloads (blocked) | 79.87% | 95.70% | **96.24%** |
| XSS payloads (blocked) | 80.25% | 100% | **100%** |
| Classic attack probes (blocked) | 73.33% | 100% | 93.33% |
| Obfuscated attacks (blocked) | 100% | 100% | **100%** |

Scoring per value wins or ties nearly everywhere. The one place it does not is the
classic attack probes, where it misses `admin'#`.

The ECML model's 0.20% on CSIC looks like the best result in that row and is not.
It blocks 14% of CSIC's anomalous traffic and 80% of community payloads: it is not
discriminating, it is declining to act.

## A metric of mine that was wrong

Earlier sections quote a "CSIC recall" of 15% to 38% and treat it as a weakness.
It is not a meaningful number, and reporting it as one was a mistake.

CSIC's anomalous class is mostly not SQL injection or XSS:

```
idA=2                                          parameter tampering
nombre=Vino Rioja&precio=85&cantidad=76        a valid request, marked anomalous
precio=100%2F                                  a typo in a price
gisell*+a                                      a star in a name
```

The dataset's own documentation says as much: anomalous traffic includes parameter
tampering and requests with deliberate typos. A detector for two attack classes
should ignore those, and does. CSIC's benign half remains a genuinely useful test,
because false positives there are real false positives. Its attack half is not a
recall benchmark for this model, and the community payload lists are.

## What is left

Two failures survive, both narrow and both understood.

**`nombre=libel` scores 1.000.** The n-gram `" li"` contributes over seven points
toward "attack" on its own. `char_wb` pads word starts with a space, so SQL's
`LIKE`, HTML's `<link>` and a surname beginning `li` share a feature. Switching to
plain `char` n-grams removes the collision and was tried: false positives on CSIC
went from 1.07% to 6.23% and SQL injection precision fell from 0.86 to 0.61, so it
was reverted. The remedy is benign examples containing those fragments, not a
different analyser.

**`admin'#` scores 0.187 and is allowed.** A quote and a hash, seven characters.
Scoring values in isolation is what makes the model site independent, and it is
also what leaves a very short payload with too little to go on. This is the
trade the architecture makes, stated rather than hidden.
