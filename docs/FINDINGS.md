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
