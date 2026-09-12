# Demo: the firewall refusing real attacks

## Run it

```sh
make train                 # produces models/model.joblib, which the image bakes in
docker compose up --build
```

| URL | What it is |
|---|---|
| http://localhost:8080 | Juice Shop, behind the firewall |
| http://localhost:8080/_waf | the operator console |
| http://localhost:3000 | Juice Shop directly, unprotected |

Both paths are exposed on purpose. Showing only the protected one proves nothing.

## The proof

OWASP Juice Shop has a real SQL injection in its product search. Point sqlmap at
the application directly and it finds it. Point it through the firewall and it
does not.

```sh
# unprotected: sqlmap identifies the injection
sqlmap -u "http://localhost:3000/rest/products/search?q=1" --batch --level=2

# protected: every probe is refused, so sqlmap has nothing to work with
sqlmap -u "http://localhost:8080/rest/products/search?q=1" --batch --level=2
```

While the second run is going, the console shows the probes arriving and being
refused, one row per attempt, each with the decode trace that unwrapped it.

## Without Docker

```sh
make train
WAF_UPSTREAM=http://localhost:3000 WAF_MODE=block python -m mlwaf.waf.app
```

## Checking by hand

```sh
# allowed
curl -i "http://localhost:8080/rest/products/search?q=apple"

# refused
curl -i "http://localhost:8080/rest/products/search?q=1%27+UNION+SELECT+1,2,3--"

# refused, and it was double encoded, which is the normalisation chain working
curl -i "http://localhost:8080/rest/products/search?q=1%2527%2520UNION%2520SELECT%25201--"

# allowed, because an apostrophe in a name is not an attack
curl -i -X POST -d "name=O'Brien&city=Cork" "http://localhost:8080/api/account"
```

A refusal looks like this:

```
HTTP/1.1 403 Forbidden
X-MLWAF-Request-Id: f6d2367e-00000002
X-MLWAF-Action: block

{"error":"request_blocked",
 "message":"This request was refused by the web application firewall.",
 "request_id":"f6d2367e-00000002"}
```

The body carries a request id and nothing else. An operator can find the decision
in the console; an attacker learns nothing about why it failed, which matters
because a WAF that explains itself to the client is a tuning oracle.

## Detect mode first

The default is `detect`, and that is not timidity. A WAF is rolled out by watching
what it would have blocked, reviewing that list, and enforcing once the queue is
quiet. In detect mode nothing is refused, every request is still scored, and
`X-MLWAF-Action: would-block` marks the ones enforcement would have stopped.

```sh
WAF_MODE=detect python -m mlwaf.waf.app
```

The console's review queue is that list. Promote to enforcing from the header
toggle, or by restarting with `WAF_MODE=block`.

## Load

```sh
# 2000 requests, 20 concurrent, through the firewall
hey -n 2000 -c 20 "http://localhost:8080/rest/products/search?q=apple"
curl -s localhost:8080/_waf/metrics | grep mlwaf_scoring_seconds
```

Repeated requests are served from the decision cache, so a benchmark that hammers
one URL measures the cache rather than the model. Vary the query string to
measure scoring.
