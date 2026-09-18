# Challenge types: which ones this deployment can use, and why

wecert solves **DNS-01 only**, and that is a deliberate fit to where it runs rather than a
limitation that was never revisited. This note records the analysis, because "add HTTP-01" is a
reasonable-sounding request that turns out to be half-possible here — and the other half is
impossible for a structural reason worth writing down.

## The constraint

From `README.md`:

> One binary and one SQLite file. Because decryption happens at the load balancer, there is no
> node agent and no certificate files to distribute — the entire deploy action is a few Tencent
> Cloud API calls.

So: wecert runs on **one** CVM. The domains resolve to the **CLB**, which terminates TLS. The
backend RS pool takes no part in TLS. Every challenge type asks the CA to fetch something from
`<domain>`, which means the CA talks to the CLB — not to wecert.

| Type | Possible here? | Why |
|---|---|---|
| **DNS-01** | **Yes — what wecert does** | The proof goes in DNS, which wecert already has API credentials for. The CA never needs to reach the host at all, which is exactly why this is the right default for this shape. It is also the **only** type that can issue wildcards (`*.example.com` has no address to fetch). |
| **HTTP-01** | **Only with a CLB rule** | The CA requests `http://<domain>/.well-known/acme-challenge/<token>`. That request arrives at the CLB, which would have to forward that path to wecert's listener. CLB layer-7 rules can do this, so it is implementable — but it is not "works out of the box", it requires an operator change to the load balancer, and it adds a public HTTP listener to a program that currently serves nothing. |
| **TLS-ALPN-01** | **No** | It requires completing a TLS handshake on **port 443** with ALPN protocol `acme-tls/1`. Port 443's TLS belongs to the CLB, and `acme-tls/1` is negotiated during the handshake — there is no path or hostname to route on, so the CLB has no mechanism to pass the handshake through to a backend while terminating TLS for everything else. The only way to use it is for the domain to bypass the CLB entirely, which is a different deployment than the one this program is for. |

## What this means in practice

**HTTP-01 would be a complement, never a replacement.** It cannot issue wildcards, so a deployment
using it would lose the property that makes the rate-limit arithmetic work: with
`*.example.com` declared, adding `foo.example.com` costs **zero** issuances because the SAN set
does not change. Without wildcards, a subdomain addition that shares no identifier with the certificate
being replaced forfeits the ARI exemption and spends *50 certificates per registered domain
per 7 days*; adding it to an existing certificate keeps the exemption.

Its real use case is narrow and worth stating plainly: **an operator who cannot create a DNS API
credential** (the zone belongs to someone else, or the provider has no API) but *can* add a CLB
rule. That is a legitimate situation, and DNS-01 cannot serve it at all.

## If it is added later, what it touches

Not just a new solver. The DNS-01 path encodes its assumptions in three places, and each would
need generalising without disturbing the crash-recovery guarantees that took the most care to get
right:

- **The persisted authorization model** — `TxtName`, `TxtValue` and `Presented` in
  `state.Authorization` are TXT-shaped. HTTP-01 has a token and no DNS record.
- **The propagation waiter** — `WaitAll` probes the zone's authoritative nameservers with a
  quorum, because "every NS reachable" never passes in practice. HTTP-01 has no equivalent wait:
  the resource either answers or it does not.
- **The challenge lease registry** — `challengeLeases` exists because lego's providers delete
  **every** TXT at a name, so the last leaver owns the deletion. Nothing about HTTP-01 needs that,
  so the registry must become DNS-specific rather than universal.

The parts that must not regress are the ones that only matter when a pass dies mid-flight: the
"probe before re-present" logic that distinguishes adopt from rewrite, and the write-all →
verify-all → clean-up-together ordering that a wildcard and its apex depend on because they share
one `_acme-challenge` name.

## Why this is documented instead of implemented

Two of the three rows above are answers, not tasks. TLS-ALPN-01 is not implementable in this
deployment shape, and promising it would be worse than not having it. HTTP-01 is implementable but
touches the DNS-01 crash-recovery path, and its value is limited to the narrow case above — so it
is a decision to take deliberately, against a real operator who needs it, rather than a box to
tick. Until then DNS-01 is not a gap: it is the challenge type this architecture is built around.
