# Security policy

## What this project is

Ferrum is an **experimental** blockchain built as an engineering demonstration. Its token has never
been sold, priced, or promised to appreciate, and it never will be. Do not put anything of value on
this network.

## Threat model, stated honestly

Ferrum is a single implementation maintained by one person. It has **not** been audited. Its
substitutes for an audit are, in descending order of value:

1. a deliberately naive **reference executor**, written from `docs/SPEC.md` rather than from the
   production code, differentially tested against the real executor on every simulated block;
2. a **determinism replay harness** run in debug, in release, and cross-compiled to aarch64;
3. **fuzz targets** on the two places untrusted bytes land — the decoder and the script VM;
4. **adversarial scenario tests**, each written red-then-green.

That is a real testing programme. It is not equivalent to two independent audits. Treat the chain
accordingly.

## Reporting a vulnerability

Open a GitHub security advisory, or email the address in `Cargo.toml`. Please do not open a public
issue for anything that lets someone forge, inflate, halt or split the chain.

Include: the affected version or commit, the consensus rule or code path involved, and a concrete
reproduction — ideally a failing test against `testing/sim`.

## Scope

**In scope:** consensus splits, inflation, signature forgery or replay, UTXO double-spends, incorrect
reorg handling, node crashes or resource exhaustion reachable from the p2p or RPC surface, wallet key
handling.

**Out of scope:** the fact that the network is small and could be reorganised by anyone willing to
rent enough hashrate. That is a property of a demonstration chain with no security budget, it is
documented in `README.md`, and it is not a bug.
