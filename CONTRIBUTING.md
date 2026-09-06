# Contributing

## Before you write code

Read `docs/CONTRACT.md`. It is normative: exact names, exact signatures, exact algorithms. If an
implementation and the contract disagree, the contract wins and the implementation is a bug. If you
believe the contract is wrong, change the contract in the same pull request and say why.

## The rules that are not negotiable

- `unsafe` is forbidden workspace-wide.
- No `f32`/`f64` anywhere. Difficulty, fees and subsidy are integer-only; a float here is a
  platform-dependent chain split.
- No wall-clock, RNG, I/O or hash-map iteration inside the state-transition path. Time enters only
  through `BlockCtx`.
- Consensus arithmetic is checked. `clippy::arithmetic_side_effects` is denied on `chain`, `script`
  and `consensus`.
- `ferrum-consensus` may depend on `ferrum-types` and `ferrum-crypto` only. CI enforces this, and it
  is the single rule that keeps the PoW→BFT swap a config change instead of a rewrite.
- No unbounded channels. Every queue has an explicit capacity and load-sheds when full.

## Before you open a pull request

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
bash scripts/check-invariants.sh
```

## Changing a consensus rule

Any change to encoding, hashing, script semantics, difficulty or validation is a **hard fork**. Say
so in the pull request title, add the rule to `docs/SPEC.md`, add a red-then-green test, and gate it
behind an activation height rather than changing behaviour retroactively.

The frozen domain-separation tag list in `docs/CONTRACT.md` §1 may be *extended*. Changing or
removing an existing tag is never acceptable.

## Style

Match the surrounding code. `cargo fmt` settles formatting; it does not settle naming, module layout
or comment density, and reviewers will. Comments explain *why*, not *what* — the code already says
what it does.
