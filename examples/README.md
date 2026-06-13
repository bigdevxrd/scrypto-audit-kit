# Examples

Worked examples of using scrypto-audit-kit. Each example here is a recipe a new user can follow end-to-end.

## Quickstart: audit a public Radix blueprint

```bash
# Clone the kit
git clone https://github.com/bigdevxrd/scrypto-audit-kit
cd scrypto-audit-kit
chmod +x audit.sh

# Set your API key
export ANTHROPIC_API_KEY=sk-ant-...

# Clone a target blueprint (Ignition is a good warm-up — it's the Radix-team reference)
git clone https://github.com/radixdlt/Ignition /tmp/ignition

# Run an audit against one of its packages
./audit.sh /tmp/ignition/packages/simple-oracle

# Read the report
cat audit-reports/Ignition-simple-oracle-*.md
```

## Auditing your own blueprint

```bash
./audit.sh /path/to/your/scrypto/package
```

The package directory must contain a `Cargo.toml` and a `src/lib.rs`. The kit will pick up everything under `src/` and `tests/`.

## Re-running after changes

The kit doesn't track previous runs — each invocation is a fresh audit. If you re-run after fixing some findings:

```bash
./audit.sh /path/to/package
# new report at audit-reports/<repo>-<package>-<today>.md
```

Compare against the previous report manually to confirm fixes landed.

## Auditing a workspace with multiple packages

The kit operates on one package at a time. Loop in bash:

```bash
for pkg in /path/to/workspace/packages/*; do
  [[ -f "$pkg/Cargo.toml" ]] && ./audit.sh "$pkg"
done
```

Each package gets its own report. Cached references make this cheap after the first run.

## Sharing trial reports

Found something interesting? Open a trial-report issue (see `.github/ISSUE_TEMPLATE/trial-report.md`). Negative results are valuable.

## Sample reports

When the project has a few trial runs landed, sample reports will live alongside this README so new users can see what to expect. Until then, run one against [Ignition](https://github.com/radixdlt/Ignition) and you'll have your own sample in 60 seconds.
