# Contributing

[中文](Contributing-zh) · [Home](Home)

## Before you write code

- Read [Admission-Policy](Admission-Policy). Adding a `SIGN` capability without a test in the same
  commit will be rejected, whatever the chain is.
- Read [Testing](Testing) and run `tests/host/build.ps1` plus `tests/host/policy_check.ps1`. Both
  must pass before a pull request is worth reviewing.
- The license is personal non-commercial. By submitting a contribution you license it to the
  copyright holder under LICENSE section 7; do not send code you cannot license that way.

## Code rules that are not negotiable

| Rule | Why |
| --- | --- |
| No `String`, no STL containers, no exceptions, no RTTI in firmware | heap fragmentation and exception tables cost DRAM the wallet does not have |
| Fixed buffers with explicit lengths at every boundary | every parser is reachable from untrusted input |
| `chain_copy_text()` / bounded `snprintf`, never an unbounded copy | `policy_check.ps1` fails the build above its baseline |
| Typed error enums, no sentinel integers | a caller must not be able to invent success |
| Secrets only in `SensitiveValue<T>` | early returns and stack reuse are the common leak |
| Refuse rather than truncate, always | a truncated address or amount is a fund-loss bug |
| No new network, no new dependency without pinning a revision | reproducibility is the whole point |

## What a good change looks like

1. One concern per commit. A chain change touches the profile, the policy, the parser and the
   vectors; a comment-only change touches nothing else.
2. The test lands with the code. Prefer a negative case (malformed, tampered, oversized) over a
   second happy path.
3. Generated tables are regenerated, never edited. `--check` must pass.
4. Docs that claim a capability are updated in the same commit; a stale claim is a bug.
5. If a behaviour is unverified on hardware, say so in the code comment and in the docs.

## Publishing this wiki

GitHub wikis are a flat set of `.md` files in a separate git repository: no subdirectories, and
`_Sidebar.md` / `_Footer.md` are special. The layout here follows that:

- `Page.md` is English, `Page-zh.md` is the Chinese version, and both start with a language switch.
- `Home.md` / `Home-zh.md` are the landing pages; `_Sidebar.md` lists both languages.
- `record-*` and dated files are records; do not rewrite them.

Create the first page in the GitHub web UI once, then:

```powershell
powershell -ExecutionPolicy Bypass -File tools/publish_wiki.ps1 -DryRun
powershell -ExecutionPolicy Bypass -File tools/publish_wiki.ps1
```

The script clones `HexWallet.wiki.git` into `build/wiki-publish`, copies every root `*.md`, commits
and pushes. It refuses to push when the clone fails, so an empty wiki has to be created by hand
once.

## Reporting a security issue

Do not open a public issue for a vulnerability. Email `blueokanna@gmail.com` with the affected file,
a minimal reproduction and the expected impact. There is no bounty programme.

## Review checklist

- Does the change alter what gets signed without altering what gets displayed?
- Can the new code path be reached with a length the parser has not bounded?
- Is a failure path leaving a key, a buffer or an approval alive?
- Does the change widen a capability bit without a test and a refusal list?
- Do the docs still match the code?
