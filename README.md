# adX — Active Directory eXplorer

BloodHound sniffs. adX sees.

adX loads a SharpHound / bloodhound-python collection and tells you, straight
away, **where the attack paths are** — no Neo4j, no Postgres, no Docker. One
static binary, in memory, open in your browser in seconds. It is built for the
moment in an engagement (or an exam) when you have a foothold and need the next
move, not a graph to go spelunking in.

## Run it

```sh
./adx-darwin-arm64            # macOS (Apple Silicon)
```

With no arguments it loads a built-in sample domain so you can see what it does.
Point it at a real collection to use your own data:

```sh
./adx ~/engagement/loot/20261024.zip      # .zip, .7z, .tar.gz, .json, or a directory
```

Share it with a team (binds all interfaces, no browser opened):

```sh
./adx serve --listen 0.0.0.0:8899 ~/engagement/loot/
```

## What you get

- **Findings, ranked for you.** Kerberoast, AS-REP, unconstrained / constrained
  delegation, RBCD, DCSync rights, ADCS ESC1, dangerous ACLs over tier-zero,
  MachineAccountQuota — grouped into *exploitable now*, *reachable with extra
  steps*, and *not reachable yet*, relative to what you have already owned.
- **Mark as owned.** Click a node, mark it owned, and every path re-ranks from
  there. The "fastest route to the domain" updates as you go.
- **Attack cards.** Every finding explains why it works, the path from your
  owned principals, the steps, and ready-to-run commands for Linux (impacket,
  certipy) and Windows (Rubeus, PowerView).

## Build from source

```sh
go build -o adx .            # your platform
./scripts/build.sh 0.1.0     # all platforms into dist/
```

Supported targets: macOS, Linux and Windows on amd64 / arm64 (plus Windows x86).

## Roadmap

1. Built-in collector (`adx-collect`) — gather from Linux (remote, no agent on
   target) and from domain-joined Windows. amd64 / arm64 / x86.
2. Shared team mode with authentication and shared owned-state.
3. Local LLM analysis (Ollama) — the model drives the same queries as tools, so
   AD data never leaves the host.

## Status

Early. The detection rules need validation against real collections before you
trust a path blindly — read the attack card, don't just run the command.
