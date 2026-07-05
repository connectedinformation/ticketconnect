# Contributing

Thanks for your interest. ticketconnect is early-stage; issues, design
discussion, and pull requests are all welcome.

## Ground rules

- **The design is the source of truth.** ticketconnect is built from
  [docs/DESIGN.md](docs/DESIGN.md). Extend the design via an ADR
  (`docs/adr/NNNN-*.md`); don't silently re-architect.
- **Public-API-only injection is non-negotiable.** The injector must call only
  exported OpenSSL functions by resolved symbol address — never private struct
  offsets. This is what makes the memory-corruption bug class unrepresentable
  (see [SECURITY.md](SECURITY.md)); PRs that reintroduce offset pokes won't be
  merged.
- **No silent downgrade.** A miss or failure must fall back to normal TLS *and
  surface an event*.

## Build & test

Reference environment: **Fedora 43** (OpenSSL 3.5 for X25519MLKEM768, clang,
`bpftool`, libbpf). A container is the easiest path — see
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) for the exact toolchain.
Currently **x86-64 + OpenSSL only**.

```
make -C ticket-agent && make -C injector && make -C bpf && make -C demo

make -C ticket-agent check      # agent tests (unprivileged)
make -C injector check          # remote-call, symbols, fail-closed, real install
make -C injector check-wireup   # eBPF freeze -> install -> resume (needs sudo)
make -C bpf check               # uprobe detection (needs sudo)
./demo/run_host_demo.sh         # full host acceptance demo (needs sudo)
./demo/verify_injection.sh      # prove resumption uses the injected ticket
```

The eBPF/ptrace tests need privilege; the pure userspace tests do not.

## Style

- **C is primary.** Bjarne Stroustrup layout, enforced by
  [`.clang-format`](.clang-format): 4-space indent, no tabs, column 100,
  pointer bound to the type (`int* p`), function/class/namespace brace on its own
  line. Run `clang-format -i` before committing.
- Naming: types `Capitalized_with_underscores`, functions/variables `snake_case`.
- Comments minimal; cite RFC sections (RFC 8446, RFC 5077) where wire format
  matters.

## Pull requests

- Keep changes focused; one logical change per PR.
- Add or update tests for behavior changes; keep CI green (build + format gate +
  unprivileged tests).
- Explain *why* in the PR description, not just *what*.

## Security

Do **not** report vulnerabilities in public issues or PRs — see
[SECURITY.md](SECURITY.md).
