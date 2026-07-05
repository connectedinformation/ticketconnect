# ticketconnect

Give a legacy TLS client post-quantum key material it cannot negotiate itself —
without changing its code, its image, or its deployment.

A post-quantum-capable node agent performs the X25519MLKEM768 handshake on the
client's behalf and installs the resulting TLS 1.3 resumption session into the
client, so the client's own next connection resumes on a quantum-safe PSK. Off
the data path; zero application change.

## Status

Pre-release, in active development. The design is the source of truth:
[docs/DESIGN.md](docs/DESIGN.md).

## License

MIT — see [LICENSE](LICENSE).
