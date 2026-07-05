// session_source — the "source" half of the authority (DESIGN.md §5.1).
//
// Fetches a TLS 1.3 resumption session via a PQC-preferred handshake, and can
// replay one to prove it resumes. No pool, no UDS yet — just the primitives the
// pool and the injector payload build on.

#ifndef TICKETCONNECT_SESSION_SOURCE_H
#define TICKETCONNECT_SESSION_SOURCE_H

#include <stddef.h>

#include <openssl/ssl.h>

struct Fetch_result {
    SSL_SESSION* session; // owned; caller frees with SSL_SESSION_free (NULL if none)
    char group[64];       // negotiated key-exchange group name
    int is_pqc;           // negotiated group is a hybrid ML-KEM group
};

// Handshake to host:port (PQC preferred) and capture the resumption session.
// insecure != 0 skips certificate verification (self-signed test servers).
// Returns 0 on success with a captured, resumable session in *out.
int session_fetch(const char* host, const char* port, int insecure, struct Fetch_result* out);

// Serialize a session to a freshly malloc'd DER buffer (caller frees *der).
// Returns the DER length, or <= 0 on failure.
int session_to_der(SSL_SESSION* sess, unsigned char** der);

// Replay a serialized session against host:port. On handshake success sets
// *reused to 1 iff the connection resumed via PSK, and copies the negotiated
// group into group_out. Returns 0 on handshake success. This is the userspace
// model of the injector payload (d2i_SSL_SESSION + SSL_set_session).
int session_probe_resume(const char* host, const char* port, int insecure, const unsigned char* der,
                         size_t der_len, int* reused, char* group_out, size_t group_len);

#endif // TICKETCONNECT_SESSION_SOURCE_H
