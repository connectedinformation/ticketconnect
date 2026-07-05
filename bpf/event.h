// Shared event layout between the BPF program and the userspace loader.
// Kept deliberately small: the detection half emits identity + the SSL pointer;
// the injector (ptrace side) does the rest. No private libssl struct is read.

#ifndef TICKETCONNECT_BPF_EVENT_H
#define TICKETCONNECT_BPF_EVENT_H

struct ssl_event {
    __u32 pid; // thread-group id (the process)
    __u32 tid; // thread id (the caller of SSL_connect)
    __u64 ssl; // the SSL* argument — what the injector installs into
};

#endif // TICKETCONNECT_BPF_EVENT_H
