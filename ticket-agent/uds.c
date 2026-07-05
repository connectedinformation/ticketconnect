// uds — see uds.h.

#define _POSIX_C_SOURCE 200112L

#include "uds.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

static int read_exact(int fd, void* buf, size_t n)
{
    unsigned char* p = buf;
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, p + got, n - got);
        if (r == 0) {
            return 0; // peer closed
        }
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        got += (size_t)r;
    }
    return 1;
}

static int write_all(int fd, const void* buf, size_t n)
{
    const unsigned char* p = buf;
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, p + sent, n - sent);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        sent += (size_t)w;
    }
    return 1;
}

static void put_u32(unsigned char* p, uint32_t v)
{
    p[0] = (unsigned char)(v >> 24);
    p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);
    p[3] = (unsigned char)(v);
}

static uint32_t get_u32(const unsigned char* p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

int uds_parse_request(const unsigned char* buf, size_t len, uint8_t* op, char* dest,
                      size_t dest_cap)
{
    if (len < UDS_REQ_HDR) {
        return -1;
    }
    if (buf[0] != UDS_MAGIC || buf[1] != UDS_VERSION) {
        return -2;
    }
    uint8_t dest_len = buf[3];
    if (dest_len == 0 || (size_t)(UDS_REQ_HDR + dest_len) != len) {
        return -3;
    }
    if ((size_t)dest_len + 1 > dest_cap) {
        return -4;
    }
    *op = buf[2];
    if (*op != UDS_OP_GET) {
        return -5;
    }
    memcpy(dest, buf + UDS_REQ_HDR, dest_len);
    dest[dest_len] = '\0';
    return 0;
}

static int send_status(int fd, uint8_t status)
{
    unsigned char resp[UDS_RESP_HDR] = {UDS_MAGIC, UDS_VERSION, status, 0, 0, 0, 0, 0, 0};
    return write_all(fd, resp, sizeof(resp));
}

static void handle_conn(int fd, Pool* pool)
{
    unsigned char frame[UDS_REQ_HDR + UDS_DEST_MAX];
    if (read_exact(fd, frame, UDS_REQ_HDR) != 1) {
        return;
    }
    if (frame[0] != UDS_MAGIC || frame[1] != UDS_VERSION || frame[3] == 0) {
        send_status(fd, UDS_STATUS_ERROR);
        return;
    }
    uint8_t dest_len = frame[3];
    if (read_exact(fd, frame + UDS_REQ_HDR, dest_len) != 1) {
        return;
    }

    uint8_t op = 0;
    char dest[UDS_DEST_MAX + 1];
    if (uds_parse_request(frame, (size_t)UDS_REQ_HDR + dest_len, &op, dest, sizeof(dest)) != 0) {
        send_status(fd, UDS_STATUS_ERROR);
        return;
    }

    unsigned char* der = NULL;
    int der_len = 0;
    int is_pqc = 0;
    char group[64] = {0};
    if (!pool_get(pool, dest, &der, &der_len, &is_pqc, group, sizeof(group))) {
        send_status(fd, UDS_STATUS_MISS); // explicit miss, never a dropped conn
        pool_maintain(pool, dest);        // refill so the next request can hit
        return;
    }

    size_t group_len = strlen(group);
    size_t total = (size_t)UDS_RESP_HDR + group_len + (size_t)der_len;
    unsigned char* resp = malloc(total);
    if (resp == NULL) {
        free(der);
        send_status(fd, UDS_STATUS_ERROR);
        return;
    }
    resp[0] = UDS_MAGIC;
    resp[1] = UDS_VERSION;
    resp[2] = UDS_STATUS_OK;
    resp[3] = (unsigned char)(is_pqc ? 1 : 0);
    resp[4] = (unsigned char)group_len;
    put_u32(resp + 5, (uint32_t)der_len);
    memcpy(resp + UDS_RESP_HDR, group, group_len);
    memcpy(resp + UDS_RESP_HDR + group_len, der, (size_t)der_len);

    write_all(fd, resp, total);
    free(resp);
    free(der);
    pool_maintain(pool, dest); // top back up (this request consumed one)
}

int uds_serve(const char* path, Pool* pool)
{
    signal(SIGPIPE, SIG_IGN);

    int lfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (lfd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(addr.sun_path)) {
        fprintf(stderr, "socket path too long: %s\n", path);
        close(lfd);
        return 1;
    }
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

    unlink(path);
    if (bind(lfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(lfd);
        return 1;
    }
    if (listen(lfd, 16) < 0) {
        perror("listen");
        close(lfd);
        return 1;
    }

    for (;;) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        handle_conn(cfd, pool);
        close(cfd);
    }

    close(lfd);
    unlink(path);
    return 0;
}

int uds_get(const char* path, const char* dest, unsigned char** der, int* der_len, int* is_pqc,
            char* group, size_t group_cap)
{
    size_t dest_len = strlen(dest);
    if (dest_len == 0 || dest_len > UDS_DEST_MAX) {
        return -1;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(addr.sun_path)) {
        close(fd);
        return -1;
    }
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    // Bound the wait: a slow/refilling agent must never stall the caller's loop.
    struct timeval tv = {.tv_sec = 3, .tv_usec = 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    unsigned char req[UDS_REQ_HDR + UDS_DEST_MAX];
    req[0] = UDS_MAGIC;
    req[1] = UDS_VERSION;
    req[2] = UDS_OP_GET;
    req[3] = (unsigned char)dest_len;
    memcpy(req + UDS_REQ_HDR, dest, dest_len);
    if (write_all(fd, req, UDS_REQ_HDR + dest_len) != 1) {
        close(fd);
        return -1;
    }

    unsigned char hdr[UDS_RESP_HDR];
    if (read_exact(fd, hdr, sizeof(hdr)) != 1) {
        close(fd);
        return -1;
    }
    if (hdr[0] != UDS_MAGIC || hdr[1] != UDS_VERSION) {
        close(fd);
        return -1;
    }
    uint8_t status = hdr[2];
    if (status != UDS_STATUS_OK) {
        close(fd);
        return status; // MISS or ERROR — a valid, explicit answer
    }

    int pqc = hdr[3];
    uint8_t group_len = hdr[4];
    uint32_t n = get_u32(hdr + 5);

    char gbuf[256];
    if (group_len > 0 && read_exact(fd, gbuf, group_len) != 1) {
        close(fd);
        return -1;
    }
    gbuf[group_len] = '\0';

    unsigned char* buf = malloc(n > 0 ? n : 1);
    if (buf == NULL || read_exact(fd, buf, n) != 1) {
        free(buf);
        close(fd);
        return -1;
    }
    close(fd);

    *der = buf;
    *der_len = (int)n;
    *is_pqc = pqc;
    if (group != NULL && group_cap > 0) {
        snprintf(group, group_cap, "%s", gbuf);
    }
    return UDS_STATUS_OK;
}
