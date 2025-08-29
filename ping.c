#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>

// varint encoding for MC protocol
int write_varint(uint32_t value, uint8_t *buf) {
    int i = 0;
    do {
        uint8_t temp = value & 0x7F;
        value >>= 7;
        if (value != 0) temp |= 0x80;
        buf[i++] = temp;
    } while (value != 0 && i < 5);
    return i;
}

int connect_tcp(const char *host, uint16_t port) {
    struct addrinfo hints = {0}, *res, *r;
    char portstr[6];
    int sock = -1;

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof(portstr), "%u", port);

    if (getaddrinfo(host, portstr, &hints, &res) != 0) return -1;
    for (r = res; r != NULL; r = r->ai_next) {
        sock = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
        if (sock < 0) continue;
        if (connect(sock, r->ai_addr, r->ai_addrlen) == 0) break;
        close(sock); sock = -1;
    }
    freeaddrinfo(res);
    return sock;
}

// send all bytes
int sendall(int sock, const uint8_t *buf, int len) {
    int sent = 0;
    while (sent < len) {
        int n = send(sock, buf + sent, len - sent, 0);
        if (n <= 0) return -1;
        sent += n;
    }
    return sent;
}

// read varint from socket
int read_varint(int sock, uint32_t *out) {
    uint32_t result = 0;
    int shift = 0, i = 0;
    uint8_t byte;
    while (1) {
        if (recv(sock, &byte, 1, 0) != 1) return -1;
        result |= (uint32_t)(byte & 0x7F) << shift;
        if (!(byte & 0x80)) break;
        shift += 7;
        if (++i > 5) return -1;
    }
    *out = result;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("Usage: %s <host> <port> [protocol]\n", argv[0]);
        return 1;
    }
    const char *host = argv[1];
    uint16_t port = atoi(argv[2]);
    uint32_t protocol = (argc > 3) ? atoi(argv[3]) : 761; // default to 1.20.1

    int sock = connect_tcp(host, port);
    if (sock < 0) {
        fprintf(stderr, "Failed to connect\n");
        return 1;
    }

    // build handshake packet
    uint8_t handshake[512], *p = handshake;
    uint8_t temp[10];
    int len = 0;

    // packet ID 0x00
    *p++ = 0x00;
    // protocol version
    int n = write_varint(protocol, temp);
    memcpy(p, temp, n); p += n;
    // server address (varint len + string)
    uint8_t hostlen = strlen(host);
    *p++ = hostlen;
    memcpy(p, host, hostlen); p += hostlen;
    // port (big endian)
    *p++ = port >> 8;
    *p++ = port & 0xFF;
    // next state: status (1)
    *p++ = 0x01;

    int handshake_len = p - handshake;
    // length prefix (varint)
    n = write_varint(handshake_len, temp);

    // send handshake
    sendall(sock, temp, n);
    sendall(sock, handshake, handshake_len);

    // send status request (packet ID 0x00)
    uint8_t status_req[] = { 0x01, 0x00 }; // length, packet id
    sendall(sock, status_req, 2);

    // read response
    uint32_t packet_len = 0;
    if (read_varint(sock, &packet_len) < 0) goto fail;
    uint8_t *resp = malloc(packet_len + 1);
    int got = 0, nbytes;
    while (got < packet_len) {
        nbytes = recv(sock, resp + got, packet_len - got, 0);
        if (nbytes <= 0) goto fail;
        got += nbytes;
    }
    resp[packet_len] = 0;

    // skip packet ID and varint JSON length
    uint32_t json_len = 0, offset = 1;
    // parse varint for JSON length
    p = resp + offset;
    int j = 0;
    do {
        json_len |= (p[j] & 0x7F) << (7 * j);
    } while ((p[j++] & 0x80) && j < 5);
    offset += j;

    printf("%.*s\n", json_len, resp + offset);

    free(resp);
    close(sock);
    return 0;
fail:
    fprintf(stderr, "Error receiving response\n");
    close(sock);
    return 1;
}
