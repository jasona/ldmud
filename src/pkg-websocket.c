/*------------------------------------------------------------------
 * WebSocket support for LDMud (RFC 6455)
 *
 * This module provides native WebSocket support at the driver level,
 * allowing web-based clients to connect directly alongside traditional
 * telnet connections. The implementation follows the same pattern as
 * TLS (pkg-tls.c), wrapping at the connection level.
 *
 * Data flow: Network <-> TLS <-> WebSocket <-> Command Processing
 *------------------------------------------------------------------*/

#include "driver.h"

#ifdef USE_WEBSOCKETS

#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>

#include "pkg-websocket.h"
#include "actions.h"
#include "comm.h"
#include "interpret.h"
#include "mstrings.h"
#include "object.h"
#include "sha1.h"
#include "simulate.h"
#include "svalue.h"
#include "xalloc.h"

#include "../mudlib/sys/driver_hook.h"

/*-------------------------------------------------------------------------*/
/* Forward declarations */

static void ws_compute_accept_key(const char *client_key, char *output);
static size_t ws_base64_encode(const unsigned char *in, size_t len,
                               char *out, size_t out_size);
static void ws_send_raw_frame(interactive_t *ip, unsigned char opcode,
                              const char *payload, size_t len);
static void ws_handle_ping(interactive_t *ip, const char *data, size_t len);
static void ws_handle_pong(interactive_t *ip, const char *data, size_t len);
static void ws_handle_close_frame(interactive_t *ip, const char *data,
                                  size_t len);

/*-------------------------------------------------------------------------*/
/* The WebSocket GUID (RFC 6455 Section 4.2.2) */

static const char ws_guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/*=========================================================================*/
/*                         Internal Helpers                                */
/*=========================================================================*/

/*-------------------------------------------------------------------------*/
static size_t
ws_base64_encode (const unsigned char *in, size_t len,
                  char *out, size_t out_size)

/* Standard base64 encode <in> (length <len>) into <out> (size <out_size>).
 * Returns the number of characters written (not counting the NUL terminator).
 */

{
    static const char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i, o;

    for (i = 0, o = 0; i + 2 < len && o + 4 <= out_size; i += 3)
    {
        out[o++] = b64[(in[i] >> 2) & 0x3F];
        out[o++] = b64[((in[i] & 0x03) << 4) | ((in[i+1] >> 4) & 0x0F)];
        out[o++] = b64[((in[i+1] & 0x0F) << 2) | ((in[i+2] >> 6) & 0x03)];
        out[o++] = b64[in[i+2] & 0x3F];
    }

    if (i < len && o + 4 <= out_size)
    {
        out[o++] = b64[(in[i] >> 2) & 0x3F];
        if (i + 1 < len)
        {
            out[o++] = b64[((in[i] & 0x03) << 4) | ((in[i+1] >> 4) & 0x0F)];
            out[o++] = b64[((in[i+1] & 0x0F) << 2)];
        }
        else
        {
            out[o++] = b64[((in[i] & 0x03) << 4)];
            out[o++] = '=';
        }
        out[o++] = '=';
    }

    if (o < out_size)
        out[o] = '\0';

    return o;
} /* ws_base64_encode() */

/*-------------------------------------------------------------------------*/
static void
ws_compute_accept_key (const char *client_key, char *output)

/* Compute the Sec-WebSocket-Accept value from the client's
 * Sec-WebSocket-Key. Result is written to <output> which must
 * be at least 29 bytes (28 chars + NUL).
 *
 * Algorithm: base64(SHA-1(client_key + GUID))
 */

{
    SHA1Context sha;
    uint8_t digest[SHA1HashSize];
    size_t key_len = strlen(client_key);
    size_t guid_len = sizeof(ws_guid) - 1;

    SHA1Reset(&sha);
    SHA1Input(&sha, (const uint8_t *)client_key, key_len);
    SHA1Input(&sha, (const uint8_t *)ws_guid, guid_len);
    SHA1Result(&sha, digest);

    ws_base64_encode(digest, SHA1HashSize, output, 29);
} /* ws_compute_accept_key() */

/*=========================================================================*/
/*                     Initialization and Cleanup                          */
/*=========================================================================*/

/*-------------------------------------------------------------------------*/
void
ws_init_data (struct ws_data_s *ws)

/* Initialize a ws_data_s structure to default values. */

{
    ws->handshake_buf = NULL;
    ws->handshake_len = 0;
    ws->frame_buf = NULL;
    ws->frame_len = 0;
    ws->frame_alloc = 0;
    ws->frame_opcode = 0;
    ws->subprotocol = NULL;
    ws->text_mode = MY_TRUE;
    ws->close_sent = MY_FALSE;
    ws->cb = NULL;
} /* ws_init_data() */

/*-------------------------------------------------------------------------*/
void
ws_cleanup (interactive_t *ip)

/* Free all WebSocket-related resources for connection <ip>. */

{
    struct ws_data_s *ws = &ip->ws_data;

    if (ws->handshake_buf)
    {
        xfree(ws->handshake_buf);
        ws->handshake_buf = NULL;
    }

    if (ws->frame_buf)
    {
        xfree(ws->frame_buf);
        ws->frame_buf = NULL;
    }

    if (ws->subprotocol)
    {
        xfree(ws->subprotocol);
        ws->subprotocol = NULL;
    }

    if (ws->cb)
    {
        free_callback(ws->cb);
        xfree(ws->cb);
        ws->cb = NULL;
    }

    ws->handshake_len = 0;
    ws->frame_len = 0;
    ws->frame_alloc = 0;
    ws->frame_opcode = 0;
    ws->text_mode = MY_TRUE;
    ws->close_sent = MY_FALSE;

    ip->ws_status = WS_INACTIVE;
} /* ws_cleanup() */

/*=========================================================================*/
/*                         Handshake Processing                            */
/*=========================================================================*/

/*-------------------------------------------------------------------------*/
static char *
ws_find_header (const char *headers, const char *name, char *value, size_t vsize)

/* Find a header by <name> in the HTTP <headers> string.
 * Copies the value into <value> (up to <vsize>-1 chars).
 * Returns <value> on success, NULL if not found.
 */

{
    const char *p = headers;
    size_t nlen = strlen(name);

    while (*p)
    {
        /* Find next line */
        if (strncasecmp(p, name, nlen) == 0 && p[nlen] == ':')
        {
            const char *v = p + nlen + 1;
            const char *end;
            size_t len;

            /* Skip leading whitespace */
            while (*v == ' ' || *v == '\t')
                v++;

            /* Find end of value (CR or LF) */
            end = v;
            while (*end && *end != '\r' && *end != '\n')
                end++;

            len = end - v;
            if (len >= vsize)
                len = vsize - 1;
            memcpy(value, v, len);
            value[len] = '\0';
            return value;
        }

        /* Skip to next line */
        while (*p && *p != '\n')
            p++;
        if (*p == '\n')
            p++;
    }

    return NULL;
} /* ws_find_header() */

/*-------------------------------------------------------------------------*/
int
ws_continue_handshake (interactive_t *ip)

/* Continue accumulating and parsing the WebSocket HTTP upgrade request.
 *
 * The raw bytes from the client are in ip->text[0..ip->text_end-1].
 * We consume them and accumulate in ws_data.handshake_buf until we
 * see the \r\n\r\n end-of-headers marker.
 *
 * Returns:
 *   -1 on error (connection should be closed)
 *    0 still handshaking
 *    1 handshake complete, connection is now WS_ACTIVE
 */

{
    struct ws_data_s *ws = &ip->ws_data;
    size_t avail;
    size_t needed;
    char *end_of_headers;

    avail = ip->text_end;
    if (avail == 0)
        return 0;

    /* Grow the handshake buffer to hold the new data */
    needed = ws->handshake_len + avail + 1;
    if (needed > WS_MAX_HANDSHAKE_SIZE)
    {
        /* HTTP request too large */
        return -1;
    }

    if (!ws->handshake_buf)
    {
        ws->handshake_buf = xalloc(needed);
        if (!ws->handshake_buf)
            return -1;
    }
    else
    {
        char *newbuf = rexalloc(ws->handshake_buf, needed);
        if (!newbuf)
            return -1;
        ws->handshake_buf = newbuf;
    }

    memcpy(ws->handshake_buf + ws->handshake_len, ip->text, avail);
    ws->handshake_len += avail;
    ws->handshake_buf[ws->handshake_len] = '\0';

    /* Consume all input bytes */
    ip->text_end = 0;
    ip->tn_end = 0;

    /* Look for end of HTTP headers */
    end_of_headers = strstr(ws->handshake_buf, "\r\n\r\n");
    if (!end_of_headers)
        return 0;  /* Still waiting for more data */

    /* --- Parse the HTTP request --- */
    {
        char key_buf[64];
        char upgrade_buf[32];
        char connection_buf[128];
        char version_buf[8];
        char accept_key[29];
        char response[512];
        int response_len;
        char *first_line_end;

        /* Validate the request line: GET <path> HTTP/1.1\r\n */
        if (strncmp(ws->handshake_buf, "GET ", 4) != 0)
            return -1;

        first_line_end = strstr(ws->handshake_buf, "\r\n");
        if (!first_line_end)
            return -1;

        if (!strstr(ws->handshake_buf, "HTTP/1.1"))
            return -1;

        /* Validate required headers */
        if (!ws_find_header(ws->handshake_buf, "Upgrade", upgrade_buf,
                            sizeof(upgrade_buf)))
            return -1;
        if (strcasecmp(upgrade_buf, "websocket") != 0)
            return -1;

        if (!ws_find_header(ws->handshake_buf, "Connection", connection_buf,
                            sizeof(connection_buf)))
            return -1;
        /* Check that "Upgrade" appears in the Connection header value.
         * The header may contain multiple comma-separated tokens. */
        {
            Bool found = MY_FALSE;
            char *tok = connection_buf;
            while (*tok)
            {
                while (*tok == ' ' || *tok == ',')
                    tok++;
                if (strncasecmp(tok, "Upgrade", 7) == 0
                    && (tok[7] == '\0' || tok[7] == ' ' || tok[7] == ','))
                {
                    found = MY_TRUE;
                    break;
                }
                while (*tok && *tok != ',')
                    tok++;
            }
            if (!found)
                return -1;
        }

        if (!ws_find_header(ws->handshake_buf, "Sec-WebSocket-Version",
                            version_buf, sizeof(version_buf)))
            return -1;
        if (strcmp(version_buf, "13") != 0)
            return -1;

        if (!ws_find_header(ws->handshake_buf, "Sec-WebSocket-Key",
                            key_buf, sizeof(key_buf)))
            return -1;

        /* Compute the accept key */
        ws_compute_accept_key(key_buf, accept_key);

        /* Build the HTTP 101 response */
        response_len = snprintf(response, sizeof(response),
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: %s\r\n"
            "\r\n",
            accept_key);

        if (response_len < 0 || (size_t)response_len >= sizeof(response))
            return -1;

        /* Send the response directly */
        comm_socket_write(response, response_len, ip, WB_NONDISCARDABLE);

        /* Free the handshake buffer */
        xfree(ws->handshake_buf);
        ws->handshake_buf = NULL;
        ws->handshake_len = 0;

        /* Transition to active WebSocket state */
        ip->ws_status = WS_ACTIVE;
        ip->tn_enabled = MY_FALSE;

        /* Invoke the completion callback if set */
        if (ws->cb)
        {
            callback_t *cb = ws->cb;
            ws->cb = NULL;

            push_number(inter_sp, 0);  /* success */
            push_ref_object(inter_sp, ip->ob, "ws_continue_handshake");

            (void)backend_callback(cb, 2);

            free_callback(cb);
            xfree(cb);
        }

        return 1;
    }
} /* ws_continue_handshake() */

/*=========================================================================*/
/*                       Frame Encoding / Decoding                         */
/*=========================================================================*/

/*-------------------------------------------------------------------------*/
static void
ws_send_raw_frame (interactive_t *ip, unsigned char opcode,
                   const char *payload, size_t len)

/* Build and send a WebSocket frame to the client.
 * Server-to-client frames are NOT masked (per RFC 6455).
 *
 * Uses minimal payload length encoding as required by the spec.
 */

{
    unsigned char header[14];
    size_t hlen = 0;

    /* Byte 0: FIN=1, RSV=0, opcode */
    header[hlen++] = WS_FIN_BIT | (opcode & WS_OPCODE_MASK);

    /* Byte 1+: MASK=0, payload length */
    if (len <= 125)
    {
        header[hlen++] = (unsigned char)len;
    }
    else if (len <= 65535)
    {
        header[hlen++] = 126;
        header[hlen++] = (unsigned char)((len >> 8) & 0xFF);
        header[hlen++] = (unsigned char)(len & 0xFF);
    }
    else
    {
        header[hlen++] = 127;
        header[hlen++] = 0;
        header[hlen++] = 0;
        header[hlen++] = 0;
        header[hlen++] = 0;
        header[hlen++] = (unsigned char)((len >> 24) & 0xFF);
        header[hlen++] = (unsigned char)((len >> 16) & 0xFF);
        header[hlen++] = (unsigned char)((len >> 8) & 0xFF);
        header[hlen++] = (unsigned char)(len & 0xFF);
    }

    /* Build a single buffer with header + payload to send atomically.
     * Use WB_WEBSOCKET_RAW to prevent double-framing in comm_socket_write.
     */
    {
        char *frame = xalloc(hlen + len);
        if (!frame)
            return;
        memcpy(frame, header, hlen);
        if (len > 0 && payload)
            memcpy(frame + hlen, payload, len);
        comm_socket_write(frame, hlen + len, ip,
                          WB_NONDISCARDABLE | WB_WEBSOCKET_RAW);
        xfree(frame);
    }
} /* ws_send_raw_frame() */

/*-------------------------------------------------------------------------*/
static void
ws_handle_ping (interactive_t *ip, const char *data, size_t len)

/* Handle an incoming Ping frame: respond with Pong carrying the same
 * application data.
 */

{
    ws_send_raw_frame(ip, WS_OP_PONG, data, len);
} /* ws_handle_ping() */

/*-------------------------------------------------------------------------*/
static void
ws_handle_pong (interactive_t *ip UNUSED, const char *data UNUSED,
                size_t len UNUSED)

/* Handle an incoming Pong frame. Currently a no-op. */

{
    /* Could track keepalive/latency here in the future. */
} /* ws_handle_pong() */

/*-------------------------------------------------------------------------*/
static void
ws_handle_close_frame (interactive_t *ip, const char *data, size_t len)

/* Handle an incoming Close frame.
 *
 * If we haven't sent a close yet, echo the status code back.
 * Transition to WS_CLOSING.
 */

{
    if (!ip->ws_data.close_sent)
    {
        if (len >= 2)
        {
            /* Echo back the status code only */
            ws_send_close(ip, (unsigned char)data[0] << 8 | (unsigned char)data[1],
                          NULL);
        }
        else
        {
            ws_send_close(ip, WS_CLOSE_NORMAL, NULL);
        }
    }

    ip->ws_status = WS_CLOSING;
} /* ws_handle_close_frame() */

/*-------------------------------------------------------------------------*/
void
ws_send_close (interactive_t *ip, uint16_t code, const char *reason)

/* Send a Close frame with the given status <code> and optional <reason>.
 * Marks the connection as having sent a close frame.
 */

{
    char buf[WS_MAX_CONTROL_PAYLOAD];
    size_t len = 0;

    if (ip->ws_data.close_sent)
        return;

    /* Status code in network byte order */
    buf[len++] = (char)((code >> 8) & 0xFF);
    buf[len++] = (char)(code & 0xFF);

    /* Optional UTF-8 reason string (max 123 bytes to fit control frame limit) */
    if (reason)
    {
        size_t rlen = strlen(reason);
        if (rlen > WS_MAX_CONTROL_PAYLOAD - 2)
            rlen = WS_MAX_CONTROL_PAYLOAD - 2;
        memcpy(buf + len, reason, rlen);
        len += rlen;
    }

    ws_send_raw_frame(ip, WS_OP_CLOSE, buf, len);
    ip->ws_data.close_sent = MY_TRUE;

    if (ip->ws_status == WS_ACTIVE)
        ip->ws_status = WS_CLOSING;
} /* ws_send_close() */

/*-------------------------------------------------------------------------*/
void
ws_send_ping (interactive_t *ip, const char *data, size_t len)

/* Send a Ping frame with optional application data. */

{
    if (len > WS_MAX_CONTROL_PAYLOAD)
        len = WS_MAX_CONTROL_PAYLOAD;

    ws_send_raw_frame(ip, WS_OP_PING, data, len);
} /* ws_send_ping() */

/*-------------------------------------------------------------------------*/
Bool
ws_frame_output (interactive_t *ip, const char *msg, size_t len,
                 unsigned char opcode)

/* Wrap outgoing data <msg> (length <len>) in a WebSocket frame
 * and send it. Returns MY_TRUE on success.
 */

{
    ws_send_raw_frame(ip, opcode, msg, len);
    return MY_TRUE;
} /* ws_frame_output() */

/*-------------------------------------------------------------------------*/
int
ws_deframe_input (interactive_t *ip)

/* Process WebSocket-framed data from ip->text[0..ip->text_end-1].
 *
 * Parses frames, handles control frames internally, and reassembles
 * fragmented data messages.
 *
 * Returns:
 *   -1  Protocol error, connection should be closed
 *    0  No complete data message yet (still accumulating, or only
 *       control frames processed)
 *    1  Complete text message ready in ip->command[]
 *    2  Complete binary message (dispatched via H_WEBSOCKET hook)
 */

{
    struct ws_data_s *ws = &ip->ws_data;
    unsigned char *buf = (unsigned char *)ip->text;
    size_t buf_len = ip->text_end;
    size_t pos = 0;
    int result = 0;

    while (pos < buf_len)
    {
        unsigned char b0, b1;
        Bool fin;
        unsigned char opcode;
        Bool masked;
        uint64_t payload_len;
        unsigned char mask_key[4];
        size_t header_len;
        size_t frame_total;

        /* Need at least 2 bytes for the minimum frame header */
        if (pos + 2 > buf_len)
            break;

        b0 = buf[pos];
        b1 = buf[pos + 1];

        fin    = (b0 & WS_FIN_BIT) != 0;
        opcode = b0 & WS_OPCODE_MASK;
        masked = (b1 & WS_MASK_BIT) != 0;
        payload_len = b1 & WS_LEN_MASK;

        /* RSV bits must be 0 (no extensions negotiated) */
        if (b0 & (WS_RSV1_BIT | WS_RSV2_BIT | WS_RSV3_BIT))
        {
            ws_send_close(ip, WS_CLOSE_PROTOCOL_ERROR, "RSV bits set");
            return -1;
        }

        /* Client frames MUST be masked */
        if (!masked)
        {
            ws_send_close(ip, WS_CLOSE_PROTOCOL_ERROR, "Unmasked frame");
            return -1;
        }

        header_len = 2;

        /* Extended payload length */
        if (payload_len == 126)
        {
            if (pos + 4 > buf_len)
                break;  /* Incomplete header */
            payload_len = ((uint64_t)buf[pos+2] << 8) | buf[pos+3];
            header_len = 4;
        }
        else if (payload_len == 127)
        {
            if (pos + 10 > buf_len)
                break;  /* Incomplete header */
            payload_len = ((uint64_t)buf[pos+2] << 56)
                        | ((uint64_t)buf[pos+3] << 48)
                        | ((uint64_t)buf[pos+4] << 40)
                        | ((uint64_t)buf[pos+5] << 32)
                        | ((uint64_t)buf[pos+6] << 24)
                        | ((uint64_t)buf[pos+7] << 16)
                        | ((uint64_t)buf[pos+8] << 8)
                        |  (uint64_t)buf[pos+9];
            header_len = 10;

            /* MSB must be 0 */
            if (payload_len & ((uint64_t)1 << 63))
            {
                ws_send_close(ip, WS_CLOSE_PROTOCOL_ERROR, "Invalid length");
                return -1;
            }
        }

        /* Add masking key length */
        header_len += 4;  /* mask is always present (we validated above) */

        /* Check if we have the complete frame */
        frame_total = header_len + (size_t)payload_len;
        if (pos + frame_total > buf_len)
            break;  /* Incomplete frame, wait for more data */

        /* Extract masking key */
        mask_key[0] = buf[pos + header_len - 4];
        mask_key[1] = buf[pos + header_len - 3];
        mask_key[2] = buf[pos + header_len - 2];
        mask_key[3] = buf[pos + header_len - 1];

        /* Unmask the payload in place */
        {
            unsigned char *payload = buf + pos + header_len;
            size_t i;
            for (i = 0; i < (size_t)payload_len; i++)
                payload[i] ^= mask_key[i & 3];
        }

        /* --- Handle the frame by opcode --- */

        if (opcode >= 0x8)
        {
            /* Control frame */
            unsigned char *payload = buf + pos + header_len;

            /* Control frames must not be fragmented */
            if (!fin)
            {
                ws_send_close(ip, WS_CLOSE_PROTOCOL_ERROR,
                              "Fragmented control frame");
                return -1;
            }

            /* Control frames max 125 bytes */
            if (payload_len > WS_MAX_CONTROL_PAYLOAD)
            {
                ws_send_close(ip, WS_CLOSE_PROTOCOL_ERROR,
                              "Control frame too large");
                return -1;
            }

            switch (opcode)
            {
            case WS_OP_CLOSE:
                ws_handle_close_frame(ip, (char *)payload, (size_t)payload_len);
                pos += frame_total;
                /* After receiving close, stop processing */
                goto done;

            case WS_OP_PING:
                ws_handle_ping(ip, (char *)payload, (size_t)payload_len);
                break;

            case WS_OP_PONG:
                ws_handle_pong(ip, (char *)payload, (size_t)payload_len);
                break;

            default:
                ws_send_close(ip, WS_CLOSE_PROTOCOL_ERROR,
                              "Unknown control opcode");
                return -1;
            }
        }
        else
        {
            /* Data frame */
            unsigned char *payload = buf + pos + header_len;

            if (opcode == WS_OP_CONTINUATION)
            {
                /* Continuation frame: must have an active fragment */
                if (ws->frame_opcode == 0)
                {
                    ws_send_close(ip, WS_CLOSE_PROTOCOL_ERROR,
                                  "Unexpected continuation");
                    return -1;
                }
            }
            else if (opcode == WS_OP_TEXT || opcode == WS_OP_BINARY)
            {
                /* New data message; must not be mid-fragment */
                if (ws->frame_opcode != 0)
                {
                    ws_send_close(ip, WS_CLOSE_PROTOCOL_ERROR,
                                  "Interleaved data frames");
                    return -1;
                }
                ws->frame_opcode = opcode;
                ws->frame_len = 0;
            }
            else
            {
                ws_send_close(ip, WS_CLOSE_PROTOCOL_ERROR,
                              "Unknown data opcode");
                return -1;
            }

            /* Append payload to reassembly buffer */
            if (payload_len > 0)
            {
                size_t new_len = ws->frame_len + (size_t)payload_len;
                if (new_len > WS_MAX_FRAME_REASSEMBLY)
                {
                    ws_send_close(ip, WS_CLOSE_TOO_BIG, "Message too big");
                    return -1;
                }

                if (new_len > ws->frame_alloc)
                {
                    size_t new_alloc = ws->frame_alloc ? ws->frame_alloc * 2
                                                       : 4096;
                    if (new_alloc < new_len)
                        new_alloc = new_len;
                    if (new_alloc > WS_MAX_FRAME_REASSEMBLY)
                        new_alloc = WS_MAX_FRAME_REASSEMBLY;

                    if (ws->frame_buf)
                    {
                        char *newbuf = rexalloc(ws->frame_buf, new_alloc);
                        if (!newbuf)
                        {
                            ws_send_close(ip, WS_CLOSE_INTERNAL_ERROR,
                                          "Out of memory");
                            return -1;
                        }
                        ws->frame_buf = newbuf;
                    }
                    else
                    {
                        ws->frame_buf = xalloc(new_alloc);
                        if (!ws->frame_buf)
                        {
                            ws_send_close(ip, WS_CLOSE_INTERNAL_ERROR,
                                          "Out of memory");
                            return -1;
                        }
                    }
                    ws->frame_alloc = new_alloc;
                }

                memcpy(ws->frame_buf + ws->frame_len, payload,
                       (size_t)payload_len);
                ws->frame_len = new_len;
            }

            /* If this is the final fragment, deliver the message */
            if (fin)
            {
                unsigned char msg_opcode = ws->frame_opcode;
                ws->frame_opcode = 0;

                if (msg_opcode == WS_OP_TEXT)
                {
                    /* Text message: copy to ip->command[] for normal
                     * command dispatch. Truncate if necessary. */
                    size_t cmd_len = ws->frame_len;
                    if (cmd_len >= MAX_TEXT - 1)
                        cmd_len = MAX_TEXT - 2;

                    memcpy(ip->command, ws->frame_buf, cmd_len);
                    ip->command[cmd_len] = '\0';
                    ip->command_end = cmd_len;
                    ip->command_start = 0;
                    ip->command_unprocessed_end = cmd_len;
                    ws->frame_len = 0;
                    result = 1;
                }
                else /* WS_OP_BINARY */
                {
                    /* Binary message: dispatch via H_WEBSOCKET hook */
                    if (driver_hook[H_WEBSOCKET].type == T_CLOSURE)
                    {
                        string_t *data_str;

                        data_str = new_n_mstring(ws->frame_buf, ws->frame_len,
                                                 STRING_BYTES);
                        if (data_str)
                        {
                            svalue_t *ob_arg;
                            push_number(inter_sp, WS_OP_BINARY);
                            push_bytes(inter_sp, data_str);
                            push_ref_object(inter_sp, ip->ob,
                                           "ws_deframe_input");
                            ob_arg = inter_sp;

                            call_lambda_ob(&driver_hook[H_WEBSOCKET], 3,
                                          ob_arg);
                            pop_stack(); /* discard return value */
                        }
                    }
                    ws->frame_len = 0;
                    result = 2;
                }
            }
        }

        pos += frame_total;
    } /* while (pos < buf_len) */

done:
    /* Remove consumed bytes from ip->text[] */
    if (pos > 0)
    {
        if (pos < buf_len)
        {
            memmove(ip->text, ip->text + pos, buf_len - pos);
            ip->text_end = buf_len - pos;
        }
        else
        {
            ip->text_end = 0;
        }
        ip->tn_end = 0;
    }

    return result;
} /* ws_deframe_input() */

/*=========================================================================*/
/*                               Efuns                                     */
/*=========================================================================*/

/*-------------------------------------------------------------------------*/
svalue_t *
v_websocket_init_connection (svalue_t *sp, int num_arg)

/* EFUN websocket_init_connection()
 *
 *   int websocket_init_connection(object ob)
 *   int websocket_init_connection(object ob, string fun, string|object fob,
 *                                 mixed extra...)
 *   int websocket_init_connection(object ob, closure fun, mixed extra...)
 *
 * Initiate WebSocket handshake on interactive object <ob>
 * (or this_object() if <ob> is not given).
 *
 * Result:
 *   0: Handshake is in progress (will complete asynchronously).
 *  -1: Error.
 */

{
    svalue_t *argp = sp - num_arg + 1;
    object_t *obj;
    interactive_t *ip;

    if (num_arg > 0)
    {
        obj = argp->u.ob;
        put_number(argp, 0);
    }
    else
    {
        if (current_object.type != T_OBJECT)
            errorf("websocket_init_connection() for lightweight object.\n");
        obj = ref_object(current_object.u.ob, "websocket_init_connection");
    }

    if (!O_SET_INTERACTIVE(ip, obj))
    {
        free_object(obj, "websocket_init_connection");
        errorf("Bad arg 1 to websocket_init_connection(): "
              "object not interactive.\n");
    }

    free_object(obj, "websocket_init_connection");

    if (ip->ws_status != WS_INACTIVE)
        errorf("websocket_init_connection(): Connection already has "
              "WebSocket active.\n");

    /* Extract callback if provided */
    if (num_arg > 1)
    {
        int error_index;
        callback_t *cb;

        inter_sp = sp;
        assign_eval_cost();

        error_index = setup_efun_callback(&cb, argp + 1, num_arg - 1);

        if (error_index >= 0)
        {
            inter_sp = sp = argp;
            vefun_bad_arg(error_index + 2, argp);
            /* NOTREACHED */
            return argp;
        }

        ip->ws_data.cb = cb;
    }

    inter_sp = sp = argp - 1;

    /* Flush pending output */
    {
        object_t *save_c_g = command_giver;
        command_giver = obj;
        add_message_flush();
        command_giver = save_c_g;
    }

    /* Begin handshake */
    ip->ws_status = WS_HANDSHAKING;
    ip->tn_enabled = MY_FALSE;

    push_number(sp, 0);
    return sp;
} /* v_websocket_init_connection() */

/*-------------------------------------------------------------------------*/
svalue_t *
f_websocket_send (svalue_t *sp)

/* EFUN websocket_send()
 *
 *   void websocket_send(string|bytes message, int opcode)
 *
 * Send a WebSocket frame. For text (opcode WS_OP_TEXT), <message>
 * should be a string. For binary (opcode WS_OP_BINARY), <message>
 * should be a bytes value.
 *
 * If opcode is omitted or 0, it defaults to text for strings
 * and binary for bytes.
 */

{
    interactive_t *ip;
    unsigned char opcode;
    const char *data;
    size_t len;

    if (current_object.type != T_OBJECT)
        errorf("websocket_send() for lightweight object.\n");

    if (!O_SET_INTERACTIVE(ip, current_object.u.ob))
        errorf("websocket_send(): Current object is not interactive.\n");

    if (ip->ws_status != WS_ACTIVE)
        errorf("websocket_send(): WebSocket connection is not active.\n");

    /* Determine opcode */
    opcode = (unsigned char)sp->u.number;
    if (opcode == 0)
    {
        if ((sp-1)->type == T_BYTES)
            opcode = WS_OP_BINARY;
        else
            opcode = WS_OP_TEXT;
    }

    /* Get the data */
    if ((sp-1)->type == T_STRING)
    {
        data = get_txt((sp-1)->u.str);
        len = mstrsize((sp-1)->u.str);
    }
    else if ((sp-1)->type == T_BYTES)
    {
        data = get_txt((sp-1)->u.str);
        len = mstrsize((sp-1)->u.str);
    }
    else
    {
        errorf("Bad arg 1 to websocket_send(): expected string or bytes.\n");
        /* NOTREACHED */
        return sp;
    }

    ws_frame_output(ip, data, len, opcode);

    free_svalue(sp); sp--;
    free_svalue(sp); sp--;

    return sp;
} /* f_websocket_send() */

/*-------------------------------------------------------------------------*/
svalue_t *
v_websocket_close (svalue_t *sp, int num_arg)

/* EFUN websocket_close()
 *
 *   void websocket_close(int code, string reason)
 *
 * Initiate WebSocket close handshake with optional status code and reason.
 * Defaults to code 1000 (normal closure).
 */

{
    svalue_t *argp = sp - num_arg + 1;
    interactive_t *ip;
    uint16_t code = WS_CLOSE_NORMAL;
    const char *reason = NULL;

    if (current_object.type != T_OBJECT)
        errorf("websocket_close() for lightweight object.\n");

    if (!O_SET_INTERACTIVE(ip, current_object.u.ob))
        errorf("websocket_close(): Current object is not interactive.\n");

    if (ip->ws_status != WS_ACTIVE && ip->ws_status != WS_CLOSING)
        errorf("websocket_close(): WebSocket connection is not active.\n");

    if (num_arg >= 1)
        code = (uint16_t)argp[0].u.number;

    if (num_arg >= 2 && argp[1].type == T_STRING)
        reason = get_txt(argp[1].u.str);

    ws_send_close(ip, code, reason);

    /* Clean up arguments */
    sp = pop_n_elems(num_arg, sp);
    return sp;
} /* v_websocket_close() */

/*-------------------------------------------------------------------------*/
svalue_t *
f_websocket_query_state (svalue_t *sp)

/* EFUN websocket_query_state()
 *
 *   int websocket_query_state(object ob)
 *
 * Returns the WebSocket state of <ob>:
 *   WS_INACTIVE(0), WS_HANDSHAKING(1), WS_ACTIVE(2), WS_CLOSING(3)
 */

{
    interactive_t *ip;
    int state;

    if (sp->type == T_OBJECT)
    {
        if (!O_SET_INTERACTIVE(ip, sp->u.ob))
        {
            free_svalue(sp);
            put_number(sp, WS_INACTIVE);
            return sp;
        }
        state = ip->ws_status;
        free_svalue(sp);
        put_number(sp, state);
    }
    else
    {
        put_number(sp, WS_INACTIVE);
    }

    return sp;
} /* f_websocket_query_state() */

#endif /* USE_WEBSOCKETS */
