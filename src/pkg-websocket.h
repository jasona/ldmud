#ifndef PKG_WEBSOCKET_H__
#define PKG_WEBSOCKET_H__ 1

#include "driver.h"

#ifdef USE_WEBSOCKETS

#include "typedefs.h"

/* --- WebSocket Connection States --- */

#define WS_INACTIVE      0  /* Not a WebSocket connection */
#define WS_HANDSHAKING   1  /* Parsing HTTP upgrade request */
#define WS_ACTIVE        2  /* WebSocket framing is active */
#define WS_CLOSING       3  /* Close handshake in progress */

/* --- WebSocket Frame Opcodes (RFC 6455 Section 5.2) --- */

#define WS_OP_CONTINUATION 0x0
#define WS_OP_TEXT         0x1
#define WS_OP_BINARY       0x2
#define WS_OP_CLOSE        0x8
#define WS_OP_PING         0x9
#define WS_OP_PONG         0xA

/* --- WebSocket Close Status Codes (RFC 6455 Section 7.4.1) --- */

#define WS_CLOSE_NORMAL           1000
#define WS_CLOSE_GOING_AWAY       1001
#define WS_CLOSE_PROTOCOL_ERROR   1002
#define WS_CLOSE_UNSUPPORTED      1003
#define WS_CLOSE_INVALID_DATA     1007
#define WS_CLOSE_POLICY           1008
#define WS_CLOSE_TOO_BIG          1009
#define WS_CLOSE_MANDATORY_EXT    1010
#define WS_CLOSE_INTERNAL_ERROR   1011

/* --- Frame Format Constants --- */

#define WS_FIN_BIT    0x80
#define WS_RSV1_BIT   0x40
#define WS_RSV2_BIT   0x20
#define WS_RSV3_BIT   0x10
#define WS_OPCODE_MASK 0x0F
#define WS_MASK_BIT   0x80
#define WS_LEN_MASK   0x7F

#define WS_MAX_CONTROL_PAYLOAD 125
#define WS_MAX_HANDSHAKE_SIZE  8192  /* Max HTTP upgrade request size */
#define WS_MAX_FRAME_REASSEMBLY (1024 * 1024)  /* 1MB max message size */

/* --- Per-Connection WebSocket Data --- */

struct ws_data_s
{
    char      *handshake_buf;    /* Accumulates HTTP request during handshake */
    size_t     handshake_len;    /* Current length in handshake_buf */

    char      *frame_buf;        /* Reassembly buffer for fragmented messages */
    size_t     frame_len;        /* Current data length in frame_buf */
    size_t     frame_alloc;      /* Allocated size of frame_buf */
    unsigned char frame_opcode;  /* Opcode from first fragment */

    char      *subprotocol;      /* Negotiated subprotocol (xalloc'd, or NULL) */
    CBool      text_mode;        /* Default outgoing type: TRUE=text, FALSE=binary */
    CBool      close_sent;       /* TRUE if we already sent a close frame */
    callback_t *cb;              /* Handshake completion callback (like tls_cb) */
};

/* --- Prototypes --- */

extern void ws_init_data(struct ws_data_s *ws);
extern void ws_cleanup(interactive_t *ip);
extern int  ws_continue_handshake(interactive_t *ip);
extern int  ws_deframe_input(interactive_t *ip);
extern Bool ws_frame_output(interactive_t *ip, const char *msg, size_t len,
                            unsigned char opcode);
extern void ws_send_close(interactive_t *ip, uint16_t code, const char *reason);
extern void ws_send_ping(interactive_t *ip, const char *data, size_t len);

/* --- Efun Prototypes --- */

extern svalue_t *v_websocket_init_connection(svalue_t *sp, int num_arg);
extern svalue_t *f_websocket_send(svalue_t *sp);
extern svalue_t *v_websocket_close(svalue_t *sp, int num_arg);
extern svalue_t *f_websocket_query_state(svalue_t *sp);

#endif /* USE_WEBSOCKETS */

#endif /* PKG_WEBSOCKET_H__ */
