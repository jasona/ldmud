#ifndef LPC_WEBSOCKET_H_
#define LPC_WEBSOCKET_H_ 1

/* WebSocket connection states (as returned by websocket_query_state()). */
#define WS_INACTIVE     0
#define WS_HANDSHAKING  1
#define WS_ACTIVE       2
#define WS_CLOSING      3

/* WebSocket frame opcodes (for websocket_send()). */
#define WS_TEXT         1
#define WS_BINARY       2

/* WebSocket close status codes (RFC 6455 Section 7.4.1). */
#define WS_CLOSE_NORMAL           1000  /* Normal closure */
#define WS_CLOSE_GOING_AWAY       1001  /* Endpoint going away */
#define WS_CLOSE_PROTOCOL_ERROR   1002  /* Protocol error */
#define WS_CLOSE_UNSUPPORTED      1003  /* Unsupported data type */
#define WS_CLOSE_NO_STATUS        1005  /* Virtual: no status code present */
#define WS_CLOSE_ABNORMAL         1006  /* Virtual: abnormal closure */
#define WS_CLOSE_INVALID_DATA     1007  /* Invalid payload data (e.g. bad UTF-8) */
#define WS_CLOSE_POLICY           1008  /* Policy violation */
#define WS_CLOSE_TOO_BIG          1009  /* Message too big */
#define WS_CLOSE_MANDATORY_EXT    1010  /* Mandatory extension missing */
#define WS_CLOSE_INTERNAL_ERROR   1011  /* Internal server error */
#define WS_CLOSE_TLS_FAILURE      1015  /* Virtual: TLS handshake failure */

#endif /* LPC_WEBSOCKET_H_ */
