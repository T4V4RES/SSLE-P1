#ifndef SSLE_H
#define SSLE_H

#include <cjson/cJSON.h>
#include <microhttpd.h>

#include <signal.h>
#include <stddef.h>

/* ---------- HTTP server ---------- */

typedef struct {
    const char *method;
    const char *path;
    const char *body;
    struct MHD_Connection *connection;
} http_request;

typedef struct {
    unsigned status;
    char *body; /* malloc'd, freed by the server */
} http_response;

typedef http_response (*http_handler)(const http_request *request);

struct MHD_Daemon *http_server_start(unsigned short port, http_handler handler);
struct MHD_Daemon *https_server_start(unsigned short port, http_handler handler,
                                    const char *certificate, const char *key, const char *client_ca);
int http_body_fits(size_t current, size_t incoming);
const char *http_query(const http_request *request, const char *name);

/* json_response takes ownership of value and deletes it. */
http_response json_response(unsigned status, cJSON *value);
http_response error_response(unsigned status, const char *message);
http_response health_response(void);

/* Parses ?limit=N (default 1000, clamped to 1..10000). Returns 0 on success. */
int parse_limit(const http_request *request, int *limit);

/* ---------- HTTP client ---------- */

typedef struct {
    long status;
    char *body; /* malloc'd, release with client_response_free */
} client_response;

/* Returns 0 on success; on failure writes a message into err. */
int http_send(const char *method, const char *url, const char *body, long timeout_ms,
              client_response *out, char *err, size_t err_len);
int https_send(const char *url, const char *body, const char *ca, const char *token,
               const char *certificate, const char *key,
               client_response *out, char *err, size_t err_len);
void client_response_free(client_response *response);

/* ---------- Configuration and discovery ---------- */

const char *env_str(const char *name, const char *fallback);
int env_int(const char *name, int fallback);
char *read_text_file(const char *path, size_t maximum);
int service_endpoint(const char *variable, const char *name, char *url, size_t url_len,
                     char *err, size_t err_len);
const char *registry_url(void);

/* Asks the registry for an instance of name. Returns 0 and fills url on success. */
int discover(const char *name, char *url, size_t url_len, char *err, size_t err_len);

/* Registers with the registry (with retries) and keeps re-registering in the
 * background, so instances reappear if the registry restarts. Returns 0 on success. */
int registration_start(const char *name, const char *instance_id, const char *url);
void registration_stop(void);

/* ---------- Lifecycle ---------- */

extern volatile sig_atomic_t running;
void install_signal_handlers(void);
void wait_for_shutdown(void);
void sleep_ms(long ms);

#endif
