#include "ssle.h"

#include <curl/curl.h>

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

volatile sig_atomic_t running = 1;

/* ---------- Utilities ---------- */

void sleep_ms(long ms) {
    struct timespec ts = {ms / 1000, (ms % 1000) * 1000000L};
    while (nanosleep(&ts, &ts) == -1 && errno == EINTR && running) {}
}

const char *env_str(const char *name, const char *fallback) {
    const char *value = getenv(name);
    return value && *value ? value : fallback;
}

int env_int(const char *name, int fallback) {
    const char *value = getenv(name);
    if (!value || !*value) return fallback;
    char *end;
    errno = 0;
    long parsed = strtol(value, &end, 10);
    return *end == '\0' && !errno && parsed >= INT_MIN && parsed <= INT_MAX
        ? (int)parsed : fallback;
}

const char *registry_url(void) { return env_str("REGISTRY_URL", "http://127.0.0.1:5050"); }

char *read_text_file(const char *path, size_t maximum) {
    FILE *file = fopen(path, "rb");
    if (!file) return NULL;
    char *value = malloc(maximum + 1);
    if (value) {
        size_t count = fread(value, 1, maximum, file);
        if (ferror(file) || !feof(file) || !count || memchr(value, '\0', count)) {
            free(value);
            value = NULL;
        } else {
            value[count] = '\0';
        }
    }
    fclose(file);
    return value;
}

static void stop_handler(int signal_number) {
    (void)signal_number;
    running = 0;
}

void install_signal_handlers(void) {
    signal(SIGINT, stop_handler);
    signal(SIGTERM, stop_handler);
}

void wait_for_shutdown(void) {
    install_signal_handlers();
    while (running) sleep_ms(100);
}

/* ---------- Metrics (formato de texto do Prometheus) ---------- */

static const double latency_buckets[] = {0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5};
#define LATENCY_BUCKETS (sizeof latency_buckets / sizeof latency_buckets[0])

static struct {
    pthread_mutex_t lock;
    unsigned long requests[6]; /* indice = classe do status (1..5) */
    unsigned long auth_rejections;
    unsigned long bucket[LATENCY_BUCKETS];
    unsigned long count;
    double sum;
    long inflight;
    time_t started;
} metrics = {.lock = PTHREAD_MUTEX_INITIALIZER};

static double now_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void metrics_observe(unsigned status, double seconds) {
    pthread_mutex_lock(&metrics.lock);
    metrics.requests[status / 100 <= 5 ? status / 100 : 5]++;
    if (status == 401 || status == 403) metrics.auth_rejections++;
    for (size_t i = 0; i < LATENCY_BUCKETS; ++i)
        if (seconds <= latency_buckets[i]) metrics.bucket[i]++;
    metrics.count++;
    metrics.sum += seconds;
    metrics.inflight--;
    pthread_mutex_unlock(&metrics.lock);
}

static char *metrics_text(void) {
    size_t cap = 4096, len = 0;
    char *out = malloc(cap);
    if (!out) return NULL;
    pthread_mutex_lock(&metrics.lock);
    len += snprintf(out + len, cap - len,
        "# HELP ssle_http_requests_total Pedidos HTTP atendidos, por classe de status.\n"
        "# TYPE ssle_http_requests_total counter\n");
    for (int c = 1; c <= 5; ++c)
        len += snprintf(out + len, cap - len, "ssle_http_requests_total{code=\"%dxx\"} %lu\n",
                        c, metrics.requests[c]);
    len += snprintf(out + len, cap - len,
        "# HELP ssle_http_auth_rejections_total Pedidos recusados com HTTP 401 ou 403.\n"
        "# TYPE ssle_http_auth_rejections_total counter\n"
        "ssle_http_auth_rejections_total %lu\n", metrics.auth_rejections);
    len += snprintf(out + len, cap - len,
        "# HELP ssle_http_request_duration_seconds Tempo de resposta dos pedidos HTTP.\n"
        "# TYPE ssle_http_request_duration_seconds histogram\n");
    for (size_t i = 0; i < LATENCY_BUCKETS; ++i)
        len += snprintf(out + len, cap - len,
                        "ssle_http_request_duration_seconds_bucket{le=\"%g\"} %lu\n",
                        latency_buckets[i], metrics.bucket[i]);
    len += snprintf(out + len, cap - len,
        "ssle_http_request_duration_seconds_bucket{le=\"+Inf\"} %lu\n"
        "ssle_http_request_duration_seconds_sum %.6f\n"
        "ssle_http_request_duration_seconds_count %lu\n"
        "# HELP ssle_http_inflight_requests Pedidos em processamento.\n"
        "# TYPE ssle_http_inflight_requests gauge\n"
        "ssle_http_inflight_requests %ld\n"
        "# HELP ssle_process_start_time_seconds Instante de arranque do processo.\n"
        "# TYPE ssle_process_start_time_seconds gauge\n"
        "ssle_process_start_time_seconds %ld\n",
        metrics.count, metrics.sum, metrics.count, metrics.inflight, (long)metrics.started);
    pthread_mutex_unlock(&metrics.lock);
    return out;
}

/* ---------- HTTP server ---------- */

typedef struct {
    char *body;
    size_t size;
    int answered;
    int oversized;
} connection_context;

#define MAX_HTTP_BODY (64U * 1024U)

int http_body_fits(size_t current, size_t incoming) {
    return current <= MAX_HTTP_BODY && incoming <= MAX_HTTP_BODY - current;
}

static enum MHD_Result access_callback(void *cls, struct MHD_Connection *connection,
                                       const char *url, const char *method,
                                       const char *version, const char *upload_data,
                                       size_t *upload_data_size, void **con_cls) {
    (void)version;
    http_handler handler = (http_handler)cls;
    if (*con_cls == NULL) {
        connection_context *context = calloc(1, sizeof *context);
        if (!context) return MHD_NO;
        *con_cls = context;
        return MHD_YES;
    }
    connection_context *context = *con_cls;
    if (*upload_data_size > 0) {
        if (!http_body_fits(context->size, *upload_data_size)) {
            context->oversized = 1;
            *upload_data_size = 0;
            return MHD_YES;
        }
        if (context->oversized) {
            *upload_data_size = 0;
            return MHD_YES;
        }
        char *grown = realloc(context->body, context->size + *upload_data_size + 1);
        if (!grown) return MHD_NO;
        memcpy(grown + context->size, upload_data, *upload_data_size);
        context->size += *upload_data_size;
        grown[context->size] = '\0';
        context->body = grown;
        *upload_data_size = 0;
        return MHD_YES;
    }
    if (context->answered) return MHD_YES;
    context->answered = 1;

    const char *content_type = "application/json";
    http_response response;
    if (context->oversized) {
        response = error_response(413, "request body exceeds 64 KiB");
        pthread_mutex_lock(&metrics.lock);
        metrics.inflight++;
        pthread_mutex_unlock(&metrics.lock);
        metrics_observe(413, 0);
    } else if (strcmp(method, "GET") == 0 && strcmp(url, "/metrics") == 0) {
        response.status = 200;
        response.body = metrics_text();
        content_type = "text/plain; version=0.0.4";
    } else {
        pthread_mutex_lock(&metrics.lock);
        metrics.inflight++;
        pthread_mutex_unlock(&metrics.lock);
        double start = now_seconds();
        http_request request = {method, url, context->body ? context->body : "", connection};
        response = handler(&request);
        metrics_observe(response.body ? response.status : 500, now_seconds() - start);
    }
    if (!response.body) response = error_response(500, "internal error");

    struct MHD_Response *raw = MHD_create_response_from_buffer(
        strlen(response.body), response.body, MHD_RESPMEM_MUST_FREE);
    MHD_add_response_header(raw, "Content-Type", content_type);
    enum MHD_Result result = MHD_queue_response(connection, response.status, raw);
    MHD_destroy_response(raw);
    return result;
}

static void completed_callback(void *cls, struct MHD_Connection *connection, void **con_cls,
                               enum MHD_RequestTerminationCode code) {
    (void)cls;
    (void)connection;
    (void)code;
    connection_context *context = *con_cls;
    if (context) {
        free(context->body);
        free(context);
    }
    *con_cls = NULL;
}

/* HTTP_THREADS=1 mantem o comportamento original (um pedido de cada vez).
 * Com mais threads o servico aguenta pedidos lentos em paralelo. */
struct MHD_Daemon *https_server_start(unsigned short port, http_handler handler,
                                    const char *certificate, const char *key, const char *client_ca) {
    metrics.started = time(NULL);
    int configured_threads = env_int("HTTP_THREADS", 2);
    unsigned threads = configured_threads >= 1 && configured_threads <= 32 ? configured_threads : 2;
    int configured_timeout = env_int("HTTP_TIMEOUT", 5);
    unsigned timeout = configured_timeout >= 1 && configured_timeout <= 60 ? configured_timeout : 5;
    if (certificate && key) {
        struct MHD_OptionItem trust[] = {
            {MHD_OPTION_END, 0, NULL},
            {MHD_OPTION_END, 0, NULL}
        };
        if (client_ca) trust[0] = (struct MHD_OptionItem){MHD_OPTION_HTTPS_MEM_TRUST, 0, (void *)client_ca};
        return MHD_start_daemon(MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_TLS, port, NULL, NULL,
                                access_callback, (void *)handler,
                                MHD_OPTION_NOTIFY_COMPLETED, completed_callback, NULL,
                                MHD_OPTION_THREAD_POOL_SIZE, threads,
                                MHD_OPTION_CONNECTION_TIMEOUT, timeout,
                                MHD_OPTION_CONNECTION_LIMIT, (unsigned int)128,
                                MHD_OPTION_HTTPS_MEM_CERT, certificate,
                                MHD_OPTION_HTTPS_MEM_KEY, key,
                                MHD_OPTION_ARRAY, trust,
                                MHD_OPTION_HTTPS_PRIORITIES, "NORMAL:-VERS-ALL:+VERS-TLS1.3:+VERS-TLS1.2",
                                MHD_OPTION_END);
    }
    return MHD_start_daemon(MHD_USE_INTERNAL_POLLING_THREAD, port, NULL, NULL,
                            access_callback, (void *)handler,
                            MHD_OPTION_NOTIFY_COMPLETED, completed_callback, NULL,
                            MHD_OPTION_THREAD_POOL_SIZE, threads > 0 ? threads : 1,
                            MHD_OPTION_CONNECTION_TIMEOUT, timeout,
                            MHD_OPTION_CONNECTION_LIMIT, (unsigned int)128,
                            MHD_OPTION_END);
}

struct MHD_Daemon *http_server_start(unsigned short port, http_handler handler) {
    return https_server_start(port, handler, NULL, NULL, NULL);
}

const char *http_query(const http_request *request, const char *name) {
    return MHD_lookup_connection_value(request->connection, MHD_GET_ARGUMENT_KIND, name);
}

http_response json_response(unsigned status, cJSON *value) {
    http_response response = {status, cJSON_PrintUnformatted(value)};
    cJSON_Delete(value);
    return response;
}

http_response error_response(unsigned status, const char *message) {
    cJSON *value = cJSON_CreateObject();
    cJSON_AddStringToObject(value, "error", message);
    return json_response(status, value);
}

http_response health_response(void) {
    cJSON *value = cJSON_CreateObject();
    cJSON_AddStringToObject(value, "status", "ok");
    return json_response(200, value);
}

int parse_limit(const http_request *request, int *limit) {
    const char *text = http_query(request, "limit");
    *limit = 1000;
    if (!text) return 0;
    char *end;
    errno = 0;
    long parsed = strtol(text, &end, 10);
    if (*text == '\0' || *end != '\0' || errno) return -1;
    if (parsed < 1) parsed = 1;
    if (parsed > 10000) parsed = 10000;
    *limit = (int)parsed;
    return 0;
}

/* ---------- HTTP client ---------- */

static pthread_once_t curl_once = PTHREAD_ONCE_INIT;
static void curl_init(void) { curl_global_init(CURL_GLOBAL_DEFAULT); }

typedef struct {
    char *data;
    size_t size;
} buffer;

static size_t append_response(char *data, size_t size, size_t count, void *target) {
    buffer *out = target;
    if (size && count > SIZE_MAX / size) return 0;
    size_t bytes = size * count;
    if (out->size > 1024U * 1024U || bytes > 1024U * 1024U - out->size) return 0;
    char *grown = realloc(out->data, out->size + bytes + 1);
    if (!grown) return 0;
    memcpy(grown + out->size, data, bytes);
    out->size += bytes;
    grown[out->size] = '\0';
    out->data = grown;
    return bytes;
}

static int send_request(const char *method, const char *url, const char *body, long timeout_ms,
                        const char *ca, const char *token, const char *certificate, const char *key,
                        client_response *out,
                        char *err, size_t err_len) {
    pthread_once(&curl_once, curl_init);
    out->status = 0;
    out->body = NULL;
    CURL *curl = curl_easy_init();
    if (!curl) {
        snprintf(err, err_len, "could not initialize HTTP client");
        return -1;
    }
    buffer received = {NULL, 0};
    struct curl_slist *headers = curl_slist_append(NULL, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, ca ? "https" : "http,https");
    if (ca) curl_easy_setopt(curl, CURLOPT_CAINFO, ca);
    if (certificate) {
        curl_easy_setopt(curl, CURLOPT_SSLCERT, certificate);
        curl_easy_setopt(curl, CURLOPT_SSLKEY, key);
    }
    if (token) {
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BEARER);
        curl_easy_setopt(curl, CURLOPT_XOAUTH2_BEARER, token);
    }
    curl_easy_setopt(curl, CURLOPT_PROXY, "");
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout_ms);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, append_response);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &received);
    if (body && *body) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(body));
    }
    CURLcode code = curl_easy_perform(curl);
    int result = 0;
    if (code != CURLE_OK) {
        snprintf(err, err_len, "%s", curl_easy_strerror(code));
        free(received.data);
        result = -1;
    } else {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &out->status);
        out->body = received.data ? received.data : strdup("");
    }
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return result;
}

int http_send(const char *method, const char *url, const char *body, long timeout_ms,
              client_response *out, char *err, size_t err_len) {
    return send_request(method, url, body, timeout_ms, NULL, NULL, NULL, NULL, out, err, err_len);
}

int https_send(const char *url, const char *body, const char *ca, const char *token,
               const char *certificate, const char *key,
               client_response *out, char *err, size_t err_len) {
    return send_request("POST", url, body, 2000, ca, token, certificate, key, out, err, err_len);
}

void client_response_free(client_response *response) {
    free(response->body);
    response->body = NULL;
}

/* ---------- Discovery ---------- */

int service_endpoint(const char *variable, const char *name, char *url, size_t url_len,
                     char *err, size_t err_len) {
    const char *direct = env_str(variable, NULL);
    if (!direct && !env_int("SSLE_DIRECT", 0)) return discover(name, url, url_len, err, err_len);
    if (!direct || strlen(direct) >= url_len) {
        snprintf(err, err_len, "invalid configuration for %s", variable);
        return -1;
    }
    strcpy(url, direct);
    return 0;
}

int discover(const char *name, char *url, size_t url_len, char *err, size_t err_len) {
    char target[512];
    snprintf(target, sizeof target, "%s/services/%s", registry_url(), name);
    client_response response;
    if (http_send("GET", target, NULL, 2000, &response, err, err_len) != 0) return -1;
    if (response.status != 200) {
        snprintf(err, err_len, "service not found: %s", name);
        client_response_free(&response);
        return -1;
    }
    cJSON *json = cJSON_Parse(response.body);
    client_response_free(&response);
    const cJSON *found = cJSON_GetObjectItemCaseSensitive(json, "url");
    if (!cJSON_IsString(found)) {
        snprintf(err, err_len, "registry returned no URL");
        cJSON_Delete(json);
        return -1;
    }
    snprintf(url, url_len, "%s", found->valuestring);
    cJSON_Delete(json);
    return 0;
}

/* ---------- Registration ---------- */

static struct {
    char name[128];
    char instance_id[256];
    char url[256];
    pthread_t heartbeat;
    int active;
} registration;

static int send_registration(char *err, size_t err_len) {
    char health[300];
    snprintf(health, sizeof health, "%s/health", registration.url);
    cJSON *payload = cJSON_CreateObject();
    cJSON_AddStringToObject(payload, "name", registration.name);
    cJSON_AddStringToObject(payload, "instance_id", registration.instance_id);
    cJSON_AddStringToObject(payload, "url", registration.url);
    cJSON_AddStringToObject(payload, "health_url", health);
    char *body = cJSON_PrintUnformatted(payload);
    cJSON_Delete(payload);

    char target[512];
    snprintf(target, sizeof target, "%s/register", registry_url());
    client_response response;
    int result = http_send("POST", target, body, 2000, &response, err, err_len);
    free(body);
    if (result != 0) return -1;
    if (response.status != 200) {
        snprintf(err, err_len, "HTTP %ld", response.status);
        result = -1;
    }
    client_response_free(&response);
    return result;
}

static void *heartbeat_loop(void *unused) {
    (void)unused;
    const long interval_ms = env_int("REGISTER_INTERVAL", 10) * 1000L;
    char err[256];
    while (running) {
        for (long waited = 0; running && waited < interval_ms; waited += 100) sleep_ms(100);
        if (running && send_registration(err, sizeof err) != 0)
            fprintf(stderr, "re-registration failed: %s\n", err);
    }
    return NULL;
}

int registration_start(const char *name, const char *instance_id, const char *url) {
    snprintf(registration.name, sizeof registration.name, "%s", name);
    snprintf(registration.instance_id, sizeof registration.instance_id, "%s", instance_id);
    snprintf(registration.url, sizeof registration.url, "%s", url);
    char err[256] = "";
    for (int attempt = 0; attempt < 20; ++attempt) {
        if (send_registration(err, sizeof err) == 0) {
            registration.active = 1;
            pthread_create(&registration.heartbeat, NULL, heartbeat_loop, NULL);
            return 0;
        }
        sleep_ms(250);
    }
    fprintf(stderr, "registration failed: %s\n", err);
    return -1;
}

void registration_stop(void) {
    if (!registration.active) return;
    running = 0;
    pthread_join(registration.heartbeat, NULL);
    registration.active = 0;

    cJSON *payload = cJSON_CreateObject();
    cJSON_AddStringToObject(payload, "name", registration.name);
    cJSON_AddStringToObject(payload, "instance_id", registration.instance_id);
    char *body = cJSON_PrintUnformatted(payload);
    cJSON_Delete(payload);
    char target[512], err[256];
    snprintf(target, sizeof target, "%s/unregister", registry_url());
    client_response response;
    if (http_send("DELETE", target, body, 500, &response, err, sizeof err) == 0)
        client_response_free(&response);
    free(body);
}
