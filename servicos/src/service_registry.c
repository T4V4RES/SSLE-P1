#include "ssle.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_ENTRIES 256
#define MAX_SERVICES 64

typedef struct {
    int used;
    char name[128];
    char instance_id[256];
    char url[256];
    char health_url[300];
    char registered_at[32];
} entry;

typedef struct {
    char name[128];
    size_t next;
} round_robin;

static entry entries[MAX_ENTRIES];
static round_robin counters[MAX_SERVICES];
static pthread_mutex_t entries_mutex = PTHREAD_MUTEX_INITIALIZER;

static void timestamp(char *out, size_t len) {
    time_t now = time(NULL);
    struct tm utc;
    gmtime_r(&now, &utc);
    strftime(out, len, "%Y-%m-%dT%H:%M:%SZ", &utc);
}

static cJSON *entry_json(const entry *e) {
    cJSON *value = cJSON_CreateObject();
    cJSON_AddStringToObject(value, "instance_id", e->instance_id);
    cJSON_AddStringToObject(value, "url", e->url);
    cJSON_AddStringToObject(value, "health_url", e->health_url);
    cJSON_AddStringToObject(value, "registered_at", e->registered_at);
    return value;
}

/* Caller holds entries_mutex. */
static entry *find_entry(const char *name, const char *instance_id) {
    for (int i = 0; i < MAX_ENTRIES; ++i)
        if (entries[i].used && strcmp(entries[i].name, name) == 0 &&
            strcmp(entries[i].instance_id, instance_id) == 0)
            return &entries[i];
    return NULL;
}

/* Caller holds entries_mutex. */
static round_robin *counter_for(const char *name) {
    for (int i = 0; i < MAX_SERVICES; ++i)
        if (strcmp(counters[i].name, name) == 0) return &counters[i];
    for (int i = 0; i < MAX_SERVICES; ++i)
        if (counters[i].name[0] == '\0') {
            snprintf(counters[i].name, sizeof counters[i].name, "%s", name);
            return &counters[i];
        }
    return &counters[0];
}

static const char *string_field(const cJSON *json, const char *field) {
    const cJSON *value = cJSON_GetObjectItemCaseSensitive(json, field);
    return cJSON_IsString(value) && value->valuestring[0] ? value->valuestring : NULL;
}

static http_response handle_register(const http_request *request) {
    cJSON *data = cJSON_Parse(request->body);
    if (!data) return error_response(400, "invalid JSON");
    const char *name = string_field(data, "name");
    const char *id = string_field(data, "instance_id");
    const char *url = string_field(data, "url");
    if (!name || !id || !url) {
        cJSON_Delete(data);
        return error_response(400, "name, instance_id and url are required");
    }
    const char *health = string_field(data, "health_url");

    pthread_mutex_lock(&entries_mutex);
    entry *e = find_entry(name, id);
    if (!e) {
        for (int i = 0; i < MAX_ENTRIES && !e; ++i)
            if (!entries[i].used) e = &entries[i];
        if (e) {
            memset(e, 0, sizeof *e);
            e->used = 1;
            snprintf(e->name, sizeof e->name, "%s", name);
            snprintf(e->instance_id, sizeof e->instance_id, "%s", id);
            timestamp(e->registered_at, sizeof e->registered_at);
        }
    }
    if (!e) {
        pthread_mutex_unlock(&entries_mutex);
        cJSON_Delete(data);
        return error_response(507, "registry is full");
    }
    snprintf(e->url, sizeof e->url, "%s", url);
    if (health) snprintf(e->health_url, sizeof e->health_url, "%s", health);
    else snprintf(e->health_url, sizeof e->health_url, "%s/health", url);
    cJSON *service = entry_json(e);
    pthread_mutex_unlock(&entries_mutex);

    char message[300];
    snprintf(message, sizeof message, "%s registered", id);
    cJSON_Delete(data);
    cJSON *result = cJSON_CreateObject();
    cJSON_AddStringToObject(result, "message", message);
    cJSON_AddItemToObject(result, "service", service);
    return json_response(200, result);
}

static http_response handle_unregister(const http_request *request) {
    cJSON *data = cJSON_Parse(request->body);
    if (!data) return error_response(400, "invalid JSON");
    const char *name = string_field(data, "name");
    const char *id = string_field(data, "instance_id");
    pthread_mutex_lock(&entries_mutex);
    entry *e = name && id ? find_entry(name, id) : NULL;
    if (e) e->used = 0;
    pthread_mutex_unlock(&entries_mutex);
    if (!e) {
        cJSON_Delete(data);
        return error_response(404, "service instance not found");
    }
    char message[300];
    snprintf(message, sizeof message, "%s unregistered", id);
    cJSON_Delete(data);
    cJSON *result = cJSON_CreateObject();
    cJSON_AddStringToObject(result, "message", message);
    return json_response(200, result);
}

static http_response handle_list(void) {
    cJSON *result = cJSON_CreateObject();
    pthread_mutex_lock(&entries_mutex);
    for (int i = 0; i < MAX_ENTRIES; ++i) {
        if (!entries[i].used) continue;
        cJSON *group = cJSON_GetObjectItemCaseSensitive(result, entries[i].name);
        if (!group) group = cJSON_AddArrayToObject(result, entries[i].name);
        cJSON_AddItemToArray(group, entry_json(&entries[i]));
    }
    pthread_mutex_unlock(&entries_mutex);
    return json_response(200, result);
}

static http_response handle_lookup(const char *name) {
    pthread_mutex_lock(&entries_mutex);
    const entry *matches[MAX_ENTRIES];
    size_t count = 0;
    for (int i = 0; i < MAX_ENTRIES; ++i)
        if (entries[i].used && strcmp(entries[i].name, name) == 0) matches[count++] = &entries[i];
    if (count == 0) {
        pthread_mutex_unlock(&entries_mutex);
        return error_response(404, "service not found");
    }
    round_robin *counter = counter_for(name);
    cJSON *selected = entry_json(matches[counter->next++ % count]);
    pthread_mutex_unlock(&entries_mutex);
    return json_response(200, selected);
}

static http_response route(const http_request *request) {
    const char *method = request->method, *path = request->path;
    if (strcmp(method, "GET") == 0 && strcmp(path, "/health") == 0) return health_response();
    if (strcmp(method, "POST") == 0 && strcmp(path, "/register") == 0)
        return handle_register(request);
    if (strcmp(method, "DELETE") == 0 && strcmp(path, "/unregister") == 0)
        return handle_unregister(request);
    if (strcmp(method, "GET") == 0 && strcmp(path, "/services") == 0) return handle_list();
    const char *prefix = "/services/";
    if (strcmp(method, "GET") == 0 && strncmp(path, prefix, strlen(prefix)) == 0)
        return handle_lookup(path + strlen(prefix));
    return error_response(404, "route not found");
}

typedef struct {
    char name[128];
    char instance_id[256];
    char health_url[300];
} candidate;

static void *health_loop(void *unused) {
    (void)unused;
    const long interval_ms = env_int("HEALTH_INTERVAL", 5) * 1000L;
    static candidate candidates[MAX_ENTRIES];
    char err[256];
    while (running) {
        for (long waited = 0; running && waited < interval_ms; waited += 100) sleep_ms(100);
        if (!running) break;

        size_t count = 0;
        pthread_mutex_lock(&entries_mutex);
        for (int i = 0; i < MAX_ENTRIES; ++i) {
            if (!entries[i].used) continue;
            memcpy(candidates[count].name, entries[i].name, sizeof candidates[count].name);
            memcpy(candidates[count].instance_id, entries[i].instance_id,
                   sizeof candidates[count].instance_id);
            memcpy(candidates[count].health_url, entries[i].health_url,
                   sizeof candidates[count].health_url);
            ++count;
        }
        pthread_mutex_unlock(&entries_mutex);

        for (size_t i = 0; i < count; ++i) {
            client_response response;
            int healthy = http_send("GET", candidates[i].health_url, NULL, 1000, &response,
                                    err, sizeof err) == 0;
            if (healthy) {
                healthy = response.status < 400;
                client_response_free(&response);
            }
            if (healthy) continue;
            pthread_mutex_lock(&entries_mutex);
            entry *e = find_entry(candidates[i].name, candidates[i].instance_id);
            if (e) e->used = 0;
            pthread_mutex_unlock(&entries_mutex);
            printf("Removed unhealthy instance %s\n", candidates[i].instance_id);
            fflush(stdout);
        }
    }
    return NULL;
}

int main(void) {
    const int port = env_int("PORT", 5050);
    struct MHD_Daemon *server = http_server_start((unsigned short)port, route);
    if (!server) {
        fprintf(stderr, "could not start HTTP server\n");
        return 1;
    }
    install_signal_handlers();
    pthread_t checker;
    pthread_create(&checker, NULL, health_loop, NULL);
    printf("Service registry listening on port %d\n", port);
    fflush(stdout);
    wait_for_shutdown();
    pthread_join(checker, NULL);
    MHD_stop_daemon(server);
    return 0;
}
