#include "ssle.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

static sqlite3 *database;
static pthread_mutex_t database_mutex = PTHREAD_MUTEX_INITIALIZER;

static int initialize_database(void) {
    const char *path = env_str("TEMP_DB", "temp_data.db");
    if (sqlite3_open(path, &database) != SQLITE_OK) {
        fprintf(stderr, "could not open database %s\n", path);
        return -1;
    }
    sqlite3_busy_timeout(database, 2000);
    const char *sql =
        "CREATE TABLE IF NOT EXISTS temperatures ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT NOT NULL, "
        "temperature REAL NOT NULL, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)";
    char *error = NULL;
    if (sqlite3_exec(database, sql, NULL, NULL, &error) != SQLITE_OK) {
        fprintf(stderr, "%s\n", error ? error : "database error");
        sqlite3_free(error);
        return -1;
    }
    return 0;
}

static http_response handle_store(const http_request *request) {
    cJSON *data = cJSON_Parse(request->body);
    if (!data) return error_response(400, "invalid JSON");
    const cJSON *device = cJSON_GetObjectItemCaseSensitive(data, "device_id");
    const cJSON *temperature = cJSON_GetObjectItemCaseSensitive(data, "temperature");
    if (!cJSON_IsString(device) || device->valuestring[0] == '\0') {
        cJSON_Delete(data);
        return error_response(400, "device_id must be a non-empty string");
    }
    if (!cJSON_IsNumber(temperature)) {
        cJSON_Delete(data);
        return error_response(400, "temperature must be numeric");
    }

    pthread_mutex_lock(&database_mutex);
    sqlite3_stmt *statement = NULL;
    sqlite3_prepare_v2(database, "INSERT INTO temperatures (device_id, temperature) VALUES (?, ?)",
                       -1, &statement, NULL);
    sqlite3_bind_text(statement, 1, device->valuestring, -1, SQLITE_TRANSIENT);
    sqlite3_bind_double(statement, 2, temperature->valuedouble);
    int ok = sqlite3_step(statement) == SQLITE_DONE;
    sqlite3_finalize(statement);
    sqlite3_int64 id = sqlite3_last_insert_rowid(database);
    pthread_mutex_unlock(&database_mutex);
    cJSON_Delete(data);
    if (!ok) return error_response(500, "could not store reading");

    cJSON *result = cJSON_CreateObject();
    cJSON_AddStringToObject(result, "status", "stored");
    cJSON_AddNumberToObject(result, "id", (double)id);
    return json_response(201, result);
}

static http_response handle_list(const http_request *request) {
    int limit;
    if (parse_limit(request, &limit) != 0) return error_response(400, "limit must be an integer");

    cJSON *rows = cJSON_CreateArray();
    pthread_mutex_lock(&database_mutex);
    sqlite3_stmt *statement = NULL;
    sqlite3_prepare_v2(database,
                       "SELECT id, device_id, temperature, timestamp FROM temperatures "
                       "ORDER BY id DESC LIMIT ?",
                       -1, &statement, NULL);
    sqlite3_bind_int(statement, 1, limit);
    while (sqlite3_step(statement) == SQLITE_ROW) {
        cJSON *row = cJSON_CreateObject();
        cJSON_AddNumberToObject(row, "id", (double)sqlite3_column_int64(statement, 0));
        cJSON_AddStringToObject(row, "device_id", (const char *)sqlite3_column_text(statement, 1));
        cJSON_AddNumberToObject(row, "temperature", sqlite3_column_double(statement, 2));
        cJSON_AddStringToObject(row, "timestamp", (const char *)sqlite3_column_text(statement, 3));
        cJSON_AddItemToArray(rows, row);
    }
    sqlite3_finalize(statement);
    pthread_mutex_unlock(&database_mutex);
    return json_response(200, rows);
}

static http_response route(const http_request *request) {
    const char *method = request->method, *path = request->path;
    if (strcmp(method, "GET") == 0 && strcmp(path, "/health") == 0) return health_response();
    if (strcmp(method, "POST") == 0 && strcmp(path, "/store") == 0) return handle_store(request);
    if (strcmp(method, "GET") == 0 && strcmp(path, "/temperatures") == 0)
        return handle_list(request);
    return error_response(404, "route not found");
}

int main(void) {
    if (initialize_database() != 0) return 1;
    const int port = env_int("PORT", 5002);
    char default_url[64];
    snprintf(default_url, sizeof default_url, "http://127.0.0.1:%d", port);
    struct MHD_Daemon *server = http_server_start((unsigned short)port, route);
    if (!server) {
        fprintf(stderr, "could not start HTTP server\n");
        return 1;
    }
    install_signal_handlers();
    if (!env_int("SSLE_DIRECT", 0) && registration_start("storage-service",
                           env_str("INSTANCE_ID", "pt.lisbon.dc1.rack1.node2.storage.01"),
                           env_str("SERVICE_URL", default_url)) != 0) {
        MHD_stop_daemon(server);
        return 1;
    }
    printf("Storage service listening on port %d\n", port);
    fflush(stdout);
    wait_for_shutdown();
    registration_stop();
    MHD_stop_daemon(server);
    sqlite3_close(database);
    return 0;
}
