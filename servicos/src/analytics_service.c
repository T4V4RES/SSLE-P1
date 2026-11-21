#include "ssle.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

static http_response handle_readings(const http_request *request, int average) {
    int limit;
    if (parse_limit(request, &limit) != 0) return error_response(400, "limit must be an integer");

    char storage[256], target[320], err[256], message[400];
    if (service_endpoint("STORAGE_URL", "storage-service", storage, sizeof storage, err, sizeof err) != 0) {
        snprintf(message, sizeof message, "storage unavailable: %s", err);
        return error_response(503, message);
    }
    snprintf(target, sizeof target, "%s/temperatures?limit=%d", storage, limit);
    client_response response;
    if (http_send("GET", target, NULL, 2000, &response, err, sizeof err) != 0) {
        snprintf(message, sizeof message, "storage unavailable: %s", err);
        return error_response(503, message);
    }
    if (response.status != 200) {
        client_response_free(&response);
        return error_response(503, "storage unavailable: storage returned an error");
    }
    if (!average) return (http_response){200, response.body};
    cJSON *readings = cJSON_Parse(response.body);
    client_response_free(&response);
    if (!cJSON_IsArray(readings)) {
        cJSON_Delete(readings);
        return error_response(503, "storage unavailable: invalid response");
    }

    double sum = 0.0;
    int count = 0;
    const cJSON *reading;
    cJSON_ArrayForEach(reading, readings) {
        const cJSON *temperature = cJSON_GetObjectItemCaseSensitive(reading, "temperature");
        if (cJSON_IsNumber(temperature)) sum += temperature->valuedouble;
        ++count;
    }
    cJSON_Delete(readings);

    cJSON *result = cJSON_CreateObject();
    cJSON_AddNumberToObject(result, "sample_count", count);
    if (count == 0) cJSON_AddNullToObject(result, "average_temperature");
    else cJSON_AddNumberToObject(result, "average_temperature", round(sum / count * 100.0) / 100.0);
    return json_response(200, result);
}

static http_response route(const http_request *request) {
    const char *method = request->method, *path = request->path;
    if (strcmp(method, "GET") == 0 && strcmp(path, "/health") == 0) return health_response();
    if (strcmp(method, "GET") == 0 && strcmp(path, "/average") == 0) return handle_readings(request, 1);
    if (strcmp(method, "GET") == 0 && strcmp(path, "/temperatures") == 0) return handle_readings(request, 0);
    return error_response(404, "route not found");
}

int main(void) {
    const int port = env_int("PORT", 5003);
    char default_url[64];
    snprintf(default_url, sizeof default_url, "http://127.0.0.1:%d", port);
    struct MHD_Daemon *server = http_server_start((unsigned short)port, route);
    if (!server) {
        fprintf(stderr, "could not start HTTP server\n");
        return 1;
    }
    install_signal_handlers();
    if (!env_int("SSLE_DIRECT", 0) && registration_start("analytics-service",
                           env_str("INSTANCE_ID", "pt.lisbon.dc1.rack1.node3.analytics.01"),
                           env_str("SERVICE_URL", default_url)) != 0) {
        MHD_stop_daemon(server);
        return 1;
    }
    printf("Analytics service listening on port %d\n", port);
    fflush(stdout);
    wait_for_shutdown();
    registration_stop();
    MHD_stop_daemon(server);
    return 0;
}
