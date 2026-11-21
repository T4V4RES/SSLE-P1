#include "ssle.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static void usage(void) {
    fprintf(stderr, "Usage: temperature_sensor [--device-id ID] [--count N] [--interval-ms MS]\n");
}

int main(int argc, char **argv) {
    const char *device_id = env_str("DEVICE_ID",
        "pt.cidade-onde-o-meu-amigo-rhyan.dc1.rack1.sensor.temperature.002");
    int count = env_int("COUNT", 0);
    int interval_ms = env_int("INTERVAL_MS", 5000);
    const char *token_file = env_str("SENSOR_TOKEN_FILE", NULL);
    const char *certificate = env_str("SENSOR_TLS_CERT", NULL);
    const char *key = env_str("SENSOR_TLS_KEY", NULL);
    const char *ca = env_str("INGESTION_CA", NULL);
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--device-id") == 0 && i + 1 < argc) device_id = argv[++i];
        else if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) count = atoi(argv[++i]);
        else if (strcmp(argv[i], "--interval-ms") == 0 && i + 1 < argc) interval_ms = atoi(argv[++i]);
        else {
            usage();
            return 2;
        }
    }
    int authenticated = token_file || certificate;
    if ((env_int("SSLE_DIRECT", 0) && !authenticated) || (authenticated != !!ca) ||
        (!!certificate != !!key) || (certificate && token_file)) {
        fprintf(stderr, "direct sensor requires a TLS CA and either a token or a client certificate/key\n");
        return 2;
    }

    install_signal_handlers();
    srand((unsigned)time(NULL) ^ (unsigned)getpid());
    int failed = 0;
    for (int sent = 0; running && (count == 0 || sent < count); ++sent) {
        double temperature = round((20.0 + 10.0 * rand() / (double)RAND_MAX) * 100.0) / 100.0;
        cJSON *payload = cJSON_CreateObject();
        cJSON_AddStringToObject(payload, "device_id", device_id);
        cJSON_AddNumberToObject(payload, "temperature", temperature);
        char *body = cJSON_PrintUnformatted(payload);
        cJSON_Delete(payload);

        char ingestion[256], target[300], err[256];
        client_response response;
        char *token = token_file ? read_text_file(token_file, 66) : NULL;
        if (token) token[strcspn(token, "\r\n")] = '\0';
        if (token_file && (!token || strlen(token) != 64 || strspn(token, "0123456789abcdef") != 64)) {
            fprintf(stderr, "Error: invalid sensor credential file\n");
            failed = 1;
        } else if (service_endpoint("INGESTION_URL", "ingestion-service", ingestion, sizeof ingestion, err, sizeof err) != 0) {
            fprintf(stderr, "Error: %s\n", err);
            failed = 1;
        } else {
            snprintf(target, sizeof target, "%s/ingest", ingestion);
            int result = authenticated
                ? https_send(target, body, ca, token, certificate, key, &response, err, sizeof err)
                : http_send("POST", target, body, 2000, &response, err, sizeof err);
            if (result != 0) {
                fprintf(stderr, "Error: %s\n", err);
                failed = 1;
            } else {
                if (response.status < 200 || response.status >= 300) {
                    fprintf(stderr, "Error: ingestion returned HTTP %ld\n", response.status);
                    failed = 1;
                } else {
                    printf("Sent: %s\n", body);
                }
                client_response_free(&response);
            }
        }
        fflush(stdout);
        free(token);
        free(body);
        if (count == 0 || sent + 1 < count) sleep_ms(interval_ms);
    }
    return count && failed ? 1 : 0;
}
