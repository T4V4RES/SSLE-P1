#include "ssle.h"

#include <arpa/inet.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <math.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>

static const char *keys_dir;

#define CERT_PREFIX "x509:"

static int valid_device_id(const char *id) {
    size_t length = strlen(id);
    if (!length || length > 128 || id[0] == '.' || id[length - 1] == '.') return 0;
    return strspn(id, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.") == length;
}

static const char *bearer_token(const http_request *request) {
    const char *header = MHD_lookup_connection_value(request->connection, MHD_HEADER_KIND, "Authorization");
    if (!header || strncasecmp(header, "Bearer ", 7) != 0) return NULL;
    const char *token = header + 7;
    return strlen(token) == 64 && strspn(token, "0123456789abcdef") == 64 ? token : NULL;
}

static int authorize(const http_request *request, const char *id) {
    const union MHD_ConnectionInfo *tls =
        MHD_get_connection_info(request->connection, MHD_CONNECTION_INFO_GNUTLS_SESSION);
    gnutls_session_t session = tls ? tls->tls_session : NULL;
    const gnutls_datum_t *peer = session ? gnutls_certificate_get_peers(session, NULL) : NULL;
    const char *token = peer ? NULL : bearer_token(request);
    if (!peer && !token) return 401;

    char path[512];
    if (snprintf(path, sizeof path, "%s/%s", keys_dir, id) >= (int)sizeof path) return 500;
    char *expected = read_text_file(path, 72);
    if (!expected) return 403;
    expected[strcspn(expected, "\r\n")] = '\0';
    int certificate_id = strncmp(expected, CERT_PREFIX, sizeof CERT_PREFIX - 1) == 0;
    if (certificate_id != !!peer) {
        free(expected);
        return 403;
    }

    unsigned char digest[SHA256_DIGEST_LENGTH];
    char hash[2 * SHA256_DIGEST_LENGTH + 1];
    if (peer) {
        char client_oid[] = GNUTLS_KP_TLS_WWW_CLIENT;
        gnutls_typed_vdata_st purpose = {
            GNUTLS_DT_KEY_PURPOSE_OID, (unsigned char *)client_oid, 0
        };
        unsigned int status;
        if (gnutls_certificate_verify_peers(session, &purpose, 1, &status) < 0 || status != 0) {
            free(expected);
            return 403;
        }
        SHA256(peer[0].data, peer[0].size, digest);
    } else {
        SHA256((const unsigned char *)token, 64, digest);
    }
    for (size_t i = 0; i < sizeof digest; ++i) snprintf(hash + 2 * i, 3, "%02x", digest[i]);
    const char *fingerprint = expected + (certificate_id ? sizeof CERT_PREFIX - 1 : 0);
    int matching = strlen(fingerprint) == sizeof hash - 1 &&
                   CRYPTO_memcmp(fingerprint, hash, sizeof hash - 1) == 0;
    free(expected);
    return matching ? 0 : 403;
}

/* Regista cada recusa com o IP de origem. O agente Wazuh dos nós K3s lê esta
 * linha no log do contentor e bloqueia a origem que insiste (regra 100247). */
static void log_rejection(const http_request *request, int status, const char *device) {
    char address[INET6_ADDRSTRLEN] = "-";
    const union MHD_ConnectionInfo *info =
        MHD_get_connection_info(request->connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS);
    const struct sockaddr *peer = info ? info->client_addr : NULL;
    if (peer && peer->sa_family == AF_INET) {
        inet_ntop(AF_INET, &((const struct sockaddr_in *)peer)->sin_addr, address, sizeof address);
    } else if (peer && peer->sa_family == AF_INET6) {
        const struct in6_addr *ip6 = &((const struct sockaddr_in6 *)peer)->sin6_addr;
        if (IN6_IS_ADDR_V4MAPPED(ip6)) inet_ntop(AF_INET, &ip6->s6_addr[12], address, sizeof address);
        else inet_ntop(AF_INET6, ip6, address, sizeof address);
    }
    fprintf(stderr, "ssle-ingestion: auth_reject status=%d client=%s device=%s\n",
            status, address, valid_device_id(device) ? device : "invalid");
}

static http_response handle_ingest(const http_request *request) {
    cJSON *data = cJSON_Parse(request->body);
    if (!data) return error_response(400, "invalid JSON");
    const cJSON *device = cJSON_GetObjectItemCaseSensitive(data, "device_id");
    const cJSON *temperature = cJSON_GetObjectItemCaseSensitive(data, "temperature");
    int device_ok = cJSON_IsString(device) && device->valuestring[0] != '\0';
    int temperature_ok = cJSON_IsNumber(temperature) && isfinite(temperature->valuedouble);
    int status = 0;
    if (keys_dir && device_ok && temperature_ok)
        status = valid_device_id(device->valuestring) ? authorize(request, device->valuestring) : 400;
    if (status == 400 || status == 401 || status == 403) log_rejection(request, status, device->valuestring);
    cJSON_Delete(data);
    if (!device_ok) return error_response(400, "device_id must be a non-empty string");
    if (!temperature_ok) return error_response(400, "temperature must be numeric");
    if (status == 400) return error_response(400, "invalid device_id");
    if (status == 401) return error_response(401, "sensor credential required");
    if (status == 403) return error_response(403, "sensor credential rejected");
    if (status) return error_response(500, "sensor credential configuration error");

    char storage[256], target[300], err[256], message[400];
    if (service_endpoint("STORAGE_URL", "storage-service", storage, sizeof storage, err, sizeof err) != 0) {
        snprintf(message, sizeof message, "storage unavailable: %s", err);
        return error_response(503, message);
    }
    snprintf(target, sizeof target, "%s/store", storage);
    client_response response;
    if (http_send("POST", target, request->body, 2000, &response, err, sizeof err) != 0) {
        snprintf(message, sizeof message, "storage unavailable: %s", err);
        return error_response(503, message);
    }
    long storage_status = response.status;
    client_response_free(&response);
    if (storage_status < 200 || storage_status >= 300) return error_response(503, "storage rejected the reading");

    cJSON *result = cJSON_CreateObject();
    cJSON_AddBoolToObject(result, "stored", 1);
    cJSON_AddStringToObject(result, "storage", storage);
    return json_response(202, result);
}

static http_response route(const http_request *request) {
    const char *method = request->method, *path = request->path;
    if (strcmp(method, "GET") == 0 && strcmp(path, "/health") == 0) return health_response();
    if (strcmp(method, "POST") == 0 && strcmp(path, "/ingest") == 0) return handle_ingest(request);
    return error_response(404, "route not found");
}

int main(void) {
    const int port = env_int("PORT", 5001);
    const int direct = env_int("SSLE_DIRECT", 0);
    keys_dir = env_str("DEVICE_KEYS_DIR", NULL);
    const char *cert_file = env_str("INGESTION_TLS_CERT", NULL);
    const char *key_file = env_str("INGESTION_TLS_KEY", NULL);
    const char *client_ca_file = env_str("INGESTION_CLIENT_CA", NULL);
    if ((direct && !keys_dir) || (keys_dir && (!cert_file || !key_file)) ||
        (!!cert_file != !!key_file) || (client_ca_file && !keys_dir)) {
        fprintf(stderr, "direct ingestion requires a device key directory and TLS certificate/key\n");
        return 1;
    }
    char *certificate = cert_file ? read_text_file(cert_file, 32768) : NULL;
    char *key = key_file ? read_text_file(key_file, 32768) : NULL;
    char *client_ca = client_ca_file ? read_text_file(client_ca_file, 32768) : NULL;
    if ((cert_file && (!certificate || !key)) || (client_ca_file && !client_ca)) {
        fprintf(stderr, "could not read ingestion TLS files\n");
        free(certificate);
        free(key);
        free(client_ca);
        return 1;
    }
    char default_url[64];
    snprintf(default_url, sizeof default_url, "http://127.0.0.1:%d", port);
    struct MHD_Daemon *server = https_server_start((unsigned short)port, route, certificate, key, client_ca);
    if (!server) {
        fprintf(stderr, "could not start HTTP server\n");
        free(certificate);
        free(key);
        free(client_ca);
        return 1;
    }
    install_signal_handlers();
    if (!direct && registration_start("ingestion-service",
                           env_str("INSTANCE_ID", "pt.lisbon.dc1.rack1.node1.ingestion.01"),
                           env_str("SERVICE_URL", default_url)) != 0) {
        MHD_stop_daemon(server);
        free(certificate);
        free(key);
        free(client_ca);
        return 1;
    }
    printf("Ingestion service listening on port %d\n", port);
    fflush(stdout);
    wait_for_shutdown();
    registration_stop();
    MHD_stop_daemon(server);
    free(certificate);
    free(key);
    free(client_ca);
    return 0;
}
