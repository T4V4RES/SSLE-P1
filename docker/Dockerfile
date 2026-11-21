# Uma imagem por servico, todas a partir do mesmo Dockerfile (multi-stage).
# Contexto de build: a pasta 1/ (codigo C da aula 1).
#   docker build -f Dockerfile --target registry -t ssle/registry:1.0 ../../1

# ---------- 1. Compilacao ----------
FROM debian:trixie AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential cmake pkg-config curl openssl libssl-dev libgnutls28-dev \
      libmicrohttpd-dev libcurl4-openssl-dev libcjson-dev libsqlite3-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY CMakeLists.txt ./
COPY include include
COPY src src
COPY tests tests
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
 && cmake --build build -j2 \
 && ctest --test-dir build --output-on-failure \
 && cmake --install build --prefix /out

# ---------- 2. Base de execucao (so bibliotecas, sem compilador) ----------
FROM debian:trixie-slim AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      libmicrohttpd12t64 libcurl4t64 libcjson1 libsqlite3-0 libssl3t64 libgnutls30t64 ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin ssle \
 && mkdir /data && chown ssle:ssle /data

# ---------- 3. Imagens finais ----------
FROM runtime AS registry
COPY --from=build /out/bin/service_registry /usr/local/bin/
USER 10001
EXPOSE 5050
ENTRYPOINT ["service_registry"]

FROM runtime AS storage
COPY --from=build /out/bin/storage_service /usr/local/bin/
ENV TEMP_DB=/data/temp_data.db
VOLUME /data
USER 10001
EXPOSE 5002
ENTRYPOINT ["storage_service"]

FROM runtime AS ingestion
COPY --from=build /out/bin/ingestion_service /usr/local/bin/
USER 10001
EXPOSE 5001
ENTRYPOINT ["ingestion_service"]

FROM runtime AS analytics
COPY --from=build /out/bin/analytics_service /usr/local/bin/
USER 10001
EXPOSE 5003
ENTRYPOINT ["analytics_service"]

FROM runtime AS sensor
COPY --from=build /out/bin/temperature_sensor /usr/local/bin/
USER 10001
ENTRYPOINT ["temperature_sensor"]
