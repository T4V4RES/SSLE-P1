cmake_minimum_required(VERSION 3.20)
project(ssle_guide1 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)
add_compile_options(-Wall -Wextra)

find_package(PkgConfig REQUIRED)
pkg_check_modules(MICROHTTPD REQUIRED IMPORTED_TARGET libmicrohttpd)
pkg_check_modules(CURL REQUIRED IMPORTED_TARGET libcurl)
pkg_check_modules(CJSON REQUIRED IMPORTED_TARGET libcjson)
pkg_check_modules(SQLITE3 REQUIRED IMPORTED_TARGET sqlite3)
pkg_check_modules(GNUTLS REQUIRED IMPORTED_TARGET gnutls)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)

add_library(ssle_common STATIC src/ssle.c)
target_include_directories(ssle_common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(ssle_common PUBLIC
    PkgConfig::MICROHTTPD PkgConfig::CURL PkgConfig::CJSON Threads::Threads m)

add_executable(service_registry src/service_registry.c)
target_link_libraries(service_registry PRIVATE ssle_common)

add_executable(storage_service src/storage_service.c)
target_link_libraries(storage_service PRIVATE ssle_common PkgConfig::SQLITE3)

add_executable(ingestion_service src/ingestion_service.c)
target_link_libraries(ingestion_service PRIVATE ssle_common OpenSSL::Crypto PkgConfig::GNUTLS)

add_executable(analytics_service src/analytics_service.c)
target_link_libraries(analytics_service PRIVATE ssle_common)

add_executable(temperature_sensor src/temperature_sensor.c)
target_link_libraries(temperature_sensor PRIVATE ssle_common)

install(TARGETS service_registry storage_service ingestion_service
                analytics_service temperature_sensor
        RUNTIME DESTINATION bin)

enable_testing()
add_executable(bounds_test tests/bounds_test.c)
target_link_libraries(bounds_test PRIVATE ssle_common)
target_compile_options(bounds_test PRIVATE -UNDEBUG)
add_test(NAME input_bounds COMMAND bounds_test)
add_test(NAME end_to_end
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration_test.sh
            $<TARGET_FILE:service_registry>
            $<TARGET_FILE:storage_service>
            $<TARGET_FILE:ingestion_service>
            $<TARGET_FILE:analytics_service>
            $<TARGET_FILE:temperature_sensor>)
set_tests_properties(end_to_end PROPERTIES TIMEOUT 20)
add_test(NAME direct_authenticated
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/direct_test.sh
            $<TARGET_FILE:storage_service> $<TARGET_FILE:ingestion_service>
            $<TARGET_FILE:analytics_service> $<TARGET_FILE:temperature_sensor>)
set_tests_properties(direct_authenticated PROPERTIES TIMEOUT 20)
