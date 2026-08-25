find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)

add_library(rampart_host_openssl STATIC src/openssl_crypto.c)

target_include_directories(rampart_host_openssl PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(rampart_host_openssl PUBLIC rampart_core OpenSSL::Crypto)
rampart_apply_common_options(rampart_host_openssl)
