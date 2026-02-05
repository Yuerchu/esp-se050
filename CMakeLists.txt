set(srcs
    "nanopackage/apdu/se05x_APDU_impl.c"
    "nanopackage/apdu/smCom.c"
    "nanopackage/apdu/se05x_tlv.c"
    "nanopackage/t1oi2c/phNxpEse_Api.c"
    "nanopackage/t1oi2c/phNxpEsePal_i2c.c"
    "nanopackage/t1oi2c/phNxpEseProto7816_3.c"
    "nanopackage/mbedtls_alt/se05x_mbedtls.c"
    "port/sm_i2c.c"
    "port/sm_timer.c"
    "src/esp_se050.c"
)

set(include_dirs
    "include"
    "port"
    "nanopackage/apdu"
    "nanopackage/apdu/scp03"
    "nanopackage/apdu/eckey"
    "nanopackage/mbedtls_alt"
    "nanopackage/t1oi2c"
)

set(compile_defs
    "T1oI2C"
    "T1oI2C_UM11225"
)

if(CONFIG_SE050_SCP03 OR CONFIG_SE050_ECKEY_SCP03)
    list(APPEND srcs
        "nanopackage/apdu/scp03/se05x_scp03.c"
        "nanopackage/apdu/scp03/se05x_auth_utils.c"
        "nanopackage/apdu/scp03/mbedtls/se05x_scp03_crypto_mbedtls.c"
    )
    list(APPEND include_dirs "nanopackage/apdu/scp03/mbedtls")
    list(APPEND compile_defs "WITH_PLATFORM_SCP03")
endif()

if(CONFIG_SE050_ECKEY OR CONFIG_SE050_ECKEY_SCP03)
    list(APPEND srcs "nanopackage/apdu/eckey/se05x_ec_key_auth.c")
    list(APPEND compile_defs "WITH_ECKEY_SESSION")
endif()

if(CONFIG_SE050_ECKEY_SCP03)
    list(APPEND compile_defs "WITH_ECKEY_SCP03_SESSION")
endif()

if(CONFIG_SE050_MBEDTLS_ALT)
    list(APPEND srcs
        "nanopackage/mbedtls_alt/ecdsa_se05x.c"
        "nanopackage/mbedtls_alt/ecdsa_o.c"
    )
    list(APPEND compile_defs "MBEDTLS_ECDSA_SIGN_ALT")
endif()

if(CONFIG_SE050_APDU_MUTEX)
    list(APPEND compile_defs "ENABLE_SM_APDU_MUTEX")
endif()

idf_component_register(
    SRCS ${srcs}
    INCLUDE_DIRS ${include_dirs}
    REQUIRES driver mbedtls
)

target_compile_definitions(${COMPONENT_LIB} PUBLIC ${compile_defs})

if(CONFIG_SE050_APDU_BUFFER_SIZE)
    target_compile_definitions(${COMPONENT_LIB} PUBLIC
        CONFIG_PLUGANDTRUST_APDU_BUFFER_SIZE=${CONFIG_SE050_APDU_BUFFER_SIZE}
    )
endif()

if(CONFIG_SE050_MBEDTLS_ALT)
    idf_component_get_property(mbedtls_dir mbedtls COMPONENT_DIR)
    target_include_directories(${COMPONENT_LIB} PRIVATE "${mbedtls_dir}/mbedtls/library")

    idf_component_get_property(mbedtls_lib mbedtls COMPONENT_LIB)
    target_compile_definitions(${mbedtls_lib} PUBLIC MBEDTLS_ECDSA_SIGN_ALT)
    target_link_libraries(${mbedtls_lib} PRIVATE ${COMPONENT_LIB})
endif()

set_source_files_properties(${srcs} PROPERTIES COMPILE_OPTIONS "-Wno-unused-parameter;-Wno-sign-compare")
