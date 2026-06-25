cmake_minimum_required(VERSION 3.19)
project(QtAuthoriza LANGUAGES CXX)

find_package(Qt6 REQUIRED COMPONENTS Core Widgets Network NetworkAuth)

qt_standard_project_setup()

# ===== OpenSSL (пути вручную) =====
set(OPENSSL_INCLUDE_DIR "C:/Program Files/OpenSSL-Win64/include")

# Для Debug сборки используем MDd
set(OPENSSL_LIBRARIES
    "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MDd/libcrypto.lib"
    "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MDd/libssl.lib"
)

include_directories(${OPENSSL_INCLUDE_DIR})
# ===================================

# ===== jwt-cpp и nlohmann/json =====
include_directories(${CMAKE_SOURCE_DIR}/jwt-cpp-master/include)
include_directories(${CMAKE_SOURCE_DIR}/json-develop/single_include)
# ===================================

qt_add_executable(QtAuthoriza
    WIN32 MACOSX_BUNDLE
    main.cpp
    mainwindow.cpp
    mainwindow.h
    mainwindow.ui
    authmanager.h
    authmanager.cpp
)

target_link_libraries(QtAuthoriza
    PRIVATE
    Qt6::Core
    Qt6::Widgets
    Qt6::Network
    Qt6::NetworkAuth
    ${OPENSSL_LIBRARIES}
)

install(TARGETS QtAuthoriza
    BUNDLE  DESTINATION .
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

qt_generate_deploy_app_script(
    TARGET QtAuthoriza
    OUTPUT_SCRIPT deploy_script
    NO_UNSUPPORTED_PLATFORM_ERROR
)
install(SCRIPT ${deploy_script})