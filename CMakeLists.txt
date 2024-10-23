cmake_minimum_required(VERSION 3.5.0)
project(bitcoin_converter VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)  

find_package(OpenSSL REQUIRED)

include_directories(vendor/base58)

add_executable(bitcoin_converter main.cpp vendor/base58/base58.cpp)

target_link_libraries(${PROJECT_NAME}  
    Ws2_32
    Wldap32
    Normaliz
    Crypt32
    OpenSSL::SSL OpenSSL::Crypto 
)
