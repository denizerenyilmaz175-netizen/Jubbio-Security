cmake_minimum_required(VERSION 3.16)
project(JubbioSecurity LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(jubbio_security STATIC cpp/src/e2ee_service.cpp)
target_include_directories(jubbio_security PUBLIC cpp/include)
target_compile_options(jubbio_security PRIVATE -Wall -Wextra -Wpedantic)

add_executable(jubbio_security_test cpp/tests/test_service.cpp)
target_link_libraries(jubbio_security_test PRIVATE jubbio_security)
enable_testing()
add_test(NAME jubbio_security_test COMMAND jubbio_security_test)
