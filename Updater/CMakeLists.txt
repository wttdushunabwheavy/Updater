cmake_minimum_required(VERSION 3.20)

project(Updater LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(FetchContent)

FetchContent_Declare(
        httplib
        GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
        GIT_TAG v0.56.0
)

FetchContent_MakeAvailable(httplib)

add_executable(Updater
        src/main.cpp
        src/main.h
        src/main.cpp
)

target_link_libraries(Updater PRIVATE httplib::httplib)

if (WIN32)
    target_compile_definitions(Updater PRIVATE
            WIN32_LEAN_AND_MEAN
            NOMINMAX
    )
endif()