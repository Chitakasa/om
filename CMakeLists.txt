cmake_minimum_required(VERSION 3.20)
project(om VERSION 1.0.0 LANGUAGES CXX)

# C++ Standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Dependencies
find_package(nlohmann_json 3.2.0 REQUIRED)
find_package(CLI11 CONFIG REQUIRED)

# Executable
add_executable(om src/om.cpp)

# Link libraries
target_link_libraries(om PRIVATE nlohmann_json::nlohmann_json CLI11::CLI11)

# Compiler flags
target_compile_options(om PRIVATE -Wall -Wextra -O2)

# Install binary
install(TARGETS om DESTINATION bin)

# Install man page
install(FILES om.1 DESTINATION share/man/man1)

# Install completions
install(FILES completions/om.bash 
        DESTINATION share/bash-completion/completions 
        RENAME om)
install(FILES completions/om.zsh 
        DESTINATION share/zsh/site-functions 
        RENAME _om)
install(FILES completions/om.fish 
        DESTINATION share/fish/vendor_completions.d)

# CPack for package generation
set(CPACK_PACKAGE_NAME "om")
set(CPACK_PACKAGE_VERSION "1.0.0")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Program Manager - Store and execute commands")
set(CPACK_PACKAGE_CONTACT "your.email@example.com")

include(CPack)