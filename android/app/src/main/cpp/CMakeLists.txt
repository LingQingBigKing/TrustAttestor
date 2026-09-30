project(TrustAttestor)
cmake_minimum_required(VERSION 3.12)

set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 20)

find_package(cxx REQUIRED CONFIG)
link_libraries(cxx::cxx)


add_subdirectory(external)
add_subdirectory(checker)

add_library(${PROJECT_NAME} SHARED main.cpp indirect.cpp)

target_compile_options(${PROJECT_NAME} PRIVATE
            # 建议至少 O1，否则部分 IR 形态太原始，pass 容易踩边界
            $<$<COMPILE_LANGUAGE:C>:-O1>
            $<$<COMPILE_LANGUAGE:CXX>:-O1>

            # 不建议和 LTO 一起开，先保证普通编译稳定
            $<$<COMPILE_LANGUAGE:C>:-fno-lto>
            $<$<COMPILE_LANGUAGE:CXX>:-fno-lto>
)

target_link_libraries(
        ${PROJECT_NAME}
        musl checker
)


target_link_options(${PROJECT_NAME} PRIVATE "LINKER:--Map=${CMAKE_CURRENT_BINARY_DIR}/libTrustAttestor.map")

target_link_options(${PROJECT_NAME} PRIVATE -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/symbols.txt)

set_target_properties(${PROJECT_NAME} PROPERTIES LINK_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/symbols.txt)
