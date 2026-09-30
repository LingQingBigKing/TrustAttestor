project(systemproperties)

add_library(${PROJECT_NAME} STATIC context_node.cpp
    contexts_serialized.cpp
    contexts_split.cpp
    prop_area.cpp
    prop_info.cpp
    system_properties.cpp
    system_property_api.cpp
    system_property_set.cpp
    property_info_parser.cpp)

target_include_directories(${PROJECT_NAME} PUBLIC include)

target_link_libraries(${PROJECT_NAME} PUBLIC log android)
