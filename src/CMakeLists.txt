cmake_minimum_required(VERSION 3.18)
project(ros_cheat)
set(CMAKE_CXX_STANDARD 17)

add_library(cheat SHARED
    ros_cheat.cpp
    imgui/imgui.cpp
    imgui/imgui_draw.cpp
    imgui/imgui_tables.cpp
    imgui/imgui_widgets.cpp
    imgui/backends/imgui_impl_android.cpp
    imgui/backends/imgui_impl_opengl3.cpp
)

target_include_directories(cheat PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    imgui
    imgui/backends
)

target_link_libraries(cheat android log EGL GLESv3)
