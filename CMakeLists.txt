cmake_minimum_required(VERSION 3.21.0)
# 定义工程名称, 并指定语言为C++
project(HXTest LANGUAGES CXX)

if(NOT WIN32)
    # 是否启用 Address Sanitizer
    # set(HX_DEBUG_BY_ADDRESS_SANITIZER ON)

    # 使用 Address Sanitizer
    # if(HX_DEBUG_BY_ADDRESS_SANITIZER AND CMAKE_BUILD_TYPE STREQUAL "Debug")
    #     set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address")
    #     set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address")
    #     message("=-=-=-=-=-=-= 启用 Address Sanitizer [-fsanitize=address] =-=-=-=-=-=-=")
    # endif()
endif()

# 如果没有定义CMAKE_BUILD_TYPE，则设置为Release
# 可以使用 cmake -DCMAKE_BUILD_TYPE=Debug .. 来指定
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
    message("=-=-=-=-=-=-= 当前是 [Release] 模式 =-=-=-=-=-=-=")
else()
    message("=-=-=-=-=-=-= 当前是 [DEBUG] 模式 =-=-=-=-=-=-=")
    add_definitions(-D_HX_DEBUG_) # 添加一个 _HX_DEBUG_ 宏
    message("已添加宏: _HX_DEBUG_")
endif()

# 设置CMake模块路径, 包含当前目录下的cmake文件夹以及之前的路径
# set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake;${CMAKE_MODULE_PATH}")

# 定义生成的库的存放目录
# set(LIB_PATH ${PROJECT_SOURCE_DIR}/lib)

set(ROOT_PATH "${PROJECT_SOURCE_DIR}") # 设置根项目的根目录
# 在camke .. 的时候会输出提示目录路径 (可选)
message(STATUS "Prefix dir is ${CMAKE_INSTALL_PREFIX}")
message(STATUS "Binary dir is ${PROJECT_BINARY_DIR}")
message(STATUS "Source dir is ${PROJECT_SOURCE_DIR}")
message(STATUS "ROOT_PATH dir is ${ROOT_PATH}")

# QT Start
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

set(projectName "HX_CLI")

project(${projectName}
    VERSION 0.0.1
    DESCRIPTION ${projectName}
    HOMEPAGE_URL "https://github.com/HengXin666/HXTest"
    LANGUAGES CXX
)

include_directories(include)

file(GLOB_RECURSE src_files CONFIGURE_DEPENDS 
    src/*.cpp
    include/*.h
    include/*.hpp
)

find_package(Qt5 REQUIRED COMPONENTS Core Gui Widgets)

add_executable(${projectName}
    ${src_files}
)

target_compile_features(${projectName} PUBLIC cxx_std_20)

target_link_libraries(${projectName}
    PRIVATE Qt5::Core
    PRIVATE Qt5::Gui
    PRIVATE Qt5::Widgets
)

set(QT_QML_GENERATE_QMLLS_INI ON)

# Qt拓展 (音频播放)
# find_package(Qt6 REQUIRED COMPONENTS Multimedia)
# target_link_libraries(${projectName} PRIVATE Qt::Multimedia)

# Qt拓展 (SVG)
# find_package(Qt6 REQUIRED COMPONENTS Svg)
# target_link_libraries(${projectName} PRIVATE Qt::Svg)

# Qt拓展 (XML)
# find_package(Qt6 REQUIRED COMPONENTS Xml)
# target_link_libraries(${projectName} PRIVATE Qt::Xml)

# Qt拓展 (编码)
# find_package(Qt6 REQUIRED COMPONENTS Core5Compat)
# target_link_libraries(${projectName} PRIVATE Qt::Core5Compat)

# Qt拓展 (并行库)
# find_package(Qt6 REQUIRED COMPONENTS Concurrent)
# target_link_libraries(${projectName} PRIVATE Qt::Concurrent)

# Qt拓展 (网络库)
# find_package(Qt6 REQUIRED COMPONENTS Network)
# target_link_libraries(${projectName} PRIVATE Qt::Network)

if (WIN32)
    # 解决路径问题, 确保 windeployqt.exe 存在
    set(QT_BIN_DIR "${QT_COMPILER_PATH}/bin")
    if(NOT EXISTS "${QT_BIN_DIR}/windeployqt.exe")
        message(FATAL_ERROR "Error: windeployqt.exe not found in ${QT_BIN_DIR}")
    endif()

    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/Debug")
        add_custom_command(TARGET ${projectName} POST_BUILD
            COMMAND "${QT_BIN_DIR}/windeployqt.exe" --debug "$<TARGET_FILE:${projectName}>"
            WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/Debug"
        )
    elseif (CMAKE_BUILD_TYPE STREQUAL "Release")
        file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/Release")
        add_custom_command(TARGET ${projectName} POST_BUILD
            COMMAND "${QT_BIN_DIR}/windeployqt.exe" --release "$<TARGET_FILE:${projectName}>"
            WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/Release"
        )
    endif()
endif()

set_target_properties(${projectName} PROPERTIES
    ${BUNDLE_ID_OPTION}
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE OFF
    WIN32_EXECUTABLE OFF # 这里需要为 OFF 才可以让vscode在控制台中输出...
)

include(GNUInstallDirs)
install(TARGETS ${projectName}
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

set_target_properties(${projectName} PROPERTIES FOLDER qt/${PARENT_DIR})

# 将include目录添加到HXTest库的公共包含目录中
# target_include_directories(HXTest PUBLIC include)