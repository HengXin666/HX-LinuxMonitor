cmake_minimum_required(VERSION 3.15.0)
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
)

find_package(Qt5 REQUIRED COMPONENTS Core Gui Widgets)

# 遍历每个 .cpp 文件, 生成可执行文件
foreach(TEST_FILE ${src_files})
    # 提取 .cpp 文件名作为目标名 (去掉路径和扩展名)
    get_filename_component(TEST_NAME ${TEST_FILE} NAME_WE)

    # 获取 .cpp 文件所在的目录 (相对路径)
    get_filename_component(TEST_DIR ${TEST_FILE} DIRECTORY)
    
    # 获取 TEST_DIR 的最后一级目录名 (即父文件夹名)
    get_filename_component(PARENT_DIR ${TEST_DIR} NAME)
    
    # 添加测试可执行文件
    add_executable(${TEST_NAME} ${TEST_FILE})

    # 示例: 添加std线程依赖
    target_link_libraries(${TEST_NAME}
        PRIVATE Qt5::Core
        PRIVATE Qt5::Gui
        PRIVATE Qt5::Widgets
    )

    # 设置 FOLDER 属性, 使其按所在 demo 子目录分类
    set_target_properties(${TEST_NAME} PROPERTIES FOLDER qt/${PARENT_DIR})

    set_target_properties(${TEST_NAME} PROPERTIES
        ${BUNDLE_ID_OPTION}
        MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
        MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
        MACOSX_BUNDLE OFF
        WIN32_EXECUTABLE OFF # 这里需要为 OFF 才可以让vscode在控制台中输出...
    )

    include(GNUInstallDirs)
    install(TARGETS ${TEST_NAME}
        BUNDLE DESTINATION .
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )

    set_target_properties(${TEST_NAME} PROPERTIES FOLDER qt/${PARENT_DIR})

    # 使用 Address Sanitizer
    if(HX_DEBUG_BY_ADDRESS_SANITIZER)
        target_compile_options(${TEST_NAME} PRIVATE
        $<$<CONFIG:Debug>:-fsanitize=address>)

        target_link_options(${TEST_NAME} PRIVATE
            $<$<CONFIG:Debug>:-fsanitize=address>)
    endif()
endforeach()

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


# 将include目录添加到HXTest库的公共包含目录中
# target_include_directories(HXTest PUBLIC include)