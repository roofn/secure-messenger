cmake_minimum_required(VERSION 3.22)

project(secure_messenger_clients LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 6.4 REQUIRED COMPONENTS
    Core Gui
    Qml Quick        
    Network WebSockets
)

# ------------------------
# sm_client (QML/Quick)
# ------------------------

cmake_minimum_required(VERSION 3.22)
project(secure_messenger_clients LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 6.4 REQUIRED COMPONENTS
  Core Gui Qml Quick Network WebSockets Widgets
)

qt_add_executable(sm_client
  src/main.cpp
  src/AppController.cpp
  src/AppController.h
)

qt_add_qml_module(sm_client
  URI smclient
  VERSION 1.0
  QML_FILES qml/Main.qml
  RESOURCE_PREFIX "/"
)

target_link_libraries(sm_client PRIVATE
  Qt6::Core Qt6::Gui Qt6::Qml Qt6::Quick Qt6::Network Qt6::WebSockets
)

install(TARGETS sm_client RUNTIME DESTINATION bin)

set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "${CMAKE_COMMAND} -E time")
