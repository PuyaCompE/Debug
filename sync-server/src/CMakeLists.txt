cmake_minimum_required(VERSION 2.6)
project(sync-server C)

add_definitions(-Wall -Werror)

if(ULOOP_TIMEOUT_REMAINING64)
  add_definitions(-DHAVE_ULOOP_TIMEOUT_REMAINING64=1)
endif()

include(FindPkgConfig)
pkg_search_module(JSON REQUIRED json-c json)

include_directories(${JSON_INCLUDE_DIRS})
link_directories(${JSON_LIBRARY_DIRS})

add_executable(sync-server sync-server.c)
target_link_libraries(sync-server ubus ubox blobmsg_json ${JSON_LIBRARIES})

install(TARGETS sync-server
  RUNTIME DESTINATION bin)
