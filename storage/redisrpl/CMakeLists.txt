# Copyright (c) 2006, 2013, Oracle and/or its affiliates. All rights reserved.
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA

SET(REDISRPL_SOURCES  ha_redisrpl.cc ha_redisrpl.h)

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/storage/redisrpl/hiredis)

IF(WITH_REDISRPL_STORAGE_ENGINE AND NOT WITHOUT_REDISRPL_STORAGE_ENGINE)
  MYSQL_ADD_PLUGIN(redisrpl ${REDISRPL_SOURCES} STORAGE_ENGINE DEFAULT)
ELSEIF(NOT WITHOUT_EXAMPLE_STORAGE_ENGINE)
  MYSQL_ADD_PLUGIN(redisrpl ${REDISRPL_SOURCES} STORAGE_ENGINE MODULE_ONLY)
ENDIF()

