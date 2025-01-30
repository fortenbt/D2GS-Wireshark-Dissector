# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

cmake_minimum_required(VERSION 3.12)
cmake_policy(SET CMP0048 NEW)

project(D2GS VERSION 0.0.1 DESCRIPTION "Wireshark D2GS Plugin" LANGUAGES C)

# The build in Wireshark's source tree (Windows build) uses this WiresharkPlugin
include(WiresharkPlugin OPTIONAL RESULT_VARIABLE in_ws)

if (in_ws)
	include(CMakeLists.Windows.txt)
else()
	include(CMakeLists.Linux.txt)
endif()

#
# Editor modelines  -  https://www.wireshark.org/tools/modelines.html
#
# Local variables:
# c-basic-offset: 8
# tab-width: 8
# indent-tabs-mode: t
# End:
#
# vi: set shiftwidth=8 tabstop=8 noexpandtab:
# :indentSize=8:tabSize=8:noTabs=false:
#
