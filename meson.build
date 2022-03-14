
# A lua module to allow utilising conversation and packet data within Wireshark Lua dissectors.
#
# Note: This is a proof of concept. There are known issues with this module. It should only be
#       used for prototype code
#
# (c) 2022, Alastair Knowles
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
# 
# SPDX-License-Identifier: GPL-2.0-or-later

project('wslua_conversation', 'c')

lua = dependency('lua5.2')
ws  = dependency('wireshark')

library('wslua_conversation', 'wslua_conversation.c', name_prefix : '', dependencies : [lua, ws])
