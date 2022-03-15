/*
 * A lua module to allow utilising conversation and packet data within Wireshark Lua dissectors.
 *
 * Note: This is a proof of concept. There are known issues with this module. It should only be
 *       used for prototype code
 *
 * (c) 2022, Alastair Knowles
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "wslua_lite.h"

#include <epan/wmem/wmem.h>
#include <epan/proto_data.h>

#include <lauxlib.h>
#include <lua.h>

/* This is a bit hacky. Cleanup is handled by using __gc to ensure memory is marked as
 * unreferenced / NULL if lua state is ever reset, ensuring consistency between Lua land and
 * wireshark land.
 *
 * This seems to work quite well. No need to serialise/copy values to something more 'C' friendly
 * (e.g. g_variant fields) as it seems that dissection is fully reset when lua scripts are reloaded
 * (ctrl+shift+L)
 */
typedef struct _luareg_data_t {
    lua_State *L;
    int reg_ref;
} luareg_data_t;

static gboolean luareg_data_callback(wmem_allocator_t* alloc, wmem_cb_event_t event, void* user_data)
{
    luareg_data_t *data = (luareg_data_t*)user_data;

    if (alloc != wmem_file_scope())
    {
        return TRUE;
    }

    if ((data->L != NULL) && (data->reg_ref != LUA_NOREF)) {
        // Remove data from Lua registry, if lua state still valid
        luaL_unref(data->L, LUA_REGISTRYINDEX, data->reg_ref);
        lua_gc(data->L, LUA_GCCOLLECT, 0);

        data->L = NULL;
        data->reg_ref = LUA_NOREF;
    }

    return FALSE; // Unregister callback once called
}

static int cleanup_luareg_data(lua_State *L) {
    int i = lua_upvalueindex(1);

    luaL_checktype(L, i, LUA_TLIGHTUSERDATA);
    luareg_data_t *data = (luareg_data_t*)lua_topointer(L, i);

    data->L = NULL;
    data->reg_ref = LUA_NOREF; // No need to unreference. This method is only called for cleanup anyway.

    return 0;
}

static void create_luareg_table(lua_State *L, luareg_data_t *data) {
    // Create base table
    lua_createtable(L, 1, 0);

    // Swap table with passed in data
    lua_insert(L, -2);

    // Insert data into table
    lua_rawseti(L, -2, 1);

    // Create metatable
    lua_createtable(L, 0, 1);

    // Create closure
    lua_pushlightuserdata(L, data);
    lua_pushcclosure(L, &cleanup_luareg_data, 1);

    // Set closure as __gc, and pop
    lua_setfield(L, -2, "__gc");

    // Set metatable
    lua_setmetatable(L, -2);

    data->L = L;
    data->reg_ref = luaL_ref(L, LUA_REGISTRYINDEX);
}

static int set_conv_data(lua_State *L) {
    Proto proto = checkProto(L, 1);
    Pinfo pinfo = checkPinfo(L, 2);

    conversation_t *conversation;
    luareg_data_t  *conv_data;

    // Check if user data has been attached to conversation
    conversation = find_or_create_conversation(pinfo->ws_pinfo);
    conv_data    = (luareg_data_t *)conversation_get_proto_data(conversation, proto->hfid);

    if (conv_data == NULL) {
        // If not, create user data and attach
        conv_data = wmem_new(wmem_file_scope(), luareg_data_t);

        conv_data->L = NULL;
        conv_data->reg_ref = LUA_NOREF;

        conversation_add_proto_data(conversation, proto->hfid, conv_data);
        wmem_register_callback(wmem_file_scope(), luareg_data_callback, conv_data);
    }

    if (conv_data->L != L) {
        // Not yet setup, lets set it up
        create_luareg_table(L, conv_data);
    } else {
        // Set data
        lua_rawgeti(conv_data->L, LUA_REGISTRYINDEX, conv_data->reg_ref);
        lua_insert(L, -2); // Swap table and data
        lua_rawseti(L, -2, 1);
    }
    
    return 0; // Number of values on lua stack
}

static int get_conv_data(lua_State *L) {
    Proto proto = checkProto(L, 1);
    Pinfo pinfo = checkPinfo(L, 2);

    luareg_data_t    *conv_data;
    conversation_t *conversation;

    // Check if user data has been attached to conversation
    conversation = find_or_create_conversation(pinfo->ws_pinfo);
    conv_data    = (luareg_data_t *)conversation_get_proto_data(conversation, proto->hfid);

    if ((conv_data == NULL) || (conv_data->L != L)) {
        lua_pushnil(L);
    } else {
        lua_rawgeti(conv_data->L, LUA_REGISTRYINDEX, conv_data->reg_ref);
        lua_rawgeti(L, -1, 1);
    }

    return 1; // Number of values on lua stack
}

static int set_packet_data(lua_State *L) {
    Proto proto = checkProto(L, 1);
    Pinfo pinfo = checkPinfo(L, 2);

    luareg_data_t  *p_data;

    // Check if user data has been attached to conversation
    p_data = (luareg_data_t*)p_get_proto_data(wmem_file_scope(), pinfo->ws_pinfo, proto->hfid, 0);
    if (p_data == NULL) {
        // If not, create user data and attach
        p_data = wmem_new(wmem_file_scope(), luareg_data_t);

        p_data->L = NULL;
        p_data->reg_ref = LUA_NOREF;

        // Add proto_data
        p_add_proto_data(wmem_file_scope(), pinfo->ws_pinfo, proto->hfid, 0, p_data);
        wmem_register_callback(wmem_file_scope(), luareg_data_callback, p_data);
    }

    if (p_data->L != L) {
        // Pushes stack value onto reference
        create_luareg_table(L, p_data);
    } else {
        // Set data
        lua_rawgeti(p_data->L, LUA_REGISTRYINDEX, p_data->reg_ref);
        lua_insert(L, -2); // Swap table and data
        lua_rawseti(L, -2, 1);
    }
    
    return 0;
}

static int get_packet_data(lua_State *L) {
    Proto proto = checkProto(L, 1);
    Pinfo pinfo = checkPinfo(L, 2);

    luareg_data_t    *p_data;

    // Check if user data has been attached to conversation
    p_data = (luareg_data_t *)p_get_proto_data(wmem_file_scope(), pinfo->ws_pinfo, proto->hfid, 0);

    if ((p_data == NULL) || (p_data->L != L)) {
        lua_pushnil(L);
    } else {
        lua_rawgeti(p_data->L, LUA_REGISTRYINDEX, p_data->reg_ref);
        lua_rawgeti(L, -1, 1);
    }

    return 1; // Number of values on lua stack
}

int luaopen_wslua_conversation(lua_State *L) {
    static const struct luaL_Reg funcs[] = {
        { "get_conv_data",   get_conv_data },
        { "set_conv_data",   set_conv_data },
        { "get_packet_data", get_packet_data },
        { "set_packet_data", set_packet_data },
        { NULL, NULL } // Sentinel value
    };

    luaL_newlib(L, funcs);
    return 1; //(sizeof funcs) / (sizeof (luaL_Reg));
}
