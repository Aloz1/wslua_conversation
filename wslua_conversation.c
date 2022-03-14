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

/* FIXME: This is a bit hacky. A segfault occurs when reloading lua scripts in Wireshark, which is
 *        probably due to 'saving' the lua state, then it being reset. Perhaps a __gc metamethod
 *        can be used as a hook to ensure consistency.
 *
 *        Additionally, I'm not sure if wireshark pinfo's are fully reset on lua script reload (e.g.
 *        fd_visited might always return TRUE when a lua script is reset). If not, then the data
 *        that is registered with wireshark *_add_proto_data functions cannot simply be stored as a
 *        lua registry reference, as it would need to exist independently of Lua state (note, it
 *        could still remain as a lua ref, and only be copied on __gc to improve speed). It looks
 *        like GVariant's (a glib native dynamic typing mechanism) may work well for this, as its
 *        already provided for 'free' with glib, and seems reasonably compareable to lua tables.
 */
typedef struct _luareg_data_t {
    lua_State *L;
    int reg_ref;
} luareg_data_t;

static gboolean luamem_callback(wmem_allocator_t* alloc, wmem_cb_event_t event, void* user_data)
{
    luareg_data_t *data = (luareg_data_t*)user_data;

    if (alloc != wmem_file_scope())
    {
        return TRUE;
    }

    // Remove data from Lua registry
    luaL_unref(data->L, LUA_REGISTRYINDEX, data->reg_ref);
    data->reg_ref = LUA_NOREF;

    return FALSE; // Unregister callback once called
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

        // Pushes stack value onto reference
        conv_data->reg_ref = luaL_ref(L, LUA_REGISTRYINDEX);
        conv_data->L = L;

        conversation_add_proto_data(conversation, proto->hfid, conv_data);
        wmem_register_callback(wmem_file_scope(), luamem_callback, conv_data);
    } else if (conv_data->L != L) {
        // Pushes stack value onto reference
        conv_data->reg_ref = luaL_ref(L, LUA_REGISTRYINDEX);
        conv_data->L = L;
    } else {
        // Set data
        lua_rawseti(conv_data->L, LUA_REGISTRYINDEX, conv_data->reg_ref);
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

        // Pushes stack value onto reference
        p_data->reg_ref = luaL_ref(L, LUA_REGISTRYINDEX);
        p_data->L = L;

        // Add proto_data
        p_add_proto_data(wmem_file_scope(), pinfo->ws_pinfo, proto->hfid, 0, p_data);
        wmem_register_callback(wmem_file_scope(), luamem_callback, p_data);
    } else if (p_data->L != L) {
        // Pushes stack value onto reference
        p_data->reg_ref = luaL_ref(L, LUA_REGISTRYINDEX);
        p_data->L = L;
    } else {
        // Set data
        lua_rawseti(p_data->L, LUA_REGISTRYINDEX, p_data->reg_ref);
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
