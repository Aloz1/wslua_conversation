/*
 * wslua_lite.h
 *
 * The contents of this file is a stripped back version of what can be found in epan/wslua/wslua.h,
 * which is not included as a public header for dissector plugins. Hence, the notice below has been
 * copied from that file, as I do not know who owns copywrite on which portions of code.
 *
 * Wireshark's interface to the Lua Programming Language
 *
 * (c) 2006, Luis E. Garcia Ontanon <luis@ontanon.org>
 * (c) 2007, Tamas Regos <tamas.regos@ericsson.com>
 * (c) 2008, Balint Reczey <balint.reczey@ericsson.com>
 * (c) 2022, Alastair Knowles
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _PACKET_LUA_H
#define _PACKET_LUA_H

#include <glib.h>
#include <epan/expert.h>
#include <epan/packet_info.h>
#include <epan/conversation.h>

#include <lauxlib.h>

#define DEFINE_CHECK_USER(C, check_code, retval) \
C check##C(lua_State* L, int idx) { \
    C* p; \
    luaL_checktype(L,idx,LUA_TUSERDATA); \
    p = (C*)luaL_checkudata(L, idx, #C); \
    check_code; \
    return p ? *p : retval; \
}

#define FAIL_ON_NULL(s) if (! *p) luaL_argerror(L,idx,"null " s)

#define FAIL_ON_NULL_OR_EXPIRED(s) if (!*p) { \
        luaL_argerror(L,idx,"null " s); \
    } else if ((*p)->expired) { \
        luaL_argerror(L,idx,"expired " s); \
    }

typedef enum {
    PREF_UINT,
    PREF_BOOL,
    PREF_ENUM,
    PREF_STRING,
    PREF_RANGE,
    PREF_STATIC_TEXT,
    PREF_OBSOLETE
} pref_type_t;

struct _wslua_pinfo {
    packet_info *ws_pinfo;
    gboolean expired;
};

typedef struct _wslua_pinfo *Pinfo;

typedef struct _wslua_pref_t {
    gchar* name;
    gchar* label;
    gchar* desc;
    pref_type_t type;
    union {
        gboolean b;
        guint u;
        gchar* s;
        gint e;
        range_t *r;
        void* p;
    } value;
    union {
        guint32 max_value;
        struct {
            const enum_val_t *enumvals;
            gboolean radio_buttons;
        } enum_info;
        gchar* default_s;
    } info;

    struct _wslua_pref_t* next;
    struct _wslua_proto_t* proto;
    int ref;
} wslua_pref_t;

typedef struct _wslua_proto_t {
    gchar* name;
    gchar* loname;
    gchar* desc;
    int hfid;
    int ett;
    wslua_pref_t prefs;
    int fields;
    int expert_info_table_ref;
    expert_module_t *expert_module;
    module_t *prefs_module;
    dissector_handle_t handle;
    GArray *hfa;
    GArray *etta;
    GArray *eia;
    gboolean is_postdissector;
    gboolean expired;
} wslua_proto_t;

typedef struct _wslua_proto_t* Proto;

DEFINE_CHECK_USER(Pinfo, FAIL_ON_NULL_OR_EXPIRED("Pinfo"), NULL);
DEFINE_CHECK_USER(Proto, FAIL_ON_NULL_OR_EXPIRED("Proto"), NULL);

#endif /* _PACKET_LUA_H */
