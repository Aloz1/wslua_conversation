# Introduction
This is a proof of concept lua c-module that exposes conversation data and packet data primitives for storing and fetching user data. Any lua data can be stored and retrieved at a later stage.

Note, this has not been fully tested, and is not recommended for production code.

# Building
To build:
```bash
meson build
cd build
meson compile
```

# Example usage
The example below is roughly equivalent to the C examples found in the doc/README.request\_response\_tracking and doc/README.dissector documents found within the Wireshark source distribution (or gitlab).

```lua
-- Near top of dissector.lua file
package.cpath = table.concat({ '/absolute/lib/dir/path/?.so', package.cpath }, ';')

local conversation = require "wslua_conversation"


-- etc ...


-- In dissector definition
function my_proto:dissector(buffer, pinfo, tree)
    -- etc ...

    -- Fetch conversation
    local conv  = conversation.get_conv_data(my_proto, pinfo)

    if next(conv) == nil then
        -- Nothing created yet
        conv = { some : "initial", values : "etc" }
        conversation.set_conv_data(my_proto, pinfo, conv)
    end


    -- Check if visited
    if not pinfo.visited then
        -- Update some stateful values
        conv.some_stateful_info = "blah"
        conversation.set_conv_data(my_proto, pinfo, conv)

        if some_cond then
            -- Also set packet specific data (equivalent to p_add_proto_data)
            conversation.set_packet_data(my_proto, pinfo, {some : 'more', data : 'blah' })
        end
    end

    -- etc ...

    local pdata = conversation.get_packet_data(my_proto, pinfo)

    -- etc ...
end
```
