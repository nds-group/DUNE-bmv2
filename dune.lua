-- DUNE protocol Wireshark Lua dissector
-- Matches EtherType 0xd00e then parses Dune_h (8 bytes)

local dune = Proto("dune", "DUNE Protocol")

-- Enumerations
local class_type_vals = {
    [0] = "PL (Packet Level)",
    [1] = "FL (Flow Level)"
}

local orig_ethertype_vals = {
    [0x0800] = "IPv4",
    [0x86DD] = "IPv6",
    [0x8847] = "MPLS Unicast",
    [0x8848] = "MPLS Multicast"
}

-- Fields (Dune_h)
local f = dune.fields
f.orig_ethertype = ProtoField.uint16("dune.orig_ethertype", "Original EtherType", base.HEX, orig_ethertype_vals)
f.class_type     = ProtoField.uint8 ("dune.class_type",     "Class Type",       base.DEC, class_type_vals)
f.class          = ProtoField.uint8 ("dune.class",          "Class",            base.DEC)
f.collision      = ProtoField.uint8 ("dune.collision",      "Collision",        base.DEC)
f.model_id       = ProtoField.uint8 ("dune.model_id",       "Model ID",         base.DEC)
f.mpls_label     = ProtoField.uint16("dune.mpls_label",     "MPLS Label",       base.DEC)

local ETHERTYPE_DUNE = 0xd00e
local DUNE_HDR_LEN = 8

function dune.dissector(tvb, pinfo, tree)
    if tvb:len() < DUNE_HDR_LEN then return 0 end

    pinfo.cols.protocol = "DUNE"

    local subtree = tree:add(dune, tvb(0, DUNE_HDR_LEN), "DUNE Header")
    local offset = 0

    subtree:add(f.orig_ethertype, tvb(offset,2)); offset = offset + 2
    subtree:add(f.class_type,     tvb(offset,1)); offset = offset + 1
    subtree:add(f.class,          tvb(offset,1)); offset = offset + 1
    subtree:add(f.collision,      tvb(offset,1)); offset = offset + 1
    subtree:add(f.model_id,       tvb(offset,1)); offset = offset + 1
    subtree:add(f.mpls_label,     tvb(offset,2)); offset = offset + 2

    -- Hand off to original EtherType dissector if available
    local orig_ethertype = tvb(0,2):uint()
    local next_tvb = tvb(DUNE_HDR_LEN):tvb()
    local eth_dissectors = DissectorTable.get("ethertype")
    local next_dissector = eth_dissectors:get_dissector(orig_ethertype)
    if next_dissector then
        next_dissector:call(next_tvb, pinfo, tree)
    end

    return
end

-- Register with ethertype table
local eth_table = DissectorTable.get("ethertype")
eth_table:add(ETHERTYPE_DUNE, dune)
