#ifndef DUNE_EGRESS_P4
#define DUNE_EGRESS_P4

#include "dune_headers.p4"

control DuneEgress(
    inout Headers_t hdr,
    inout Metadata_t meta,
    inout standard_metadata_t std_meta
)
{
    apply {}
}

#endif
