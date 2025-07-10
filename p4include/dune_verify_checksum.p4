#ifndef DUNE_VERIFY_CHECKSUM_P4
#define DUNE_VERIFY_CHECKSUM_P4

#include "dune_headers.p4"

control DuneVerifyChecksum(
    inout Headers_t hdr,
    inout Metadata_t meta
)
{
    apply {}
}

#endif
