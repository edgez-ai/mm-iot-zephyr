/* Copyright (c) 2026 EdgeZeron AI AB. All rights reserved. */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EDGEZ_MESH_S1G_CAPABILITIES_EID 217U
#define EDGEZ_MESH_S1G_CAPABILITIES_BODY_LEN 15U
#define EDGEZ_MESH_S1G_CAPABILITIES_IE_LEN \
    (2U + EDGEZ_MESH_S1G_CAPABILITIES_BODY_LEN)

/* Conservative 802.11ah full-node profile: non-sensor, one spatial stream,
 * MCS 0-7. It is intentionally independent of Morse SDK data structures. */
extern const uint8_t edgez_mesh_s1g_default_capabilities_ie[
    EDGEZ_MESH_S1G_CAPABILITIES_IE_LEN];

bool edgez_mesh_s1g_ies_have_capabilities(const uint8_t *ies,
                                           size_t ies_length);

#ifdef __cplusplus
}
#endif
