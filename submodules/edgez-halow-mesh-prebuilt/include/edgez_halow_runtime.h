/*
 * Copyright 2026 EdgeZeron AI AB. All rights reserved.
 * Licensed under the EdgeZ Commercial Software License.
 */

#ifndef EDGEZ_HALOW_RUNTIME_H
#define EDGEZ_HALOW_RUNTIME_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EDGEZ_HALOW_API_VERSION 1U

enum edgez_halow_node_role {
	EDGEZ_HALOW_NODE_SENSOR = 0,
	EDGEZ_HALOW_NODE_FULL = 1,
};

struct edgez_halow_platform_ops {
	uint32_t api_version;
	uint64_t (*monotonic_ms)(void);
	void (*log_message)(int level, const char *message);
};

int edgez_halow_runtime_init(const struct edgez_halow_platform_ops *ops);
const struct edgez_halow_platform_ops *edgez_halow_runtime_platform(void);

#ifdef __cplusplus
}
#endif

#endif /* EDGEZ_HALOW_RUNTIME_H */
