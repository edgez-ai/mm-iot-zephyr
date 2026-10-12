/*
 * Copyright (c) 2026 EdgeZeron AI AB. All rights reserved.
 * Licensed under the EdgeZ Commercial Software License.
 */

#pragma once

#ifndef EDGEZ_DIAGNOSTICS_ENABLED
#if !defined(EDGEZ_PLATFORM_ARCHIVE_BUILD) && \
    defined(CONFIG_HALOW_MESH_DEBUG_LOG) && CONFIG_HALOW_MESH_DEBUG_LOG
#define EDGEZ_DIAGNOSTICS_ENABLED 1
#else
#define EDGEZ_DIAGNOSTICS_ENABLED 0
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum edgez_diagnostic_level
{
    EDGEZ_DIAGNOSTIC_OFF = 0,
    EDGEZ_DIAGNOSTIC_ERROR,
    EDGEZ_DIAGNOSTIC_WARNING,
    EDGEZ_DIAGNOSTIC_INFO,
    EDGEZ_DIAGNOSTIC_DEBUG,
};

typedef void (*edgez_diagnostic_sink_fn)(
    void *ctx, enum edgez_diagnostic_level level,
    const char *component, const char *message);

#if EDGEZ_DIAGNOSTICS_ENABLED

/**
 * Install a process-wide diagnostic sink. Passing NULL disables output.
 * Configure the sink before starting worker tasks; changing it concurrently
 * with log delivery is intentionally unsupported.
 */
void edgez_diagnostics_set_sink(edgez_diagnostic_sink_fn sink, void *ctx);

/** Set the most verbose level delivered to the installed sink. */
void edgez_diagnostics_set_level(enum edgez_diagnostic_level level);

#if defined(__GNUC__) || defined(__clang__)
#define EDGEZ_DIAGNOSTIC_PRINTF(format_index, argument_index) \
    __attribute__((format(printf, format_index, argument_index)))
#else
#define EDGEZ_DIAGNOSTIC_PRINTF(format_index, argument_index)
#endif

void edgez_diagnostics_log(enum edgez_diagnostic_level level,
                           const char *component,
                           const char *format, ...)
    EDGEZ_DIAGNOSTIC_PRINTF(3, 4);

#undef EDGEZ_DIAGNOSTIC_PRINTF

#else

/* Disabled diagnostics must not evaluate arguments or retain format strings. */
#define edgez_diagnostics_set_sink(...) ((void)0)
#define edgez_diagnostics_set_level(...) ((void)0)
#define edgez_diagnostics_log(...) ((void)0)

#endif

#ifdef __cplusplus
}
#endif
