#ifndef VERSION_H
#define VERSION_H

// Version information for IoT Gateway Application
// Increment these numbers for each release:
// - PATCH: Bug fixes and minor changes (1.0.0 -> 1.0.1)
// - MINOR: New features, backward compatible (1.0.0 -> 1.1.0)
// - MAJOR: Breaking changes (1.0.0 -> 2.0.0)
#define VERSION_MAJOR 1
#define VERSION_MINOR 0
#define VERSION_PATCH 0

// Build information (can be injected at compile time)
#ifndef BUILD_DATE
#define BUILD_DATE __DATE__
#endif

#ifndef BUILD_TIME
#define BUILD_TIME __TIME__
#endif

#ifndef GIT_COMMIT
#define GIT_COMMIT "unknown"
#endif

#ifndef BUILD_NUMBER
#define BUILD_NUMBER "local"
#endif

// Helper macros to stringify version numbers
#define STRINGIFY(x) #x
#define TO_STRING(x) STRINGIFY(x)

// Full version string
#define VERSION_STRING \
    TO_STRING(VERSION_MAJOR) "." TO_STRING(VERSION_MINOR) "." TO_STRING(VERSION_PATCH)

// Full version info with build metadata
#define VERSION_FULL_STRING \
    "v" VERSION_STRING " (build: " BUILD_NUMBER ", " BUILD_DATE " " BUILD_TIME ")"

// Version comparison helpers
#define VERSION_AT_LEAST(major, minor, patch) \
    ((VERSION_MAJOR > major) || \
     (VERSION_MAJOR == major && VERSION_MINOR > minor) || \
     (VERSION_MAJOR == major && VERSION_MINOR == minor && VERSION_PATCH >= patch))

#endif // VERSION_H
