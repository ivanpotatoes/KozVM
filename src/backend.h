#pragma once

// Only the early x64 CPUID backend is published in this snapshot.
namespace Backend {
bool available(int profile);
bool apply(int profile, bool enabled, bool cpuid);
bool stop(bool stopping = false);
void reset();
void cleanSavedBreakpoints();
bool hit(int argc, char** argv);
bool status(int argc, char** argv);
}
