#pragma once
#include <array>

struct Profile {
    int id;
    const char* label;
    const wchar_t* wideLabel;
    bool firmwareAndModule;
};

inline constexpr std::array<Profile, 7> profiles{{
    {331, "VMProtect 3.3.1 - x64", L"VMProtect 3.3.1 - x64", false},
    {340, "VMProtect 3.4.0 - x64", L"VMProtect 3.4.0 - x64", false},
    {350, "VMProtect 3.5.0 - x64", L"VMProtect 3.5.0 - x64", false},
    {360, "VMProtect 3.6.0 - x64", L"VMProtect 3.6.0 - x64", false},
    {380, "VMProtect 3.8.0 - x64", L"VMProtect 3.8.0 - x64", false},
    {394, "VMProtect 3.9.4 - x64", L"VMProtect 3.9.4 - x64", true},
    {3101, "VMProtect 3.10.1 - x64", L"VMProtect 3.10.1 - x64", true}
}};
