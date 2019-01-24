/*
    Copyright 2018 Brick

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software
    and associated documentation files (the "Software"), to deal in the Software without restriction,
    including without limitation the rights to use, copy, modify, merge, publish, distribute,
    sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or
    substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
    BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
    NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
    DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <malloc.h>
#include <utility>

#include <stdint.h>

#define RVA2VA(type, base, rva) (type)((ULONG_PTR)base + rva)

// https://github.com/stevemk14ebr/PolyHook_2_0/blob/master/sources/IatHook.cpp
IMAGE_THUNK_DATA* FindIatThunk(void* moduleBase, const char* funcName)
{
    if (moduleBase == nullptr)
        return nullptr;

    IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)moduleBase;
    IMAGE_NT_HEADERS* pNT = RVA2VA(IMAGE_NT_HEADERS*, moduleBase, pDos->e_lfanew);
    IMAGE_DATA_DIRECTORY* pDataDir = (IMAGE_DATA_DIRECTORY*)pNT->OptionalHeader.DataDirectory;

    if (pDataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == NULL) {
        return nullptr;
    }

    IMAGE_IMPORT_DESCRIPTOR* pImports = (IMAGE_IMPORT_DESCRIPTOR*)RVA2VA(uintptr_t, moduleBase, pDataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    // import entry with null fields marks end
    for (uint_fast16_t i = 0; pImports[i].Name != NULL; i++) {
        // Original holds the API Names
        PIMAGE_THUNK_DATA pOriginalThunk = (PIMAGE_THUNK_DATA)
            RVA2VA(uintptr_t, moduleBase, pImports[i].OriginalFirstThunk);

        // FirstThunk is overwritten by loader with API addresses, we change this
        PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)
            RVA2VA(uintptr_t, moduleBase, pImports[i].FirstThunk);

        if (!pOriginalThunk) {
            return nullptr;
        }

        // Table is null terminated, increment both tables
        for (; pOriginalThunk->u1.Ordinal != NULL; pOriginalThunk++, pThunk++) {
            if (IMAGE_SNAP_BY_ORDINAL(pOriginalThunk->u1.Ordinal)) {
                continue;
            }

            PIMAGE_IMPORT_BY_NAME pImport = (PIMAGE_IMPORT_BY_NAME)
                RVA2VA(uintptr_t, moduleBase, pOriginalThunk->u1.AddressOfData);

            if (strcmp(pImport->Name, funcName))
                continue;

            return pThunk;
        }
    }

    return nullptr;
}

void CreateCoreHook(const char* name, void* detour, void** original)
{
    void* module_base = (void*)GetModuleHandleA("binaryninjacore.dll");

    void** iat_thunk = (void**)FindIatThunk(module_base, name);

    DWORD old_protect;
    VirtualProtect(iat_thunk, sizeof(*iat_thunk), PAGE_READWRITE, &old_protect);
    *original = std::exchange(*iat_thunk, detour);
    VirtualProtect(iat_thunk, sizeof(*iat_thunk), old_protect, &old_protect);
}

HANDLE const __acrt_heap = reinterpret_cast<HANDLE>(_get_heap_handle()); // Should be equal to GetProcessHeap()

static inline size_t _msize_nodbg(void* const block)
{
    return static_cast<size_t>(HeapSize(__acrt_heap, 0, block));
}

using realloc_t = decltype(&realloc);

realloc_t realloc_orig = nullptr;

void* realloc_hook(void* ptr, size_t size)
{
    if (ptr) {
        const size_t old_size = _msize_nodbg(ptr);
        const size_t half_old = old_size >> 1;

        if (size > half_old) {
            const size_t new_size = old_size + half_old;

            if (size < old_size)
                return ptr;

            if (size < new_size)
                size = new_size;
        }
    }

    return realloc_orig(ptr, size);
}

void InitHooks()
{
    CreateCoreHook("realloc", &realloc_hook, (void**)&realloc_orig);
}

extern "C" __declspec(dllexport) bool CorePluginInit()
{
    return true;
}

BOOL APIENTRY DllMain(HMODULE /*hinstDLL*/, DWORD fdwReason, LPVOID /*lpvReserved*/)
{
    if (fdwReason == DLL_PROCESS_ATTACH) {
        InitHooks();
    }

    return TRUE;
}
