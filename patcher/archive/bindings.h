#pragma once
#include <windows.h>

// Serialized by archive_patch.py. Keep every native layout detail in the profile.
struct ArchiveBinding {
    DWORD engineRva, originalRva, loadLibraryRva, getProcRva, ntPointerRva;
    DWORD openSelectionRva, describeItemRva, openPrologueBytes;
    DWORD panelModelOffset, panelSelectionModeOffset, panelCursorOffset;
    DWORD panelSelectionCountOffset, panelSelectionArrayOffset, selectionStride;
    DWORD itemFlagsOffset, descriptorPathOffset, descriptorLengthOffset;
    DWORD clipboardRva, clipboardPrologueBytes, clipboardListOffset;
    DWORD dragRva, dragPrologueBytes, dragOwnerOffset, dragActiveOffset;
    DWORD sidebarOpenRva, sidebarOpenPrologueBytes;
};
