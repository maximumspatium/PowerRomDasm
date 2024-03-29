'''
    Provides a mapping from 68k traps to Macintosh traps names.

    Author: Max Poliakovski 2020-2021
'''
TRAP_TABLE = {
    # trapN    trap name
    0xA000 : "_Open",
    0xA001 : "_Close",
    0xA002 : "_Read",
    0xA004 : "_Control",
    0xA005 : "_Status",
    0xA019 : "_InitZone",
    0xA01B : "_SetZone",
    0xA01F : "_DisposePtr",
    0xA023 : "_DisposeHandle",
    0xA029 : "_HLock",
    0xA02D : "_SetApplLimit",
    0xA02E : "_BlockMove",
    0xA036 : "_MoreMasters",
    0xA038 : "_WriteParam",
    0xA03B : "_Delay",
    0xA03F : "_InitUtil",
    0xA047 : "_SetTrapAddress",
    0xA04A : "_HNoPurge",
    0xA051 : "_ReadXPRam",
    0xA052 : "_WriteXPRam",
    0xA055 : "_StripAddress",
    0xA057 : "_SetAppBase",
    0xA064 : "_MoveHHi",
    0xA069 : "_HGetState",
    0xA06A : "_HSetState",
    0xA06C : "_InitFS",
    0xA06E : "_SlotManager",
    0xA077 : "_CountADBs",
    0xA078 : "_GetIndADB",
    0xA07A : "_SetADBInfo",
    0xA07D : "_GetDefaultStartup",
    0xA07F : "_InternalWait",
    0xA084 : "_GetOSDefault",
    0xA085 : "_PMgrOp",
    0xA0AD : "_GestaltDispatch",
    0xA0BD : "_CacheFlush",
    0xA11A : "_GetZone",
    0xA11E : "_NewPtr",
    0xA122 : "_NewHandle",
    0xA128 : "_RecoverHandle",
    0xA146 : "_GetTrapAddress",
    0xA162 : "_PurgeSpace",
    0xA198 : "_HWPriv",
    0xA1AD : "_Gestalt",
    0xA025 : "_GetHandleSize",
    0xA31E : "_NewPtrClear",
    0xA322 : "_NewHandleClear",
    0xA346 : "_GetOSTrapAddress",
    0xA440 : "_ReserveMemSys",
    0xA51E : "_NewPtrSys",
    0xA522 : "_NewHandleSys",
    0xA71E : "_NewPtrSysClear",
    0xA722 : "_NewHandleSysClear",
    0xA746 : "_GetToolTrapAddress",
    0xA817 : "_CopyMask",
    0xA81F : "_Get1Resource",
    0xA820 : "_Get1NamedResource",
    0xA851 : "_SetCursor",
    0xA852 : "_HideCursor",
    0xA86E : "_InitGraf",
    0xA895 : "_ShutDown",
    0xA89B : "_PenSize",
    0xA89E : "_PenNormal",
    0xA8A5 : "_FillRect",
    0xA8A9 : "_InsetRect",
    0xA8B0 : "_FrameRoundRect",
    0xA8B4 : "_FillRoundRect",
    0xA96E : "_Dequeue",
    0xA992 : "_DetachResource",
    0xA994 : "_CurResFile",
    0xA99B : "_SetResLoad",
    0xA9A0 : "_GetResource",
    0xA9A1 : "_GetNamedResource",
    0xA9A2 : "_LoadResource",
    0xA9AF : "_ResError",
    0xA9C9 : "_SysError",
    0xAA00 : "_OpenCPort",
    0xABEB : "_DisplayDispatch",
}
