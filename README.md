# ida-structutils

Utils for increased productivity with ida, like editing structs from the hexrays decompiler view.

## IDA support

Supports IDA9.
Older versions of IDA are not supported, and probably wont work due to IDAAPI changes.

## Installation

The install.sh script will copy the required files to your IDA plugins directory ("~/.idapro/plugins").
Passing --uninstall will delete them

## Use

Utils are to be used from the Disassembly view (AnalyzeVtable), or the Pseudocode view (all others).
All are accessible from the context menus in the view, and some have hotkeys (MakeMember).

### MakeStruct

Right click on a number in the decompiler view and select 'Make struct'.
You will be prompted to provide a name.
A struct will then be created and populated with a byte array of the clicked-on size.

The action fails if the struct already exists, unless it is unpopulated (often happens with non-standard types, that IDA can infer the existence of through debug info or name demangling).
In this case, the struct is populated to the correct size.

### MakeMember (Useful! Hotkey: m)

Right click on a assignment to (or read from) a pointer to a struct type, at a certain offset, and select "Make member" (or click on the access and hit the hotkey "m").
Once clicked, the memory access size is determined, and the struct member is 'split' into 3 parts - an anonimous array above and below the memory access, and a single member of the correct size at the offset of the memory access.

This is similar to IDAs built-in "Create new struct type" feature, but with more fine-grained control over where members should be created.
It works any time the memory access is contained within a byte array inside a struct.

### CommitType

Right click on on of the arguments of a function call in the Hexrays decompiler view, and select 'Commit type'
The signature of the function being called will be edited to accept the clicked-on type.

### AnalyzeVtable

Right click on the start of a static vtable (or any static array of functions) in the disassembly view (IDA view), and
select 'Analyze vtable'. The number of functions is auto detected, and a struct will be created which represents the vtable. 
The functions will have a first argument of the chosen type (or void pointer), and the names will be auto detected
via demangling (or simply func_0x... if this fails).
The new type will be applied to the static vtable.

### SetVtableComment

Right click on an assigment of a global vtable to a struct member in the Hexrays decompiler view, and select 'Set vtable comment'.
A comment will be appended to the struct member indicating the address of the vtable.
The address will be calculated correctly, taking into account possible pointer arithmetic (as is often the case where
the start of the vtable functions is a few bytes after the referenced symbol).
Also, the IDA view will jump to the address of the vtable, to facilitate use of "AnalyzeVtable" if needed.

### JumpToVtable

Right click on a struct vtable member (previously set with SetVtableComment), and select "Jumpt to vtable". The IDA disassembly view
will jump to the address of the vtable.
If multiple vtable commented have been set for the memeber, you will be provided with a dropdown menu to choose from.
