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
All are accessible from the context menus in the view, and some have hotkeys (MakeMember, JumpToImplementation).

### MakeStruct

Right click on a number in the decompiler view and select 'Make struct'.
You will be prompted to provide a name and a size, the latter defaulting to the clicked-on
number but editable.
A struct will then be created and populated with a byte array of the given size.

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
select 'Analyze vtable'. The number of functions is auto detected (if the scan reaches 100 entries
without finding the end, you'll be asked whether to keep scanning, in case the address wasn't
actually the start of a vtable).
You will first be asked for an (optional) class name; if left blank, it defaults to `class_<vtable address>`.
You will then be asked for the vtable struct name, the type of 'this', and the vtable symbol name, each
prefilled with a default based on the class name (`vtable_<class>`, `<class> *`, and `<class>::__vtable`
respectively), but editable. If the 'this' type doesn't resolve to a known type (e.g. the class
struct hasn't been created yet), you'll get a clear warning telling you to define it first (e.g.
with "Make struct") or use `void *`, instead of an opaque parse failure.
A struct will then be created which represents the vtable - the functions will have a first argument of the
chosen 'this' type, and the names will be auto detected via demangling (or simply func_0x... if this fails).
The new struct type will be applied to the static vtable, and the vtable's symbol will be renamed.
The IDA View is expanded to show the vtable's members instead of leaving it collapsed to a single
"terse" summary line.

### SetVtableComment

Right click on an assigment of a global vtable to a struct member in the Hexrays decompiler view, and select 'Set vtable comment'.
The target member must be pointer-sized. If it's part of a larger byte array (e.g. an
auto-generated `field_XX` array that hasn't been split yet), a pointer-sized member is carved out
of it at the assigned offset first, the same way MakeMember would. If it's some other, differently
sized member, the action fails with a clear error instead of silently misinterpreting the write.
A comment will be appended to the struct member indicating the address of the vtable.
The address will be calculated correctly, taking into account possible pointer arithmetic (as is often the case where
the start of the vtable functions is a few bytes after the referenced symbol).
Also, the IDA view will jump to the address of the vtable, to facilitate use of "AnalyzeVtable" if needed.
You will then be asked whether to analyze the vtable right away (same as running "AnalyzeVtable" at
that address). If you do, and it succeeds, the struct member's type is set to a pointer to the newly
created vtable struct, and the member is renamed to `__vtable` (or `__vtable_<offset>` if its offset
within the struct isn't 0). The Hexrays view is refreshed so the new type and name are visible
immediately.

### JumpToVtable

Right click on a struct vtable member (previously set with SetVtableComment), and select "Jumpt to vtable". The IDA disassembly view
will jump to the address of the vtable.
If multiple vtable commented have been set for the memeber, you will be provided with a dropdown menu to choose from.

### JumpToImplementation

Right click on a vtable slot being called in the Hexrays decompiler view (e.g. the 'Func_18' in
`tcb->field_vtable->Func_18(tcb)`, where 'field_vtable' was previously tagged with SetVtableComment),
and select "Jump to implementation" (or click on the slot and hit the hotkey "Ctrl-J").
For each vtable address registered on 'field_vtable', the vtable's size is determined (the same
way AnalyzeVtable does) and candidates too small to have an entry at the called slot are pruned -
this avoids offering a 'function' that is actually just the next vtable in memory, or a random
qword, when a base class vtable is registered on the member but doesn't declare the called virtual
function. For each remaining candidate, the called slot's offset is added and dereferenced to find
the actual implementing function, and the disassembly/pseudocode view jumps there directly - no
need to jump to the vtable first and double-click the right entry.
If multiple vtables are registered for the member, you will be provided with a chooser listing each
candidate's vtable type, vtable symbol name, vtable address, function symbol name, and function
address, to choose from.
