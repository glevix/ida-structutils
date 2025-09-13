# ida-structutils

Utils for increased productivity with ida, like editing structs from the hexrays decompiler view.

## IDA support

Supports IDA9.
Older versions of IDA are not supported, and probably wont work due to IDAAPI changes.

## Installation

The install.sh script will copy the required files to your IDA plugins directory ("~/.idapro/plugins").
Passing --uninstall will delete them

## Use

Currently all plugins are to be used from the Hexrays decompiler view

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

