# ida-structutils
Utils for increased productivity with ida, like editing structs from the hexrays decompiler view

## Installation

The install.sh script will copy the required files to your IDA plugins directory ("~/.idapro/plugins").
Passing --uninstall will delete them

## Use

Currently all plugins are to be used from the Hexrays decompiler view

### MakeStruct

Right click on a number in the decompiler view and select 'Make struct'.
You will be prompeted to provide a name.
A struct will then be created populated with a byte array of the clicked-on size.

The action fails if the struct already exists, unless it is unpopulated (often happens when the existence of the type can be inferred by IDA).
In this case, the struct is populated to the correct size.

### CommitType

Right click on on of the arguments of a function call in the Hexrays decompiler view, and select 'Commit type'
The signature of the function being called will be edited to accept the clicked-on type.

### MakeMember

Very useful!

Right click on a assignment to (or read from) a pointer to a struct type, at a certain offset, and select "Make member" (or click on the access and hit the hotkey "m").
Once clicked, the memory access size is determined, and the struct member is 'split' into 3 parts - an anonimous array above and below the memory access, and a single member of the correct size at the offset of the memory access.

This is similar to IDAs built-in "Create new struct type" feature, but with more fine-grained control over where members should be created.
It works any time the memeory access is contained within a byte array inside a struct.

Hotkey: m

