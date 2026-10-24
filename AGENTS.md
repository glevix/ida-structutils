# AGENTS.md

## What this is

An IDA Pro plugin (IDA 9 only — older versions won't work due to IDA API changes). It adds
right-click actions in the Hex-Rays decompiler view and the disassembly view for faster struct
editing: splitting byte arrays into typed members, creating structs from clicked literals,
detecting/reconstructing vtables, and syncing function argument types from call sites.

There is no build step, package manager, or test suite — this is pure Python 2 modules that IDA
loads directly via its plugin API (`idaapi`, `ida_kernwin`, `ida_typeinf`, `ida_hexrays`, etc.).
Nothing here runs or imports outside of a live IDA process, so there is no way to unit-test or
execute this code standalone — IDA's `idaapi`/`ida_*` modules only exist inside the IDA Python
runtime.

## Layout

- `structutils.py` — plugin entry point (`PLUGIN_ENTRY`), registers/unregisters actions on load/unload.
- `structutils_resources/actions.py` — generic framework: `ActionManager`, `Action` base classes
  for popup menu actions in the pseudocode view (`HexRaysPopupAction`) vs. the disassembly view
  (`IdaViewPopupAction`), and the Hex-Rays event callback plumbing.
- `structutils_resources/utils.py` — all actual features live here as `Action` subclasses
  (`MakeStruct`, `MakeMember`, `CommitType`, `AnalyzeVtable`, `SetVtableComment`, `JumpToVtable`,
  plus the debug helper `HexRaysDebug`). Each is instantiated and registered at the bottom of the file.
- `structutils_resources/__init__.py` — re-exports `actions` and `utils`.
- `install.sh` — copies `structutils.py` and `structutils_resources/` into `~/.idapro/plugins`.
  `install.sh --uninstall` removes them (prompts for confirmation either way).
- `AGENTS.txt` — empty, unused; leave it unless the user asks to clean it up.

## How features are wired up

Every feature is a subclass of `HexRaysPopupAction` (pseudocode/decompiler view) or
`IdaViewPopupAction` (disassembly view), implementing:
- `check(hx_view)` — decides whether the action should appear in the popup for the current cursor item.
- `activate(ctx)` — runs when the user selects the action.

New actions must be instantiated and passed to `actions.action_manager.register(...)` at module
load time (see the bottom of `utils.py`) to actually show up.

Hex-Rays cursor items are inspected via `hx_view.item.e` (a `cexpr_t`), walking the AST with
`hx_view.cfunc.body.find_parent_of(expr)` to figure out what was clicked and what contains it
(casts, derefs, array indexing, assignments). `EXPR_TYPES`/`expr_str` in `utils.py` is a lookup
table for debugging `cot_*`/`cit_*` op codes — `HexRaysDebug` prints the op of whatever's under
the cursor, which is the fastest way to understand a new AST shape when extending an action.

## Notable constraints / gotchas

- IDA 9 removed the `ida_struct` module (e.g. `get_struc`, `get_member`). This codebase
  reimplements the needed bits on top of `ida_typeinf.tinfo_t` and `idautils.StructMembers`
  (`get_struc`, `get_member_details` in `utils.py`) — don't reintroduce `ida_struct` calls.
- Struct member mutation goes through the legacy `idc.add_struc_member`/`idc.del_struc_member`
  calls (not the tinfo-based udt APIs) — error codes are documented inline above
  `make_member_from_array`.
- `get_vtable_size` guesses vtable length heuristically (stops at next symbol, an xref, or a
  non-code pointer) — there's no reliable "end of vtable" marker in IDA, so this is inherently
  best-effort and worth noting in review if changed.

## Verifying changes

There's no automated test suite and no CI. The only way to check behavior is to install
(`./install.sh`) into a real IDA 9 + Hex-Rays setup and exercise the action manually against a
binary, per the usage steps in `README.md`. When making changes, read the affected `Action`
carefully rather than expecting to run anything — flag to the user that manual IDA testing is
needed rather than claiming verification you can't actually perform.

## Conventions

- Logging goes through the module-level `LOG` logger in `utils.py` (`LOG.debug`/`.info`/`.warning`/`.error`), not `print`.
- Actions return `True`/`False` from `activate`/helpers to signal success; on failure, surface an
  `ida_kernwin.warning(...)` to the user in addition to logging.
- README.md is the user-facing feature doc — if you change an action's behavior or add a new one,
  update the corresponding section there too.
