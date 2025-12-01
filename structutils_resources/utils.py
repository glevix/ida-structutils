import idaapi
#import ida_struct
import ida_funcs
import ida_kernwin
import ida_name
import ida_ida
import ida_bytes
import ida_typeinf
import ida_xref
import idc
import idautils
from . import actions

class StructUtilsException(Exception):
    pass

'''
IDA9 got rid of the ida_struct module, and with it the ida_struct.get_struc function
'''
def get_struc(struct_id):
    tif = ida_typeinf.tinfo_t()
    if tif.get_type_by_tid(struct_id):
        if tif.is_struct():
            return tif
    return idaapi.BADADDR

'''
IDA9 got rid of the ida_struct module, and with it the ida_struct.get_member function 
'''
def get_member_details(struct_id, offset):
    members = idautils.StructMembers(struct_id)
    if members:
        for moffset, name, size in members:
            if moffset == offset:
                return name, size
    else:
        print(f"No members found in structure with id '{struct_id}'")

'''
Helper function for introducing a new member into a struct, inside an array of bytes.
The new member will be created at the specified offset in the array, thereby splitting the array into 2 parts
'''
def make_member_from_array(struct_name, array_offset, offset_in_array, member_size, member_name=None):

    print(f'make_member_from_array({struct_name}, {array_offset}, {offset_in_array}, {member_size}, {member_name})')

    if member_size not in TYPES:
        print(f'Illegal member size {member_size}')
        return False
    if offset_in_array < 0:
        print(f'Illegal offset {offset_in_array}')
        return False

    struct_id = idc.get_struc_id(struct_name)
    tid = ida_typeinf.get_named_type_tid(struct_name)

    if tid != struct_id:
        print('Struct id and tid dont match')
        return False
    
    if struct_id == idaapi.BADADDR:
        print(f'Could not get struct id for {struct_name}')
        return False

    struct = get_struc(struct_id)

    # TODO replace with tinfo_t.find_udb
    _, array_size = get_member_details(struct_id, array_offset)

    if array_size <= 0:
        print(f'Bad array size: {array_size}')
        return False

    top = array_size - (offset_in_array + member_size)
    if top < 0:
        print(f'Size would overrun array')
        return False

    if not member_name:
        member_name = f'field_{array_offset + offset_in_array:02X}'

    # Delete the original array
    idc.del_struc_member(struct_id, array_offset + offset_in_array)

    '''
    Possible error codes for idc.add_struc_member:
    -1: already has member with this name (bad name)
    -2: already has member at this offset
    -3: bad number of bytes or bad sizeof(type)
    -4: bad typeid parameter
    -5: bad struct id (the 1st argument)
    -6: unions can't have variable sized members
    -7: variable sized member should be the last member in the structure
    -8: recursive structure nesting is forbidden
    '''

    # Add the new member
    error = idc.add_struc_member(struct_id, member_name, array_offset + offset_in_array, (TYPES[member_size]|idaapi.FF_DATA )&0xFFFFFFFF, -1, member_size)
    if error:
        print(f'Error {error} adding new member')
        return False

    if offset_in_array:
        # Add gap array below
        error = idc.add_struc_member(struct_id, f'field_{array_offset:02X}', array_offset, (TYPES[1]|idaapi.FF_DATA )&0xFFFFFFFF, -1, offset_in_array)
        if error:
            print(f'Error {error} adding gap array below new member')
            return False

    if top:
        # Add gap array above
        error = idc.add_struc_member(struct_id, f'field_{array_offset + offset_in_array + member_size:02X}', array_offset + offset_in_array + member_size, (TYPES[1]|idaapi.FF_DATA )&0xFFFFFFFF, -1, top)
        if error:
            print(f'Error {error} adding gap array above new member')
            return False

    return True

'''
IDA basic type sizes
'''
TYPES = {
    1: idaapi.FF_BYTE,
    2: idaapi.FF_WORD,
    4: idaapi.FF_DWORD,
    8: idaapi.FF_QWORD,
    16: idaapi.FF_OWORD,
    }

'''
Provides a 'Make struct' option in the dissasembly context right-click dropdown list,
whenever the cursor is on a number.
Once clicked, a popup will request the new struct name, and a new struct will be created
with the size of the number
'''
class MakeStruct(actions.HexRaysPopupAction):

    description = 'Make struct'

    def __init__(self):
        super(MakeStruct, self).__init__()

    def check(self, hx_view):
        # Only makes sense for expressions
        if hx_view.item.citype != idaapi.VDI_EXPR:
            return False
        op = hx_view.item.e.op
        if op == idaapi.cot_num:
            return True
        else:
            return False

    def activate(self, ctx):

        hx_view = idaapi.get_widget_vdui(ctx.widget)
        size = hx_view.item.e.numval()
        name = ida_kernwin.ask_str("", 0, "New struct name:")

        tid = ida_typeinf.get_named_type_tid(name)
        if tid != idaapi.BADADDR:
            tif = ida_typeinf.tinfo_t()
            if not tif.get_type_by_tid(tid):
                print(f'"{name}" has a tid but no type - bug in IDA?')
                return False
            if tif.present():
                print(f'"{name}" already exists')
                return False
            else:
                print(f'"{name}" already exists as a non-present type, populating')
                if ida_typeinf.idc_parse_types(f'struct {name}{{}};', 0):
                    print(f'Failed')
                    return False
                print(f'Populated struct type "{name}"')
        else:
            tid = idc.add_struc(idaapi.BADADDR, name, False)
            struct = get_struc(tid)
            if not struct:
                print("Failed")
                return False
            print(f'Created new struct type "{name}"')


        error = idc.add_struc_member(tid, "field_0", 0, (TYPES[1]|idaapi.FF_DATA )&0xFFFFFFFF, -1, size)
        if error:
            print(f'Error {error} adding new member')
            return False

        return True

'''
Provides a 'Make member' option in the dissasembly context right-click dropdown list,
whenever the cursor is on an array index of a struct member, or a struct member.
Once clicked, the memory access size is determined, and the struct member is 'split'
into 3 parts - an anonimous array above and below the memory access, and a single
member of the correct size at the offset of the memory access.
VERY USEFUL!
'''
class MakeMember(actions.HexRaysPopupAction):

    description = 'Make member'
    hotkey = 'M'

    def __init__(self):
        super(MakeMember, self).__init__()

    def check(self, hx_view):
        # Only makes sense for expressions
        if hx_view.item.citype != idaapi.VDI_EXPR:
            return False
        op = hx_view.item.e.op
        if op == idaapi.cot_num:
            # User possibly clicked in the index of the array
            return True
        if op == idaapi.cot_memref or op == idaapi.cot_memptr:
            # User possibly clicked the array itself
            return True
        return False

    def activate(self, ctx):

        hx_view = idaapi.get_widget_vdui(ctx.widget)

        #print(f'First OP: {hx_view.item.e.op}')

        if hx_view.item.e.op == idaapi.cot_num:
            return self.from_array_index(hx_view, hx_view.item.e)
        else:
            # cot_memptr or cot_memref
            return self.from_member(hx_view, hx_view.item.e)

    def from_member(self, hx_view, indexee_expression):

        # indexee_expression is the item representing the accessing of the array from the struct (x.m / x->m)
        # example (the 'field_2C8' is clicked): *(_QWORD *)&tcb->field_2C8[48] = 0i64
        # example (the 'field_3D' is clicked, and is an array of bytes): *(_QWORD *)tcb->field_3D0 = 0i64;

        next_expression = hx_view.cfunc.body.find_parent_of(indexee_expression).to_specific_type
        #print(f'Parent: {next_expression.op}')
        if next_expression.op == idaapi.cot_idx:
            return self.from_array_index(hx_view, next_expression.y)
        elif next_expression.op != idaapi.cot_cast:
            print(f'Aborting: parent of memref/memptr expression is not idx or cast')
            return False
        casting_expression = next_expression

        # This is the item representing the deref (*)
        ptr_expression = hx_view.cfunc.body.find_parent_of(casting_expression).to_specific_type
        if ptr_expression.op != idaapi.cot_ptr:
            print(f'Aborting: casting expression is not inside a ptr expression ({ptr_expression.op})')
            return False

        if indexee_expression.op == idaapi.cot_memptr:
            typeinfo = indexee_expression.x.type.get_pointed_object()
        elif indexee_expression.op == idaapi.cot_memref:
            typeinfo = indexee_expression.x.type

        # Get the size of the actual memory access
        new_member_size = ptr_expression.ptrsize

        # Get the offset of the member itself
        old_member_offset = indexee_expression.m

        struct_name = typeinfo.dstr()

        if make_member_from_array(struct_name, old_member_offset, 0, new_member_size, member_name=None):
            hx_view.refresh_view(True)
            return True
        else:
            print(f'Failed')  
            return False

    def from_array_index(self, hx_view, array_offset_expression):

        # array_offset_expression is the item representing the number inside the square brackets
        # example (the '48' is clicked): *(_QWORD *)&tcb->field_2C8[48] = 0i64

        # This is the item representing the square brackets
        indexing_expression = hx_view.cfunc.body.find_parent_of(array_offset_expression).to_specific_type # ida_hexrays.cexpr_t
        if indexing_expression.op != idaapi.cot_idx:
            print(f'Aborting: num expression is not inside an indexing expression ({indexing_expression.op})')
            return False

        # This is the object being indexed by the square brackets
        indexee_expression = indexing_expression.x
        if indexee_expression.op == idaapi.cot_memptr:
            typeinfo = indexee_expression.x.type.get_pointed_object()
        elif indexee_expression.op == idaapi.cot_memref:
            typeinfo = indexee_expression.x.type
        else:
            print(f'Aborting: indexee expression is not a memref or memptr ({indexee_expression.op})')
            return False

        # Now look for the "*(cast)&" sequence. TODO handle the case where there isnt one
        # If the next expression is one of the following, the array deref is direct
        finals = [idaapi.cot_cast, idaapi.cit_if, idaapi.cot_band, idaapi.cot_ugt]

        next_expression = hx_view.cfunc.body.find_parent_of(indexing_expression).to_specific_type
        if next_expression.op == idaapi.cot_ref:
            referencing_expression = next_expression

            # This is the item representing the cast
            casting_expression = hx_view.cfunc.body.find_parent_of(referencing_expression).to_specific_type
            if casting_expression.op != idaapi.cot_cast:
                print(f'Aborting: referencing expression is not inside a casting expression ({casting_expression.op})')
                return False

            next_expression = hx_view.cfunc.body.find_parent_of(casting_expression).to_specific_type
            if next_expression.op == idaapi.cot_ptr:
                member_size = next_expression.ptrsize
            elif next_expression.op == idaapi.cot_call:
                print(f'Aborting: Memory reference passed to function, no way to guess size')
                return False
                # TODO: if the cast type is a pointer, we can infer the size, but this would still be risky
                # We could also just set the size to 1, so that the offset can be given a meaningful name
                # until the type can be inferred.
                #member_size = casting_expression.type.get_size()
            else:
                print(f'Aborting: casting expression is not inside a ptr or call expression ({next_expression.op})')
                return False
        elif idaapi.is_assignment(next_expression.op) or next_expression.op in finals:
            # The array element is being accessed directly - get the size from the array type
            member_type = indexee_expression.type.get_array_element()
            member_size = member_type.get_size()
        else:
            print(f'Aborting. Parent of indexing expression is not reference or assignment ({next_expression.op})')
            return False

        # We now have all the items we need. Start making the calculations

        #print(f'Access size is {member_size}')

        # Get the offset within the array
        offset_in_array = array_offset_expression.numval()
        #print(f'Offset in array is {offset_in_array}')

        # Get the offset of the array itself
        array_offset = indexee_expression.m
        #print(f'Array offset is {hex(array_offset)}')

        struct_name = typeinfo.dstr()

        if make_member_from_array(struct_name, array_offset, offset_in_array, member_size, member_name=None):
            hx_view.refresh_view(True)
            return True
        else:
            print(f'Failed')
            return False

EXPR_TYPES = {
  0: ('cot_empty', ''),
  1: ('cot_comma', 'x, y'),
  2: ('cot_asg', 'x = y'),
  3: ('cot_asgbor', 'x |= y'),
  4: ('cot_asgxor', 'x ^= y'),
  5: ('cot_asgband', 'x &= y'),
  6: ('cot_asgadd', 'x += y'),
  7: ('cot_asgsub', 'x -= y'),
  8: ('cot_asgmul', 'x *= y'),
  9: ('cot_asgsshr', 'x >>= y signed'),
  10: ('cot_asgushr', 'x >>= y unsigned'),
  11: ('cot_asgshl', 'x <<= y'),
  12: ('cot_asgsdiv', 'x /= y signed'),
  13: ('cot_asgudiv', 'x /= y unsigned'),
  14: ('cot_asgsmod', 'x %= y signed'),
  15: ('cot_asgumod', 'x %= y unsigned'),
  16: ('cot_tern', 'x ? y : z'),
  17: ('cot_lor', 'x || y'),
  18: ('cot_land', 'x && y'),
  19: ('cot_bor', 'x | y'),
  20: ('cot_xor', 'x ^ y'),
  21: ('cot_band', 'x & y'),
  22: ('cot_eq', 'x == y int or fpu (see EXFL_FPOP)'),
  23: ('cot_ne', 'x != y int or fpu (see EXFL_FPOP)'),
  24: ('cot_sge', 'x >= y signed or fpu (see EXFL_FPOP)'),
  25: ('cot_uge', 'x >= y unsigned'),
  26: ('cot_sle', 'x <= y signed or fpu (see EXFL_FPOP)'),
  27: ('cot_ule', 'x <= y unsigned'),
  28: ('cot_sgt', 'x >  y signed or fpu (see EXFL_FPOP)'),
  29: ('cot_ugt', 'x >  y unsigned'),
  30: ('cot_slt', 'x <  y signed or fpu (see EXFL_FPOP)'),
  31: ('cot_ult', 'x <  y unsigned'),
  32: ('cot_sshr', 'x >> y signed'),
  33: ('cot_ushr', 'x >> y unsigned'),
  34: ('cot_shl', 'x << y'),
  35: ('cot_add', 'x + y'),
  36: ('cot_sub', 'x - y'),
  37: ('cot_mul', 'x * y'),
  38: ('cot_sdiv', 'x / y signed'),
  39: ('cot_udiv', 'x / y unsigned'),
  40: ('cot_smod', 'x % y signed'),
  41: ('cot_umod', 'x % y unsigned'),
  42: ('cot_fadd', 'x + y fp'),
  43: ('cot_fsub', 'x - y fp'),
  44: ('cot_fmul', 'x * y fp'),
  45: ('cot_fdiv', 'x / y fp'),
  46: ('cot_fneg', '-x fp'),
  47: ('cot_neg', '-x'),
  48: ('cot_cast', '(type)x'),
  49: ('cot_lnot', '!x'),
  50: ('cot_bnot', '~x'),
  51: ('cot_ptr', '*x, access size in \'ptrsize\''),
  52: ('cot_ref', '&x'),
  53: ('cot_postinc', 'x++'),
  54: ('cot_postdec', 'x--'),
  55: ('cot_preinc', '++x'),
  56: ('cot_predec', 'x'),
  57: ('cot_call', 'x(...)'),
  58: ('cot_idx', 'x[y]'),
  59: ('cot_memref', 'x.m'),
  60: ('cot_memptr', 'x->m, access size in \'ptrsize\''),
  61: ('cot_num', 'n'),
  62: ('cot_fnum', 'fpc'),
  63: ('cot_str', 'string constant'),
  64: ('cot_obj', 'obj_ea'),
  65: ('cot_var', 'v'),
  66: ('cot_insn', 'instruction in expression, internal representation only'),
  67: ('cot_sizeof', 'sizeof(x)'),
  68: ('cot_helper', 'arbitrary name'),
  69: ('cot_type', 'arbitrary type'),
  69: ('cot_last', ''),
  70: ('cit_empty', 'instruction types start here'),
  71: ('cit_block', 'block-statement: { ... }'),
  72: ('cit_expr', 'expression-statement: expr;'),
  73: ('cit_if', 'if-statement'),
  74: ('cit_for', 'for-statement'),
  75: ('cit_while', 'while-statement'),
  76: ('cit_do', 'do-statement'),
  77: ('cit_switch', 'switch-statement'),
  78: ('cit_break', 'break-statement'),
  79: ('cit_continue', 'continue-statement'),
  80: ('cit_return', 'return-statement'),
  81: ('cit_goto', 'goto-statement'),
  82: ('cit_asm', 'asm-statement'),
}

def expr_str(op):
    return f'{EXPR_TYPES[op][0]} (  {EXPR_TYPES[op][1]}  )'


'''
Provides a 'Commit type' option in the dissasembly context right-click dropdown list,
whenever the cursor is on an argument in a function call.
Once clicked, the matching function argument type is set to the type of the passed argument,
ignoring cast, and the decompiler function signature is synced to the database.
'''
class CommitType(actions.HexRaysPopupAction):

    description = 'Commit type'

    def __init__(self):
        super(CommitType, self).__init__()

    def check(self, hx_view):
        # Only makes sense for expressions
        if hx_view.item.citype != idaapi.VDI_EXPR:
            return False
        return True

    '''
    Helper to apply the new type to a function object
    '''
    def apply_to_object(self, func_address, func_tinfo, arg_index, arg_tinfo):

        # First sync the decompiler tinfo, otherwise we cannot get the function details
        ida_typeinf.apply_tinfo(func_address, func_tinfo, idaapi.TINFO_DEFINITE)

        # Get the DB tinfo
        old_tif = idaapi.tinfo_t()
        idaapi.get_tinfo(old_tif, func_address)

        # Get the function details
        funcdata = idaapi.func_type_data_t()
        old_tif.get_func_details(funcdata)

        # Edit the argument type
        funcdata.at(arg_index).type = arg_tinfo

        # Commit the edit to the DB
        new_tif = idaapi.tinfo_t()
        new_tif.create_func(funcdata)
        idaapi.apply_tinfo(func_address, new_tif, idaapi.TINFO_DEFINITE)

    def activate(self, ctx):

        hx_view = idaapi.get_widget_vdui(ctx.widget)
        arg = hx_view.item.e
        call = hx_view.cfunc.body.find_parent_of(arg).to_specific_type

        while call.op != idaapi.cot_call:
            arg = call
            call = hx_view.cfunc.body.find_parent_of(arg).to_specific_type
            if not call.is_expr():
                print('Aborting: could not find call expression')
                return False

        if arg.op == idaapi.cot_cast:
            typeinfo = arg.x.type
        else:
            typeinfo = arg.type

        try:
            index = list(call.a).index(arg)
        except ValueError:
            print('Could not find arg in arg list - make sure you are clicking on a call argument')
            return False
        #print(f'Arg type is {typeinfo.dstr()}, index is {index}')

        function = call.x
        if function.op == idaapi.cot_helper:
            print(f'Not a real function (cot_helper) - aborting')
            return False
        elif function.op == idaapi.cot_obj:
            self.apply_to_object(function.obj_ea, function.type, index, typeinfo)
            hx_view.refresh_view(True)
            return True
        else:
            print(f'Unsupported function expression type {expr_str(function.op)} - aborting')
            return False




def get_nearest_symbols(ea):
    n = ida_name.get_nlist_size()

    prev_sym = None, None
    next_sym = None, None

    for i in range(n):
        sym_ea = ida_name.get_nlist_ea(i)

        if sym_ea < ea:
            prev_sym = (sym_ea, ida_name.get_nlist_name(i))
        elif sym_ea > ea:
            next_sym = (sym_ea, ida_name.get_nlist_name(i))
            break

    return prev_sym, next_sym

def has_xrefs_to(ea):
    """
    Return True if 'ea' has any real code or data xrefs pointing to it.
    Works in IDA 7.x → 9.x.
    """
    for xref in idautils.XrefsTo(ea):
        t = xref.type
        # Code reference flags
        code_flags = ida_xref.fl_CF | ida_xref.fl_CN | ida_xref.fl_JF | ida_xref.fl_JN | ida_xref.fl_F
        # Data reference flags
        data_flags = ida_xref.dr_R | ida_xref.dr_W | ida_xref.dr_O
        if t & (code_flags | data_flags):
            return True
    return False

def ptr_points_to_code(ea):
    """
    Returns True if the memory at 'ea' contains a pointer to code.
    """
    # Get pointer size
    ptr_size = 8 if ida_ida.inf_is_64bit() else 4

    # Read pointer value
    if ptr_size == 8:
        target_ea = ida_bytes.get_qword(ea)
    else:
        target_ea = ida_bytes.get_dword(ea)

    if target_ea is None or target_ea == 0:
        return False

    # Check if target_ea is a function
    if ida_funcs.get_func(target_ea):
        return True

    # Optionally, check if target_ea is an instruction (code)
    flags = ida_bytes.get_full_flags(target_ea)
    if ida_bytes.is_code(flags):
        return True

    return False

def get_vtable_size(ea):

    func = ida_funcs.get_func(ea)
    if func:
        ida_kernwin.warning(f'Error: {hex(ea)} is in a function - cannot be a vtable')
        return 0

    # Check surrounding symbols
    name = ida_name.get_name(ea)
    (prev_name_ea, prev_name), (next_name_ea, next_name) = get_nearest_symbols(ea)

    if name:
        print(f'Address {hex(ea)} has symbol {name}')
    else:
        print(f'Address {hex(ea)} has no symbol')
    print(f'Previous symbol is at {hex(prev_name_ea)}: {prev_name} (distance: {hex(ea-prev_name_ea)})')
    print(f'Next symbol is at {hex(next_name_ea)}: {next_name} (distance: {hex(next_name_ea-ea)})')

    ptr_size = 8 if ida_ida.inf_is_64bit() else 4

    # The heuristic for finding the end of the vtable is whenever we reach:
    # 1) A new symbol
    # 2) An xreffed address
    # 3) A non-code pointer

    endea = ea
    stop = False
    while True:

        print(f'Checking {hex(endea)}')

        # Reached next symbol?
        if endea == next_name_ea:
            print(f'reached symbol')
            stop = True

        # Reached xref (ignore the possible xref to the vtable itself)?
        if endea != ea:
            if has_xrefs_to(endea):
                print(f'reached xref')
                stop = True

        # Reached a non-code pointer?
        if not ptr_points_to_code(endea):
            print(f'reached non code pointer')
            stop = True

        if stop:
            break
        endea += ptr_size

    count = (endea-ea)//ptr_size
    print(f'vtable ends at {hex(endea)}')
    print(f'vtable contains {count} functions')

    return count


def create_vtable_entry(ea, offset, this_type='void', entries=None):

    print(f'Creating entry for offset {hex(offset)}')

    ptr_size = 8 if ida_ida.inf_is_64bit() else 4
    default = f'int (*func_{hex(offset)})({this_type});'

    # Check if we can heuristically name the entry instead of just returning the default
    if ptr_size == 8:
        func_ea = ida_bytes.get_qword(ea+offset)
    else:
        func_ea = ida_bytes.get_dword(ea+offset)

    if not func_ea:
        print(f'No function')
        return default

    func_name = idaapi.get_ea_name(func_ea, idaapi.GN_SHORT|idaapi.GN_DEMANGLED)
    if not func_name:
        print(f'No function name')
        return default

    delim = func_name.find("(")
    if delim != -1:
        func_name = func_name[:delim]
    else:
        print(f'No parentheses')
        return default

    if '::' in func_name:
        func_name =  func_name.split('::')[-1].strip()
    else:
        print(f'No scope delimiter')
        return default

    if '~' in func_name:
        return f'int (*destructor_{hex(offset)})({this_type});'

    if func_name:
        #print(entries)
        entries[func_name] = 1 if func_name not in entries else entries[func_name] + 1
        suffix = '' if entries[func_name] == 1 else f'_{hex(offset)}'
        return f'int (*{func_name}{suffix})({this_type});'

    print(f'No name')
    return default


def make_vtable_def(ea, name, count, this_type):

    ptr_size = 8 if ida_ida.inf_is_64bit() else 4
    entries = dict()
    funcs = '\n'.join([create_vtable_entry(ea, i*ptr_size, this_type, entries) for i in range(count)])
    struct_def = f'struct {name} {{ \n{funcs}\n}};'
    return struct_def


def apply_struct(ea, struct_name):


    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(struct_name):
        print(f'Unable to retrieve {struct_name} structure')
        return False

    # apply the type to EA
    ida_bytes.del_items(ea, 0, tif.get_size())
    ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE)

    return True

class AnalyzeVtable(actions.IdaViewPopupAction):

    description = 'Analyze vtable'
    
    def __init__(self):
        super(AnalyzeVtable, self).__init__()


    def activate(self, ctx):
        ea = ctx.cur_ea
        print(f'Analyzing vtable at {hex(ea)}')
        count = get_vtable_size(ea)
        if not count:
            ida_kernwin.warning(f'Could not analyze vtable at {hex(ea)}')
            return

        name = ida_kernwin.ask_str(f'vtable_{hex(ea)}', 0, f'vtable at {hex(ea)} has {count} entries. Create and assign a vtable struct? New vtable name:')
        
        if not name:
            return

        tid = ida_typeinf.get_named_type_tid(name)
        if tid != idaapi.BADADDR:
            ida_kernwin.warning(f'Type {name} already exists')
            return

        this_type = ida_kernwin.ask_str(f'void*', 0, f'Type of "this"?')

        struct_def = make_vtable_def(ea, name, count, this_type)
        
        if ida_typeinf.idc_parse_types(struct_def, 0):
            ida_kernwin.warning(f'Could not parse struct definition')
            print(struct_def)
            return

        print(f'Created new struct type {name}')

        if not apply_struct(ea, name):
            ida_kernwin.warning(f'Could not apply vtable struct {name} to address {ea}')
            return


def append_member_comment(struct_name, member_offset, text, ignore_duplicate=True):

    sid = idc.get_struc_id(struct_name)
    if sid == idaapi.BADADDR:
        print(f'Failed to get struct id for {struct_name}')
        return False

    old = idc.get_member_cmt(sid, member_offset)

    if ignore_duplicate:
        if text in old:
            return True

    if old:
        new = '\n'.join([old, text])
    else:
        new = text

    idc.set_member_cmt(sid, member_offset, new, 0)
    return True


class SetVtableComment(actions.HexRaysPopupAction):

    description = 'Set vtable comment'

    def __init__(self):
        super(SetVtableComment, self).__init__()

    def check(self, hx_view):
        # Only makes sense for expressions
        if hx_view.item.citype != idaapi.VDI_EXPR:
            return False

        return True

    def activate(self, ctx):

        hx_view = idaapi.get_widget_vdui(ctx.widget)

        # We need to propagate until we find the assignment op
        e = hx_view.item.e
        while e:
            print(expr_str(e.op))
            if e.op == idaapi.cot_asg:
                break
            if e.op == idaapi.cit_expr:
                e = None
                break
            e = hx_view.cfunc.body.find_parent_of(e).to_specific_type

        if not e:
            ida_kernwin.warning(f'Could not find assignment expression')
            return

        self.ptr_size = 8 if ida_ida.inf_is_64bit() else 4

        # Start with the rhs - should be pointer to global vtable
        try:
            ea = self.resolve_vtable_expression(e.y)
        except StructUtilsException as e:
            ida_kernwin.warning(f'Failed to resolve vtable expression')
            return

        print(f'Got vtable address: {hex(ea)}')

        try:
            struct_name, vtable_member_offset = self.resolve_assignment_expression(e.x)
        except StructUtilsException as e:
            ida_kernwin.warning(f'Failed to resolve assignment expression')
            return

        print(f'Got struct {struct_name}, offset {hex(vtable_member_offset)}')
        
        if not append_member_comment(struct_name, vtable_member_offset, f'VTABLE: {hex(ea)}'):
            ida_kernwin.warning(f'Failed to set comment')
            return

        # Jump to the vtable in IDA view, allowing quick access to AnalyzeVtable
        ida_kernwin.jumpto(ea)

        print(f'Done')


    def resolve_assignment_expression(self, e):

        print(f'Resolving assignment expression: {expr_str(e.op)}')

        # Handle x.m
        if e.op == idaapi.cot_memref:
            typeinfo = e.x.type
            typename = typeinfo.get_type_name()
            if not typename:
                print(f'Could not get type name')
                raise StructUtilsException()
            if not typeinfo.is_struct():
                print(f'Type {typename} is not a struct')
                raise StructUtilsException()
            return typename, e.m

        # Handle x->m
        if e.op == idaapi.cot_memptr:
            typeinfo = e.x.type.get_pointed_object()
            typename = typeinfo.get_type_name()
            if not typename:
                print(f'Could not get type name')
                raise StructUtilsException()
            if not typeinfo.is_struct():
                print(f'Type {typename} is not a struct')
                raise StructUtilsException()
            if e.ptrsize != self.ptr_size:
                print(f'Access size of {e.ptrsize} differs from sizeof(void*) which is {self.ptr_size}')
                raise StructUtilsException()
            return typename, e.m

        print(f'Error: unhandled op')
        raise StructUtilsException()


    def resolve_vtable_expression(self, e):

        print(f'Resolving vtable expression: {expr_str(e.op)}')

        # Handle cast
        if e.op == idaapi.cot_cast:
            # Validate cast to pointer size... should we really bother?
            if e.type.get_size() != self.ptr_size:
                print(f'Error: Cast size of {e.type.get_size()} differs from pointer size of {self.ptr_size}')
                raise StructUtilsException()
            return self.resolve_vtable_expression(e.x)

        # Handle addition
        if e.op == idaapi.cot_add:
            a = self.resolve_vtable_expression(e.x)
            b = self.resolve_vtable_expression(e.y)
            # Handle possilble pointer arithmetic
            if e.x.type.is_ptr():
                sz = e.x.type.get_pointed_object().get_size()
                return a + sz*b
            if e.y.type.is_ptr():
                sz = e.y.type.get_pointed_object().get_size()
                return b + sz*a

        # Handle number
        if e.op == idaapi.cot_num:
            return e.numval()

        # Handle reference
        if e.op == idaapi.cot_ref:
            if e.x.op != idaapi.cot_obj:
                print(f'Error: Reference to non-obj expression: {expr_str(e.x.op)}')
                raise StructUtilsException()
            return self.resolve_vtable_expression(e.x)

        # Handle object
        if e.op == idaapi.cot_obj:
            return e.obj_ea

        print(f'Error: unhandled op')
        raise StructUtilsException()
            

class HexRaysDebug(actions.HexRaysPopupAction):

    description = 'Print current op'

    def __init__(self):
        super(HexRaysDebug, self).__init__()

    def check(self, hx_view):
        #print(hx_view.item.citype)
        if hx_view.item.citype != idaapi.VDI_EXPR:
            return False
        return True

    def activate(self, ctx):

        hx_view = idaapi.get_widget_vdui(ctx.widget)
        print(expr_str(hx_view.item.e.op))


actions.action_manager.register(MakeMember())
actions.action_manager.register(MakeStruct())
actions.action_manager.register(CommitType())
actions.action_manager.register(AnalyzeVtable())
actions.action_manager.register(SetVtableComment())
actions.action_manager.register(HexRaysDebug())


