import idaapi
#import ida_struct
import ida_funcs
import ida_kernwin
import ida_name
import ida_nalt
import ida_ida
import ida_bytes
import ida_typeinf
import ida_xref
import idc
import idautils
from . import actions
import logging

logging.basicConfig(level=logging.INFO, format='%(name)s - %(levelname)s - %(message)s')
LOG = logging.getLogger('STRUCTUTILS')
LOG.setLevel(logging.DEBUG)

class StructUtilsException(Exception):
    pass

class ChooseOptionForm(ida_kernwin.Form):
    def __init__(self, header, message, items):
        self.items = items
        super().__init__(
            f"""STARTITEM 0
{header}
<{message}:{{cbCombo}}>""",
            {
                'cbCombo': ida_kernwin.Form.DropdownListControl(
                    items, readonly=True)
            }
        )

def ask_options(header, message, options):
    f = ChooseOptionForm(header, message, options)
    f.Compile()
    result = f.Execute()
    if result == 1:
        ret = f.cbCombo.value
    else:
        ret = None
    f.Free()
    return ret

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
        LOG.warning(f"No members found in structure with id '{struct_id}'")

'''
Helper function for introducing a new member into a struct, inside an array of bytes.
The new member will be created at the specified offset in the array, thereby splitting the array into 2 parts
'''
def make_member_from_array(struct_name, array_offset, offset_in_array, member_size, member_name=None):

    LOG.debug(f'make_member_from_array({struct_name}, {array_offset}, {offset_in_array}, {member_size}, {member_name})')

    if member_size not in TYPES:
        LOG.error(f'Illegal member size {member_size}')
        return False
    if offset_in_array < 0:
        LOG.error(f'Illegal offset {offset_in_array}')
        return False

    struct_id = idc.get_struc_id(struct_name)
    tid = ida_typeinf.get_named_type_tid(struct_name)

    if tid != struct_id:
        LOG.error('Struct id and tid dont match')
        return False
    
    if struct_id == idaapi.BADADDR:
        LOG.error(f'Could not get struct id for {struct_name}')
        return False

    struct = get_struc(struct_id)

    # TODO replace with tinfo_t.find_udb
    _, array_size = get_member_details(struct_id, array_offset)

    if array_size <= 0:
        LOG.error(f'Bad array size: {array_size}')
        return False

    top = array_size - (offset_in_array + member_size)
    if top < 0:
        LOG.error(f'Size would overrun array')
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
        LOG.error(f'Error {error} adding new member')
        return False

    if offset_in_array:
        # Add gap array below
        error = idc.add_struc_member(struct_id, f'field_{array_offset:02X}', array_offset, (TYPES[1]|idaapi.FF_DATA )&0xFFFFFFFF, -1, offset_in_array)
        if error:
            LOG.error(f'Error {error} adding gap array below new member')
            return False

    if top:
        # Add gap array above
        error = idc.add_struc_member(struct_id, f'field_{array_offset + offset_in_array + member_size:02X}', array_offset + offset_in_array + member_size, (TYPES[1]|idaapi.FF_DATA )&0xFFFFFFFF, -1, top)
        if error:
            LOG.error(f'Error {error} adding gap array above new member')
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

class MakeStructForm(ida_kernwin.Form):
    def __init__(self, default_size):
        super().__init__(
            """STARTITEM 0
New struct
<Struct name:{name}>
<Size (bytes):{size}>
""",
            {
                'name': ida_kernwin.Form.StringInput(),
                'size': ida_kernwin.Form.NumericInput(tp=ida_kernwin.Form.FT_DEC, value=default_size),
            }
        )

def ask_struct_info(default_size):
    f = MakeStructForm(default_size)
    f.Compile()
    result = f.Execute()
    if result == 1:
        ret = (f.name.value, f.size.value)
    else:
        ret = (None, None)
    f.Free()
    return ret

'''
Provides a 'Make struct' option in the dissasembly context right-click dropdown list,
whenever the cursor is on a number.
Once clicked, a popup will request the new struct name and size (defaulting to the size
of the clicked number, but editable), and a new struct will be created with that size.
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
        detected_size = hx_view.item.e.numval()
        name, size = ask_struct_info(detected_size)

        if not name:
            return False

        if not size or size <= 0:
            LOG.warning(f'Illegal size {size}')
            return False

        tid = ida_typeinf.get_named_type_tid(name)
        if tid != idaapi.BADADDR:
            tif = ida_typeinf.tinfo_t()
            if not tif.get_type_by_tid(tid):
                LOG.warning(f'"{name}" has a tid but no type - bug in IDA?')
                return False
            if tif.present():
                LOG.warning(f'"{name}" already exists')
                return False
            else:
                LOG.info(f'"{name}" already exists as a non-present type, populating')
                if ida_typeinf.idc_parse_types(f'struct {name}{{}};', 0):
                    LOG.warning(f'Failed')
                    return False
                LOG.debug(f'Populated struct type "{name}"')
        else:
            tid = idc.add_struc(idaapi.BADADDR, name, False)
            struct = get_struc(tid)
            if not struct:
                LOG.warning("Failed")
                return False
            LOG.debug(f'Created new struct type "{name}"')


        error = idc.add_struc_member(tid, "field_0", 0, (TYPES[1]|idaapi.FF_DATA )&0xFFFFFFFF, -1, size)
        if error:
            LOG.warning(f'Error {error} adding new member')
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
            result = self.from_array_index(hx_view, hx_view.item.e)
        else:
            # cot_memptr or cot_memref
            result = self.from_member(hx_view, hx_view.item.e)

        if not result:
            ida_kernwin.warning(f'Failed to make member')

    def from_member(self, hx_view, indexee_expression):

        # indexee_expression is the item representing the accessing of the array from the struct (x.m / x->m)
        # example (the 'field_2C8' is clicked): *(_QWORD *)&tcb->field_2C8[48] = 0i64
        # example (the 'field_3D' is clicked, and is an array of bytes): *(_QWORD *)tcb->field_3D0 = 0i64;

        next_expression = hx_view.cfunc.body.find_parent_of(indexee_expression).to_specific_type
        #LOG.debug(f'Parent: {next_expression.op}')
        if next_expression.op == idaapi.cot_idx:
            return self.from_array_index(hx_view, next_expression.y)
        elif next_expression.op != idaapi.cot_cast:
            LOG.warning(f'Aborting: parent of memref/memptr expression is not idx or cast')
            return False
        casting_expression = next_expression

        # This is the item representing the deref (*)
        ptr_expression = hx_view.cfunc.body.find_parent_of(casting_expression).to_specific_type
        if ptr_expression.op != idaapi.cot_ptr:
            LOG.warning(f'Aborting: casting expression is not inside a ptr expression ({ptr_expression.op})')
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
            LOG.warning(f'Failed')  
            return False

    def from_array_index(self, hx_view, array_offset_expression):

        # array_offset_expression is the item representing the number inside the square brackets
        # example (the '48' is clicked): *(_QWORD *)&tcb->field_2C8[48] = 0i64

        # This is the item representing the square brackets
        indexing_expression = hx_view.cfunc.body.find_parent_of(array_offset_expression).to_specific_type # ida_hexrays.cexpr_t
        if indexing_expression.op != idaapi.cot_idx:
            LOG.warning(f'Aborting: num expression is not inside an indexing expression ({indexing_expression.op})')
            return False

        # This is the object being indexed by the square brackets
        indexee_expression = indexing_expression.x
        if indexee_expression.op == idaapi.cot_memptr:
            typeinfo = indexee_expression.x.type.get_pointed_object()
        elif indexee_expression.op == idaapi.cot_memref:
            typeinfo = indexee_expression.x.type
        else:
            LOG.warning(f'Aborting: indexee expression is not a memref or memptr ({indexee_expression.op})')
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
                LOG.warning(f'Aborting: referencing expression is not inside a casting expression ({casting_expression.op})')
                return False

            next_expression = hx_view.cfunc.body.find_parent_of(casting_expression).to_specific_type
            if next_expression.op == idaapi.cot_ptr:
                member_size = next_expression.ptrsize
            elif next_expression.op == idaapi.cot_call:
                LOG.warning(f'Aborting: Memory reference passed to function, no way to guess size')
                return False
                # TODO: if the cast type is a pointer, we can infer the size, but this would still be risky
                # We could also just set the size to 1, so that the offset can be given a meaningful name
                # until the type can be inferred.
                #member_size = casting_expression.type.get_size()
            else:
                LOG.warning(f'Aborting: casting expression is not inside a ptr or call expression ({next_expression.op})')
                return False
        elif idaapi.is_assignment(next_expression.op) or next_expression.op in finals:
            # The array element is being accessed directly - get the size from the array type
            member_type = indexee_expression.type.get_array_element()
            member_size = member_type.get_size()
        else:
            LOG.warning(f'Aborting. Parent of indexing expression is not reference or assignment ({next_expression.op})')
            return False

        # We now have all the items we need. Start making the calculations

        #LOG.debug(f'Access size is {member_size}')

        # Get the offset within the array
        offset_in_array = array_offset_expression.numval()
        #LOG.debug(f'Offset in array is {offset_in_array}')

        # Get the offset of the array itself
        array_offset = indexee_expression.m
        #LOG.debug(f'Array offset is {hex(array_offset)}')

        struct_name = typeinfo.dstr()

        if make_member_from_array(struct_name, array_offset, offset_in_array, member_size, member_name=None):
            hx_view.refresh_view(True)
            return True
        else:
            LOG.warning(f'Failed')
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
                LOG.warning('Aborting: could not find call expression')
                return False

        if arg.op == idaapi.cot_cast:
            typeinfo = arg.x.type
        else:
            typeinfo = arg.type

        try:
            index = list(call.a).index(arg)
        except ValueError:
            LOG.warning('Could not find arg in arg list - make sure you are clicking on a call argument')
            return False
        #LOG.warning(f'Arg type is {typeinfo.dstr()}, index is {index}')

        function = call.x
        if function.op == idaapi.cot_helper:
            LOG.warning(f'Not a real function (cot_helper) - aborting')
            return False
        elif function.op == idaapi.cot_obj:
            self.apply_to_object(function.obj_ea, function.type, index, typeinfo)
            hx_view.refresh_view(True)
            return True
        else:
            LOG.warning(f'Unsupported function expression type {expr_str(function.op)} - aborting')
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
        LOG.debug(f'Address {hex(ea)} has symbol {name}')
    else:
        LOG.debug(f'Address {hex(ea)} has no symbol')
    LOG.debug(f'Previous symbol is at {hex(prev_name_ea)}: {prev_name} (distance: {hex(ea-prev_name_ea)})')
    LOG.debug(f'Next symbol is at {hex(next_name_ea)}: {next_name} (distance: {hex(next_name_ea-ea)})')

    ptr_size = 8 if ida_ida.inf_is_64bit() else 4

    # The heuristic for finding the end of the vtable is whenever we reach:
    # 1) A new symbol
    # 2) An xreffed address
    # 3) A non-code pointer

    endea = ea
    stop = False
    while True:

        LOG.debug(f'Checking {hex(endea)}')

        # Reached next symbol?
        if endea == next_name_ea:
            LOG.debug(f'reached symbol')
            stop = True

        # Reached xref (ignore the possible xref to the vtable itself)?
        if endea != ea:
            if has_xrefs_to(endea):
                LOG.debug(f'reached xref')
                stop = True

        # Reached a non-code pointer?
        if not ptr_points_to_code(endea):
            LOG.debug(f'reached non code pointer')
            stop = True

        if stop:
            break
        endea += ptr_size

        # Sanity check: a wrongly-chosen address could land in a long run of valid code
        # pointers (e.g. a jump table) and scan far past any real vtable. Let the user bail
        # out periodically instead of churning silently.
        entry_count = (endea-ea)//ptr_size
        if entry_count % 100 == 0:
            if ida_kernwin.ask_yn(ida_kernwin.ASKBTN_BTN1,
                    f'Still scanning for the end of the vtable at {hex(ea)} - {entry_count} '
                    f'entries found so far. Continue scanning?') != ida_kernwin.ASKBTN_BTN1:
                LOG.info(f'Vtable scan at {hex(ea)} stopped by user after {entry_count} entries')
                break

    count = (endea-ea)//ptr_size
    LOG.debug(f'vtable ends at {hex(endea)}')
    LOG.debug(f'vtable contains {count} functions')

    return count


def create_vtable_entry(ea, offset, this_type='void', entries=None):

    LOG.debug(f'Creating entry for offset {hex(offset)}')

    ptr_size = 8 if ida_ida.inf_is_64bit() else 4
    default = f'int (*func_{hex(offset)})({this_type});'

    # Check if we can heuristically name the entry instead of just returning the default
    if ptr_size == 8:
        func_ea = ida_bytes.get_qword(ea+offset)
    else:
        func_ea = ida_bytes.get_dword(ea+offset)

    if not func_ea:
        LOG.debug(f'No function')
        return default

    func_name = idaapi.get_ea_name(func_ea, idaapi.GN_SHORT|idaapi.GN_DEMANGLED)
    if not func_name:
        LOG.debug(f'No function name')
        return default

    delim = func_name.find("(")
    if delim != -1:
        func_name = func_name[:delim]
    else:
        LOG.debug(f'No parentheses')
        return default

    if '::' in func_name:
        func_name =  func_name.split('::')[-1].strip()
    else:
        LOG.debug(f'No scope delimiter')
        return default

    if '~' in func_name:
        return f'int (*destructor_{hex(offset)})({this_type});'

    if func_name:
        #print(entries)
        entries[func_name] = 1 if func_name not in entries else entries[func_name] + 1
        suffix = '' if entries[func_name] == 1 else f'_{hex(offset)}'
        return f'int (*{func_name}{suffix})({this_type});'

    LOG.debug(f'No name')
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
        LOG.warning(f'Unable to retrieve {struct_name} structure')
        return False

    # apply the type to EA
    ida_bytes.del_items(ea, 0, tif.get_size())
    ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE)

    # Expand the struct's display in the IDA View instead of leaving it collapsed to a single
    # "terse" summary line
    ida_nalt.clr_abits(ea, ida_nalt.AFL_TERSESTR)
    ida_kernwin.jumpto(ea)
    ida_kernwin.refresh_idaview_anyway()

    return True

class AnalyzeVtableForm(ida_kernwin.Form):
    def __init__(self, default_name, default_this_type, default_symbol):
        super().__init__(
            """STARTITEM 0
Analyze vtable
<Struct name:{name}>
<Type of 'this':{this_type}>
<Vtable symbol:{symbol}>
""",
            {
                'name': ida_kernwin.Form.StringInput(value=default_name),
                'this_type': ida_kernwin.Form.StringInput(value=default_this_type),
                'symbol': ida_kernwin.Form.StringInput(value=default_symbol),
            }
        )

def ask_analyze_vtable_info(default_name, default_this_type, default_symbol):
    f = AnalyzeVtableForm(default_name, default_this_type, default_symbol)
    f.Compile()
    result = f.Execute()
    if result == 1:
        ret = (f.name.value, f.this_type.value, f.symbol.value)
    else:
        ret = (None, None, None)
    f.Free()
    return ret

def analyze_vtable(ea):
    """
    Interactive flow shared by AnalyzeVtable and SetVtableComment: determine the vtable's size,
    ask for a (optional) class name, then ask for the vtable struct name, the type of 'this',
    and the vtable symbol name - defaulting respectively to 'vtable_<class>', '<class> *' and
    '<class>::__vtable' (with <class> defaulting to 'class_<ea>' if left blank). Creates the
    struct definition, applies it to 'ea', and renames the vtable symbol.
    Returns the new struct's name on success, or None if cancelled or failed.
    """
    LOG.debug(f'Analyzing vtable at {hex(ea)}')
    count = get_vtable_size(ea)
    if not count:
        ida_kernwin.warning(f'Could not analyze vtable at {hex(ea)}')
        return None

    class_name = ida_kernwin.ask_str("", 0, "Class name (optional):")
    if not class_name:
        class_name = f'class_{hex(ea)}'

    name, this_type, symbol = ask_analyze_vtable_info(
        f'vtable_{class_name}', f'{class_name} *', f'{class_name}::__vtable')

    if not name:
        return None

    tid = ida_typeinf.get_named_type_tid(name)
    if tid != idaapi.BADADDR:
        ida_kernwin.warning(f'Type {name} already exists')
        return None

    # Validate 'this_type' the same way it'll actually be used (as a function pointer argument),
    # so an unknown/misspelled class type fails here with a clear message instead of as an opaque
    # "Could not parse struct definition" once embedded in every entry of the vtable struct_def.
    if idc.parse_decl(f'int (*__validate_this_type__)({this_type});', ida_typeinf.PT_SIL) is None:
        ida_kernwin.warning(
            f'"{this_type}" is not a known type. Define the class struct first (e.g. with '
            f'"Make struct"), or use "void *" for the type of \'this\'.')
        return None

    struct_def = make_vtable_def(ea, name, count, this_type)

    if ida_typeinf.idc_parse_types(struct_def, 0):
        ida_kernwin.warning(f'Could not parse struct definition')
        LOG.debug(struct_def)
        return None

    LOG.info(f'Created new struct type {name}')

    if not apply_struct(ea, name):
        ida_kernwin.warning(f'Could not apply vtable struct {name} to address {ea}')
        return None

    if symbol and not ida_name.set_name(ea, symbol, ida_name.SN_NOCHECK):
        ida_kernwin.warning(f'Could not rename vtable at {hex(ea)} to {symbol}')

    return name


def set_member_type_to_pointer(struct_name, member_offset, pointee_type_name):
    """
    Set a struct member's type to a pointer to the named type. idc has no direct tinfo-based
    type setter for struct members (idc.set_member_type only takes classic FF_* flags), so this
    mirrors idc.py's own set_member_name/set_member_cmt implementation: tinfo_t + find_udm with
    STRMEM_AUTO (offset in bytes for structs) to get the member index, then the matching
    udm-level setter.
    """
    sid = idc.get_struc_id(struct_name)
    if sid == idaapi.BADADDR:
        LOG.error(f'Failed to get struct id for {struct_name}')
        return False

    pointee_tif = ida_typeinf.tinfo_t()
    if not pointee_tif.get_named_type(pointee_type_name):
        LOG.error(f'Could not retrieve type {pointee_type_name}')
        return False

    ptr_tif = ida_typeinf.tinfo_t()
    ptr_tif.create_ptr(pointee_tif)

    tif = ida_typeinf.tinfo_t()
    if not (tif.get_type_by_tid(sid) and tif.is_udt()):
        LOG.error(f'Failed to get udt type for {struct_name}')
        return False

    udm = ida_typeinf.udm_t()
    udm.offset = member_offset
    idx = tif.find_udm(udm, ida_typeinf.STRMEM_AUTO)
    if idx == -1:
        LOG.error(f'Could not find member at offset {hex(member_offset)} in {struct_name}')
        return False

    if tif.set_udm_type(idx, ptr_tif) != ida_typeinf.TERR_OK:
        LOG.error(f'Failed to set type of member at offset {hex(member_offset)} in {struct_name}')
        return False

    return True


class AnalyzeVtable(actions.IdaViewPopupAction):

    description = 'Analyze vtable'

    def __init__(self):
        super(AnalyzeVtable, self).__init__()

    def activate(self, ctx):
        analyze_vtable(ctx.cur_ea)


def append_member_comment(struct_name, member_offset, text, ignore_duplicate=True):

    sid = idc.get_struc_id(struct_name)
    if sid == idaapi.BADADDR:
        LOG.error(f'Failed to get struct id for {struct_name}')
        return False

    old = idc.get_member_cmt(sid, member_offset) or ""

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
            LOG.debug(expr_str(e.op))
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

        LOG.debug(f'Got vtable address: {hex(ea)}')

        try:
            struct_name, vtable_member_offset = self.resolve_assignment_expression(e.x)
        except StructUtilsException as e:
            ida_kernwin.warning(f'Failed to resolve assignment expression')
            return

        # resolve_assignment_expression may have carved a pointer-sized member out of a larger
        # byte array - refresh so that change is visible immediately, same as after MakeMember
        hx_view.refresh_view(True)

        LOG.debug(f'Got struct {struct_name}, offset {hex(vtable_member_offset)}')
        
        if not append_member_comment(struct_name, vtable_member_offset, f'VTABLE: {hex(ea)}'):
            ida_kernwin.warning(f'Failed to set comment')
            return

        # Jump to the vtable in IDA view, allowing quick access to AnalyzeVtable
        ida_kernwin.jumpto(ea)

        if ida_kernwin.ask_yn(ida_kernwin.ASKBTN_BTN1, 'Would you also like to analyze this vtable now?') != ida_kernwin.ASKBTN_BTN1:
            return

        vtable_struct_name = analyze_vtable(ea)
        if not vtable_struct_name:
            return

        if not set_member_type_to_pointer(struct_name, vtable_member_offset, vtable_struct_name):
            ida_kernwin.warning(f'Failed to set member type to {vtable_struct_name} *')
            return

        sid = idc.get_struc_id(struct_name)
        member_name = '__vtable' if vtable_member_offset == 0 else f'__vtable_{vtable_member_offset:02X}'
        if not idc.set_member_name(sid, vtable_member_offset, member_name):
            ida_kernwin.warning(f'Failed to rename member to {member_name}')
            return

        hx_view.refresh_view(True)

    def resolve_assignment_expression(self, e):

        LOG.debug(f'Resolving assignment expression: {expr_str(e.op)}')

        # Handle x.m / x->m - direct member access
        if e.op in (idaapi.cot_memref, idaapi.cot_memptr):
            return self.resolve_member_access(e, e.m)

        # Handle *(T *)[&]x->m[n] = ... - writing into a (possibly indexed) byte array member
        # that isn't pointer-sized on its own and needs to be carved, same as MakeMember would
        if e.op == idaapi.cot_ptr:
            return self.carve_member_access(e)

        LOG.error(f'unhandled op')
        raise StructUtilsException()

    def resolve_member_access(self, e, offset):

        if e.op == idaapi.cot_memref:
            typeinfo = e.x.type
        elif e.op == idaapi.cot_memptr:
            typeinfo = e.x.type.get_pointed_object()
        else:
            LOG.error(f'unhandled op')
            raise StructUtilsException()

        typename = typeinfo.get_type_name()
        if not typename:
            LOG.error(f'Could not get type name')
            raise StructUtilsException()
        if not typeinfo.is_struct():
            LOG.error(f'Type {typename} is not a struct')
            raise StructUtilsException()

        if e.op == idaapi.cot_memptr and e.ptrsize != self.ptr_size:
            LOG.error(f'Access size of {e.ptrsize} differs from sizeof(void*) which is {self.ptr_size}')
            raise StructUtilsException()

        sid = idc.get_struc_id(typename)
        _, member_size = get_member_details(sid, offset)
        if member_size == self.ptr_size:
            return typename, offset

        LOG.debug(f'Member at offset {hex(offset)} in {typename} is {member_size} bytes, not pointer '
                  f'sized - attempting to carve out a pointer-sized member')
        if make_member_from_array(typename, offset, 0, self.ptr_size, member_name=None):
            return typename, offset

        LOG.error(f'Member at offset {hex(offset)} in {typename} is {member_size} bytes (expected '
                  f'{self.ptr_size}), and could not be carved into a pointer-sized member')
        raise StructUtilsException()

    def carve_member_access(self, ptr_expression):

        if ptr_expression.ptrsize != self.ptr_size:
            LOG.error(f'Access size of {ptr_expression.ptrsize} differs from sizeof(void*) which is {self.ptr_size}')
            raise StructUtilsException()

        casting_expression = ptr_expression.x
        if casting_expression.op != idaapi.cot_cast:
            LOG.error(f'Aborting: ptr expression does not wrap a cast ({expr_str(casting_expression.op)})')
            raise StructUtilsException()

        inner_expression = casting_expression.x
        offset_in_array = 0
        if inner_expression.op == idaapi.cot_ref:
            idx_expression = inner_expression.x
            if idx_expression.op != idaapi.cot_idx:
                LOG.error(f'Aborting: ref expression does not wrap an idx ({expr_str(idx_expression.op)})')
                raise StructUtilsException()
            indexee_expression = idx_expression.x
            offset_in_array = idx_expression.y.numval()
        else:
            indexee_expression = inner_expression

        if indexee_expression.op == idaapi.cot_memptr:
            typeinfo = indexee_expression.x.type.get_pointed_object()
        elif indexee_expression.op == idaapi.cot_memref:
            typeinfo = indexee_expression.x.type
        else:
            LOG.error(f'Aborting: indexee expression is not a memref or memptr ({expr_str(indexee_expression.op)})')
            raise StructUtilsException()

        typename = typeinfo.get_type_name()
        if not typename:
            LOG.error(f'Could not get type name')
            raise StructUtilsException()
        if not typeinfo.is_struct():
            LOG.error(f'Type {typename} is not a struct')
            raise StructUtilsException()

        array_offset = indexee_expression.m
        member_offset = array_offset + offset_in_array

        if make_member_from_array(typename, array_offset, offset_in_array, self.ptr_size, member_name=None):
            return typename, member_offset

        LOG.error(f'Could not carve a pointer-sized member at offset {hex(member_offset)} in {typename}')
        raise StructUtilsException()


    def resolve_vtable_expression(self, e):

        LOG.debug(f'Resolving vtable expression: {expr_str(e.op)}')

        # Handle cast
        if e.op == idaapi.cot_cast:
            # Validate cast to pointer size... should we really bother?
            if e.type.get_size() != self.ptr_size:
                LOG.error(f'Cast size of {e.type.get_size()} differs from pointer size of {self.ptr_size}')
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

            LOG.error(f'Addition of two non-pointer expressions - cannot resolve an address')
            raise StructUtilsException()

        # Handle number
        if e.op == idaapi.cot_num:
            return e.numval()

        # Handle reference
        if e.op == idaapi.cot_ref:
            if e.x.op != idaapi.cot_obj:
                LOG.error(f'Reference to non-obj expression: {expr_str(e.x.op)}')
                raise StructUtilsException()
            return self.resolve_vtable_expression(e.x)

        # Handle object
        if e.op == idaapi.cot_obj:
            return e.obj_ea

        LOG.error(f'unhandled op')
        raise StructUtilsException()





def get_registered_vtables(struct_name, member_offset):
    """
    Return the list of vtable addresses registered on a struct member via SetVtableComment's
    "VTABLE: 0x..." comment lines, or an empty list if there are none / the struct doesn't exist.
    """
    sid = idc.get_struc_id(struct_name)
    if sid == idaapi.BADADDR:
        LOG.error(f'Failed to get struct id for {struct_name}')
        return []

    comment = idc.get_member_cmt(sid, member_offset) or ""
    vtables = []
    for c in comment.splitlines():
        if c.startswith("VTABLE: 0x"):
            _, _, addr_str = c.partition(':')
            vtables.append(int(addr_str, 16))
    return vtables


class VtableChooser(ida_kernwin.Choose):
    def __init__(self, items):
        # items should be a list of lists: [[col1, col2], [col1, col2], ...]
        super().__init__(
            "Select a vtable",
            [
                ["Address", 16],
                ["Type", 30],
                ["Name", 30],
            ],
            flags=ida_kernwin.Choose.CH_MODAL
        )
        self.items = items

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        # Return one entry per column
        return self.items[n]

class JumpToVtable(actions.HexRaysPopupAction):

    description = 'Jump to vtable'

    def __init__(self):
        super(JumpToVtable, self).__init__()

    def check(self, hx_view):
        
        #LOG.debug(expr_str(hx_view.item.e.op))

        # Only makes sense for expressions
        if hx_view.item.citype != idaapi.VDI_EXPR:
            return False

        # Only makes sense for accessing a member of a struct
        if hx_view.item.e.op not in [idaapi.cot_memptr, idaapi.cot_memref]:
            return False

        return True

    def activate(self, ctx):

        hx_view = idaapi.get_widget_vdui(ctx.widget)
        e = hx_view.item.e

        if e.op == idaapi.cot_memptr:
            typeinfo = e.x.type.get_pointed_object()
        elif e.op == idaapi.cot_memref:
            typeinfo = e.x.type
        else:
            LOG.error(f'e.op is not memptr or memref')
            return

        struct_typename = typeinfo.get_type_name()
        offset = e.m

        vtables = get_registered_vtables(struct_typename, offset)
        if not vtables:
            ida_kernwin.warning(f'No vtables registered for struct {struct_typename} offset {hex(offset)}')
            return

        options = []
        for addr in vtables:
            sym = ida_name.get_ea_name(addr) or ""
            typename = idc.get_type(addr) or ""
            LOG.debug(f'vtable: {hex(addr)}, symbol: {sym}, type: {typename}')
            options.append([f"{addr:0{16}x}", typename, sym])

        chooser = VtableChooser(options)
        idx = chooser.Show(True)

        if idx < 0:
            LOG.debug('Cancelled')
            return

        ida_kernwin.jumpto(vtables[idx])


class ImplementationChooser(ida_kernwin.Choose):
    def __init__(self, items):
        # items should be a list of lists: [[col1, col2, col3, col4, col5], ...]
        super().__init__(
            "Select an implementation",
            [
                ["Vtable type", 30],
                ["Vtable symbol", 30],
                ["Vtable address", 16],
                ["Function symbol", 30],
                ["Function address", 16],
            ],
            flags=ida_kernwin.Choose.CH_MODAL
        )
        self.items = items

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]


class JumpToImplementation(actions.HexRaysPopupAction):
    """
    Provides a 'Jump to implementation' option when right-clicking a vtable slot access
    (e.g. the 'Func_18' in 'tcb->field_vtable->Func_18(tcb)'), where 'field_vtable' is a
    member previously tagged by SetVtableComment. Instead of jumping to the vtable itself
    (JumpToVtable) and then manually locating the right function, this resolves the actual
    function address(es) directly: for each vtable address found in field_vtable's VTABLE:
    comment(s), it adds the clicked slot's offset and dereferences, then jumps straight to
    the implementation (or offers a choice if multiple vtables are registered).
    """

    description = 'Jump to implementation'
    hotkey = 'Ctrl-J'

    def __init__(self):
        super(JumpToImplementation, self).__init__()

    def check(self, hx_view):

        # Only makes sense for expressions
        if hx_view.item.citype != idaapi.VDI_EXPR:
            return False

        e = hx_view.item.e

        # Must be a member access (the vtable slot being called)...
        if e.op not in [idaapi.cot_memptr, idaapi.cot_memref]:
            return False

        # ...of another member access (the vtable pointer member, tagged by SetVtableComment)
        if e.x.op not in [idaapi.cot_memptr, idaapi.cot_memref]:
            return False

        return True

    def activate(self, ctx):

        hx_view = idaapi.get_widget_vdui(ctx.widget)
        e = hx_view.item.e

        # e is the vtable slot access, e.g. the 'Func_18' in 'tcb->field_vtable->Func_18'
        slot_offset = e.m
        member_expr = e.x

        # member_expr is the vtable pointer member access, e.g. 'tcb->field_vtable'
        if member_expr.op == idaapi.cot_memptr:
            typeinfo = member_expr.x.type.get_pointed_object()
        elif member_expr.op == idaapi.cot_memref:
            typeinfo = member_expr.x.type
        else:
            LOG.error(f'member_expr.op is not memptr or memref')
            return

        struct_typename = typeinfo.get_type_name()
        member_offset = member_expr.m

        vtables = get_registered_vtables(struct_typename, member_offset)
        if not vtables:
            ida_kernwin.warning(f'No vtables registered for struct {struct_typename} offset {hex(member_offset)}')
            return

        ptr_size = 8 if ida_ida.inf_is_64bit() else 4
        slot_index = slot_offset // ptr_size

        candidates = []
        for vtable_ea in vtables:

            # Prune vtables too small to actually have an entry at this slot - this happens
            # when an extending class calls a virtual function the base class doesn't declare,
            # and some of the registered vtables belong to base classes. Without this check we'd
            # read past the end of the vtable: possibly into unrelated data/another vtable, or a
            # stray qword that isn't a function pointer at all.
            vtable_size = get_vtable_size(vtable_ea)
            if slot_index >= vtable_size:
                LOG.debug(f'Pruning vtable {hex(vtable_ea)}: has {vtable_size} entries, slot index is {slot_index}')
                continue

            func_ea_ptr = vtable_ea + slot_offset
            if ptr_size == 8:
                func_ea = ida_bytes.get_qword(func_ea_ptr)
            else:
                func_ea = ida_bytes.get_dword(func_ea_ptr)

            if not func_ea:
                LOG.debug(f'No function pointer at {hex(func_ea_ptr)} (vtable {hex(vtable_ea)})')
                continue

            vtable_type = idc.get_type(vtable_ea)
            vtable_sym = ida_name.get_ea_name(vtable_ea)
            func_sym = idaapi.get_ea_name(func_ea, idaapi.GN_SHORT | idaapi.GN_DEMANGLED)
            candidates.append((func_ea, vtable_ea, vtable_type, vtable_sym, func_sym))

        if not candidates:
            ida_kernwin.warning(f'Could not resolve an implementation at offset {hex(slot_offset)} for any registered vtable (too small, or no function pointer present)')
            return

        options = []
        for func_ea, vtable_ea, vtable_type, vtable_sym, func_sym in candidates:
            options.append([
                vtable_type or "",
                vtable_sym or "",
                f"{vtable_ea:0{16}x}",
                func_sym or "",
                f"{func_ea:0{16}x}",
            ])

        chooser = ImplementationChooser(options)
        idx = chooser.Show(True)

        if idx < 0:
            LOG.debug('Cancelled')
            return

        ida_kernwin.jumpto(candidates[idx][0])





        

class HexRaysDebug(actions.HexRaysPopupAction):

    description = 'Print current op'

    def __init__(self):
        super(HexRaysDebug, self).__init__()

    def check(self, hx_view):
        return True

    def activate(self, ctx):

        hx_view = idaapi.get_widget_vdui(ctx.widget)
        citype = hx_view.item.citype
        if citype == idaapi.VDI_EXPR:
            LOG.info(f'VDI_EXPR: {expr_str(hx_view.item.e.op)}')
        elif citype == idaapi.VDI_FUNC:
            LOG.info(f'VDI_FUNC')
        elif citype == idaapi.VDI_LVAR:
            LOG.info(f'VDI_LVAR')
        elif citype == idaapi.VDI_NONE:
            LOG.info(f'VDI_NONE')
        elif citype == idaapi.VDI_TAIL:
            LOG.info(f'VDI_TAIL')
        else:
            LOG.info(f'Unknown citype: {citype}')


actions.action_manager.register(MakeMember())
actions.action_manager.register(MakeStruct())

actions.action_manager.register(CommitType())

actions.action_manager.register(AnalyzeVtable())
actions.action_manager.register(SetVtableComment())
actions.action_manager.register(JumpToVtable())
actions.action_manager.register(JumpToImplementation())

actions.action_manager.register(HexRaysDebug())


