import idaapi
#import ida_struct
import ida_funcs
import ida_kernwin
import ida_typeinf
import idc
import idautils
from . import actions

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


class AnalyzeVtable(actions.IdaViewPopupAction):

    description = 'Analyze vtable'
    
    def __init__(self):
        super(AnalyzeVtable, self).__init__()


    def activate(self, ctx):
        print(f'Activated!')


actions.action_manager.register(MakeMember())
actions.action_manager.register(MakeStruct())
actions.action_manager.register(CommitType())
actions.action_manager.register(AnalyzeVtable())