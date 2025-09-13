'''
I dont know where this boilerplate came from, it was opensource somewhere.
I found something very similar here: http://www.yxfzedu.com/article/380
If anyone knows the source, I'd be happy to add an acknowledgment
'''
from collections import defaultdict
import idaapi

class HexRaysCallbackManager(object):
    def __init__(self):
        self.__hexrays_event_handlers = defaultdict(list)

    def initialize(self):
        idaapi.install_hexrays_callback(self.__handle)

    def finalize(self):
        idaapi.remove_hexrays_callback(self.__handle)

    def register(self, event, handler):
        self.__hexrays_event_handlers[event].append(handler)

    def __handle(self, event, *args):
        for handler in self.__hexrays_event_handlers[event]:
            handler.handle(event, *args)
        # IDA expects zero
        return 0


hx_callback_manager = HexRaysCallbackManager()


class HexRaysEventHandler(object):
    def __init__(self):
        super(HexRaysEventHandler, self).__init__()

    def handle(self, event, *args):
        raise NotImplementedError("This is an abstract class")



class ActionManager(object):
    def __init__(self):
        self.__actions = []

    def register(self, action):
        self.__actions.append(action)
        idaapi.register_action(
                idaapi.action_desc_t(action.name, action.description, action, action.hotkey)
            )
        if isinstance(action, HexRaysPopupAction):
            hx_callback_manager.register(idaapi.hxe_populating_popup, HexRaysPopupRequestHandler(action))

    def initialize(self):
        pass

    def finalize(self):
        for action in self.__actions:
            idaapi.unregister_action(action.name)

action_manager = ActionManager()

class Action(idaapi.action_handler_t):
    """
    Convenience wrapper with name property allowing to be registered in IDA using ActionManager
    """
    description = None
    hotkey = None

    def __init__(self):
        super(Action, self).__init__()

    @property
    def name(self):
        return "HexRaysPyTools:" + type(self).__name__

    def activate(self, ctx):
        # type: (idaapi.action_activation_ctx_t) -> None
        raise NotImplementedError

    def update(self, ctx):
        # type: (idaapi.action_activation_ctx_t) -> None
        raise NotImplementedError


class HexRaysPopupAction(Action):
    """
    Wrapper around Action. Represents Action which can be added to menu after right-clicking in Decompile window.
    Has `check` method that should tell whether Action should be added to popup menu when different items
    are right-clicked.
    Children of this class can also be fired by hot-key without right-clicking if one provided in `hotkey`
    static member.
    """

    def __init__(self):
        super(HexRaysPopupAction, self).__init__()

    def activate(self, ctx):
        # type: (idaapi.action_activation_ctx_t) -> None
        raise NotImplementedError

    def check(self, hx_view):
        # type: (idaapi.vdui_t) -> bool
        raise NotImplementedError

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET


class HexRaysPopupRequestHandler(HexRaysEventHandler):
    """
    This is wrapper around HexRaysPopupAction which allows to dynamically decide whether to add Action to popup
    menu or not.
    Register this in CallbackManager.
    """
    def __init__(self, action):
        super(HexRaysPopupRequestHandler, self).__init__()
        self.__action = action

    def handle(self, event, *args):
        form, popup, hx_view = args
        if self.__action.check(hx_view):
            idaapi.attach_action_to_popup(form, popup, self.__action.name, None)
        return 0
