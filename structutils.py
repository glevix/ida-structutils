import idaapi

from structutils_resources.actions import action_manager, hx_callback_manager

class MyPlugin(idaapi.plugin_t):
    
    flags = 0
    comment = "Plugin for struct utils"
    wanted_name = "StructUtils"
    wanted_hotkey = ""

    @staticmethod
    def init():
        if not idaapi.init_hexrays_plugin():
            logging.error("Failed to initialize Hex-Rays SDK")
            return idaapi.PLUGIN_SKIP

        action_manager.initialize()
        hx_callback_manager.initialize()
        return idaapi.PLUGIN_KEEP

    @staticmethod
    def run(*args):
        pass

    @staticmethod
    def term():
        action_manager.finalize()
        hx_callback_manager.finalize()
        idaapi.term_hexrays_plugin()


def PLUGIN_ENTRY():
    return MyPlugin()
