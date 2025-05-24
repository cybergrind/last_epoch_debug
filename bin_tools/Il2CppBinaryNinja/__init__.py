# ruff: noqa: F405, F403
from os.path import exists

from binaryninja import *


SKIP_TYPES = 'skip_all_types'
GLOBAL_SCRIPT_JSON = None


def get_addr(bv: BinaryView, addr: int):
    imageBase = bv.start
    return imageBase + addr


class Il2CppProcessTask(BackgroundTaskThread):
    def __init__(
        self, bv: BinaryView, script_path: str, header_path: str, filter_string: str = SKIP_TYPES
    ):
        BackgroundTaskThread.__init__(self, 'Il2Cpp start', True)
        self.bv = bv
        self.script_path = script_path
        self.header_path = header_path
        self.has_types = False
        self.filter_string = filter_string.lower()

        global GLOBAL_SCRIPT_JSON
        GLOBAL_SCRIPT_JSON = self.script_path

    def process_header(self):
        self.progress = 'Il2Cpp types (1/3)'
        log_info('Parsing header file')
        with open(self.header_path) as f:
            result = self.bv.parse_types_from_string(f.read())
        length = len(result.types)
        i = 0
        for name in result.types:
            i += 1
            if i % 100 == 0:
                percent = i / length * 100
                self.progress = f'Il2Cpp types: {percent:.2f}%'
            if self.bv.get_type_by_name(name):
                continue
            self.bv.define_user_type(name, result.types[name])

    def skip_processing(self, name: str):
        if self.filter_string == SKIP_TYPES:
            return False
        if self.filter_string not in name.lower():
            return True
        return False

    def shold_set_type(self, name: str):
        if self.filter_string == SKIP_TYPES:
            return False

        if not self.filter_string:
            return True

        if self.filter_string in name.lower():
            return True

        return False

    def process_methods(self, data: dict):
        self.progress = 'Il2Cpp methods (2/3)'
        log_info('Parsing script.json Methods')
        scriptMethods = data['ScriptMethod']
        length = len(scriptMethods)
        i = 0
        for scriptMethod in scriptMethods:
            if self.cancelled:
                self.progress = 'Il2Cpp cancelled, aborting'
                return
            i += 1
            if i % 1000 == 0:
                percent = i / length * 100
                self.progress = f'Il2Cpp methods: {percent:.2f}%'
                log_info(f'Parsing script.json Methods: {percent:.2f}%')
            addr = get_addr(self.bv, scriptMethod['Address'])
            name = scriptMethod['Name'].replace('$', '_').replace('.', '_')

            if self.skip_processing(name):
                continue

            signature = scriptMethod['Signature']
            func = self.bv.get_function_at(addr)
            if func is not None:
                # if func.name == name:
                #    continue
                func.name = scriptMethod['Name']
                if self.shold_set_type(name):
                    try:
                        func.type = signature
                    except Exception:
                        log_error(f'Failed to set function type: {signature}')
            if 'ItemFilter' in name:
                log_info(f'func is {func}: {addr} => {name} {signature} {scriptMethod["Address"]}')

    def process_strings(self, data: dict):
        self.progress = 'Il2Cpp strings (3/3)'
        log_info('Parsing script.json Strings')
        scriptStrings = data['ScriptString']
        i = 0
        for scriptString in scriptStrings:
            i += 1
            if self.cancelled:
                self.progress = 'Il2Cpp cancelled, aborting'
                return
            addr = get_addr(self.bv, scriptString['Address'])
            value = scriptString['Value']
            var = self.bv.get_data_var_at(addr)
            if var is not None:
                var.name = f'StringLiteral_{i}'
            self.bv.set_comment_at(addr, value)

    def run(self):
        if exists(self.header_path):
            self.process_header()
        else:
            log_warn('Header file not found')
        if self.bv.get_type_by_name('Il2CppClass'):
            log_warn('Il2CppClass type already exists, skipping')
            self.has_types = True
        data = json.loads(open(self.script_path, 'rb').read().decode('utf-8'))
        if 'ScriptMethod' in data:
            self.process_methods(data)
        if 'ScriptString' in data:
            self.process_strings(data)


def process(bv: BinaryView):
    global GLOBAL_SCRIPT_JSON
    fpath = GLOBAL_SCRIPT_JSON or 'script.json'
    scriptDialog = OpenFileNameField('Select script.json', 'script.json', fpath)
    headerDialog = OpenFileNameField('Select il2cpp_binja.h', 'il2cpp_binja.h', 'il2cpp_binja.h')
    filterString = TextLineField('Filter string', SKIP_TYPES)
    if not get_form_input(
        [scriptDialog, headerDialog, filterString], 'script.json from Il2CppDumper'
    ):
        return log_error('File not selected, try again!')
    if not exists(scriptDialog.result):
        return log_error('File not found, try again!')
    task = Il2CppProcessTask(bv, scriptDialog.result, headerDialog.result, filterString.result)
    task.start()


PluginCommand.register('Il2CppDumper', 'Process file', process)
