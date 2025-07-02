# -*- coding:utf-8 -*-
import os
from idaapi import plugin_t
from idaapi import PLUGIN_PROC
from idaapi import PLUGIN_OK
from idaapi import get_imagebase
import idaapi
import ida_nalt
import idautils
import idc
import random
from functools import reduce
import json

template_js = '''
var func_addr_map = [func_addr_map];
var so_name = "[so_name]";

/*
    @param print_stack: Whether printing stack info, default is false.
*/
var print_stack = false;

/*
    @param print_stack_mode
    - FUZZY: print as much stack info as possible
    - ACCURATE: print stack info as accurately as possible
    - MANUAL: if printing the stack info in an error and causes exit, use this option to manually print the address
*/
var print_stack_mode = "FUZZY";

function addr_in_so(addr){
    var module = Process.getModuleByName(so_name);
    if (addr.compare(module.base) >= 0 && addr.compare(module.base.add(module.size)) < 0) {
        console.log(addr.toString(16), "is in", module.name, "offset: 0x" + addr.sub(module.base).toString(16));
    }
}

function hook_dlopen() {
    Interceptor.attach(Process.getModuleByName('libc.so').getExportByName('android_dlopen_ext'),
        {
            onEnter: function (args) {
                this.is_can_hook = false;
                var pathptr = args[0];
                if (pathptr !== undefined && pathptr != null) {
                    var path = pathptr.readCString();
                    if (path.includes(so_name)) {
                        this.is_can_hook = true;
                    }
                }
            },
            onLeave: function (retval) {
                if (this.is_can_hook) {
                    trace_so();
                }
            }
        }
    );
}

var globalCallCount = 0;

function trace_so(){
    var module = Process.getModuleByName(so_name);
    var pid = Process.getCurrentThreadId();
    var libc = Process.getModuleByName("libc.so");
    console.log("start Stalker!");
    Stalker.exclude({
        "base": libc.base,
        "size": libc.size
    })
    Stalker.follow(pid,{
        events:{
            call:false,
            ret:false,
            exec:false,
            block:false,
            compile:false
        },
        onReceive:function(events){},
        transform: function (iterator) {
            let instruction;
            while ((instruction = iterator.next()) !== null) {
                let offset = instruction.address.sub(module.base).toInt32();
                let name = func_addr_map[offset];
                if (name !== undefined) {
                    globalCallCount += 1;
                    console.log("call" + globalCallCount + ":" + name);
                    if (print_stack) {
                        iterator.putCallout((context) => {
                            console.log("backtrace:\\n");
                            if (print_stack_mode === "FUZZY") {
                                console.log(Thread.backtrace(context, Backtracer.FUZZY).map(DebugSymbol.fromAddress).join('\\n'));
                            } else if (print_stack_mode === "ACCURATE") {
                                console.log(Thread.backtrace(context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\\n'));
                            } else if (print_stack_mode === "MANUAL") {
                                Thread.backtrace(context, Backtracer.FUZZY).map(addr_in_so);
                            }
                            console.log('---------------------');
                        });
                    }
                }
                iterator.keep();
            }
        },
        onCallSummary:function(summary){}
    });
    console.log("Stalker end!");
}

setImmediate(hook_dlopen);
        '''


class UI_Hook(idaapi.UI_Hooks):
    def __init__(self):
        idaapi.UI_Hooks.__init__(self)

    def finish_populating_widget_popup(self, form, popup):
        form_type = idaapi.get_widget_type(form)
        if form_type == idaapi.BWN_FUNCS or form_type == idaapi.BWN_PSEUDOCODE or form_type == idaapi.BWN_DISASM:
            idaapi.attach_action_to_popup(form, popup, "stalkerTraceSo:genJsScript", "")


class GenerateFridaHookScript(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):

        if ctx.widget_type == idaapi.BWN_FUNCS:
            selected = [idaapi.getn_func(idx).start_ea for idx in ctx.chooser_selection]
        else:
            selected = idautils.Functions()

        generate_js_script(selected)

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


def generate_hook_code(template_js, func_addr_map, so_name):
    replacements = {
        "[func_addr_map]": func_addr_map,
        "[so_name]": "%s" % so_name
    }
    return reduce(lambda acc, item: acc.replace(item[0], item[1]), replacements.items(), template_js)


def generate_js_script(func_list):
    func_addr_map = {}
    base_addr = get_imagebase()
    for func_ea in func_list:
        if idc.get_sreg(func_ea, "T"):
            addr = func_ea + 1
        else:
            addr = func_ea
        name = '"{}"'.format(idc.get_func_name(func_ea))
        offset = addr - base_addr
        func_addr_map[str(offset)] = name
    import json
    func_addr_map_json = json.dumps(func_addr_map)
    so_path, so_name = os.path.split(ida_nalt.get_input_file_path())
    hook_code = generate_hook_code(template_js, func_addr_map_json, so_name)
    r = [random.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(5)]
    script_name = "trace_" + so_name.split(".")[0] + '_' + ''.join(r) + ".js"
    save_path = os.path.join(so_path, script_name)
    with open(save_path, "w", encoding="utf-8") as f:
        f.write(hook_code)
    print("usage:")
    print(f'frida -U -l "{save_path}" -f [package name]')


class stalker_trace_so(plugin_t):
    flags = PLUGIN_PROC
    comment = "stalker trace so"
    help = ""
    wanted_name = "stalker trace so"
    wanted_hotkey = ""

    def init(self):
        print("stalker_trace_so plugin has been loaded.")
        idaapi.register_action(
            idaapi.action_desc_t("stalkerTraceSo:genJsScript", "stalker trace so", GenerateFridaHookScript(), "",
                                 "", 201))
        # Add ui hook
        self.ui_hook = UI_Hook()
        self.ui_hook.hook()

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        generate_js_script(idautils.Functions())

    def term(self):
        pass


def PLUGIN_ENTRY():
    return stalker_trace_so()
