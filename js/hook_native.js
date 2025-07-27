/* global Java */

/**
 * 通过名称找到导出函数
 *
 * @param module 模块
 * @param name 函数名称
 * @return NativePointer
 */
function findExportByName(module, name) {
    return module.findExportByName(name)
}

/**
 * 通过模块基地址找到导出函数
 *
 * @param module 模块
 * @param offset 函数偏移量
 * @return NativePointer
 */
function findExportByBaseAddress(module, offset) {
    // 模块基地址
    let baseAddr = module.base
    return baseAddr.add(offset)
}

/**
 * hook native函数
 *
 * @param funcAddr 函数地址
 */
function attach(funcAddr) {
    Interceptor.attach(funcAddr, {
        onEnter: function (args) {
            console.log("\nargs[0]: " + parseInt(args[0].toString(), 16))
            console.log("args[1]: " + parseInt(args[1].toString(), 16))
            console.log("args[2]: " + parseInt(args[2].toString(), 16))
        }, onLeave: function (retval) {
            console.log("retval: " + parseInt(retval.toString(), 16))
        }
    })
}

function hook() {
    Java.perform(function () {
        let soName = "libndkdemo.so"
        let name = "Java_com_example_ndkdemo_MainActivity_stringFromJNI"
        let offset = 0x670
        let module = Process.getModuleByName(soName)
        let funcAddr = findExportByName(module, name)
        attach(funcAddr)
        funcAddr = findExportByBaseAddress(module, offset)
        attach(funcAddr)
    })
}

setImmediate(hook)