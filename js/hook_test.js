/* global Java */

function main() {
    Java.perform(function () {
        // Hook普通方法
        hookTest1()
        // Hook重载参数
        hookTest2()
        // Hook构造函数
        hookTest3()
        // Hook字段
        hookTest4()
        // Hook内部类
        hookTest5()
        // 枚举所有的类与类的所有方法
        hookTest6()
        // 枚举所有方法
        hookTest7()
        // 主动调用
        hookTest8()
    });
}

function hookTest1() {
    const Demo = Java.use("com.zj.wuaipojie.Demo");
    Demo['a'].implementation = function (str) {
        const retval = this['a'](str);
        console.log(str, retval);
        return retval;
    }
}

function hookTest2() {
    const Demo = Java.use("com.zj.wuaipojie.Demo");
    // overload: 重载函数
    Demo['Inner'].overload('com.zj.wuaipojie.Demo$Animal', 'java.lang.String').implementation = function (animal, str) {
        this['Inner'](animal, str);
        console.log(animal, str)
    }
}

function hookTest3() {
    const Demo = Java.use("com.zj.wuaipojie.Demo");
    // $init: 构造函数
    Demo.$init.overload('java.lang.String').implementation = function (str) {
        console.log(str);
        str = "52";
        this.$init(str);
    }
}

function hookTest4() {
    const Demo = Java.use("com.zj.wuaipojie.Demo");
    // 修改类的静态字段"staticField"的值
    Demo['staticField'].value = "我是被修改的静态变量";
    // Java.choose(): 枚举类的所有实例
    Java.choose("com.zj.wuaipojie.Demo", {
        onMatch: function (obj) {
            // 字段名和函数名相同: _privateInt
            obj['privateInt'].value = 9999
        }, onComplete: function () {

        }
    });
}

function hookTest5() {
    // 内部类
    const InnerClass = Java.use("com.zj.wuaipojie.Demo$InnerClass");
    InnerClass.$init.implementation = function () {
        console.log(InnerClass);
    }
}

function hookTest6() {
    Java.enumerateLoadedClasses({
        onMatch: function (name) {
            // 过滤类名
            if (name.indexOf("com.zj.wuaipojie.Demo") !== -1) {
                console.log(name);
                const clazz = Java.use(name);
                console.log(clazz);
                const methods = clazz.class.getDeclaredMethods();
                console.log(methods);
            }
        },
        onComplete: function () {
        }
    })
}

function hookTest7() {
    const Demo = Java.use("com.zj.wuaipojie.Demo");
    // getDeclaredMethods: 枚举所有方法
    const methods = Demo.class.getDeclaredMethods();
    for (const method of methods) {
        const methodName = method.getName();
        console.log(methodName);
        for (const overload of Demo[methodName].overloads) {
            overload.implementation = function () {
                for (const argument of arguments) {
                    console.log(argument);
                }
                return this[methodName].apply(this, arguments);
            }
        }
    }
}

function hookTest8() {
    const Demo = Java.use("com.zj.wuaipojie.Demo");
    // 调用静态方法
    Demo['staticPrivateFunc']('hello')
    // 调用无参构造
    const instance = Demo.$new()
    // 调用非静态方法
    instance['privateFunc']('world')
}

setImmediate(main);