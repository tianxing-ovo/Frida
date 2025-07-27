/* global Java */

function hook() {
    Java.perform(function () {
        let MainActivity = Java.use("com.example.ndkdemo.MainActivity");
        MainActivity["stringFromJNI"].implementation = function (i) {
            console.log("\ni = " + i);
            let result = this["stringFromJNI"](i);
            console.log("result = " + result);
            return result;
        };
    })
}

setImmediate(hook)