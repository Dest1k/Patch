package com.knox.spoof

import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam
import de.robv.android.xposed.XC_MethodHook

class SamsungSpoofer : IXposedHookLoadPackage {
    override fun handleLoadPackage(lpparam: LoadPackageParam) {
        // Список всех пакетов, связанных с Samsung Wearable
        val targetApps = setOf(
            "com.samsung.android.app.watchmanager",
            "com.samsung.android.geargplugin",
            "com.samsung.android.gear2plugin",
            "com.samsung.android.modenplugin",
            "com.samsung.android.app.twatchmanager"
        )

        if (lpparam.packageName !in targetApps) return

        // Параметры S24 Ultra (SM-S928B)
        val model = "SM-S928B"
        val brand = "samsung"
        val manufacturer = "Samsung"

        // 1. Хукаем поля в android.os.Build
        XposedHelpers.setStaticObjectField(android.os.Build::class.java, "MANUFACTURER", manufacturer)
        XposedHelpers.setStaticObjectField(android.os.Build::class.java, "BRAND", brand)
        XposedHelpers.setStaticObjectField(android.os.Build::class.java, "MODEL", model)
        XposedHelpers.setStaticObjectField(android.os.Build::class.java, "PRODUCT", "e3qxbe")
        XposedHelpers.setStaticObjectField(android.os.Build::class.java, "DEVICE", "e3q")

        // 2. Хукаем SystemProperties.get()
        try {
            XposedHelpers.findAndHookMethod(
                "android.os.SystemProperties",
                lpparam.classLoader,
                "get",
                String::class.java,
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        when (param.args[0] as String) {
                            "ro.product.model" -> param.result = model
                            "ro.product.brand" -> param.result = brand
                            "ro.product.manufacturer" -> param.result = manufacturer
                        }
                    }
                }
            )
        } catch (e: Exception) {}
    }
}
