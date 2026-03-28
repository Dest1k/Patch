package com.knox.spoof

import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam
import de.robv.android.xposed.XC_MethodHook

class SamsungSpoofer : IXposedHookLoadPackage {

    companion object {
        const val MODEL        = "SM-S928B"
        const val BRAND        = "samsung"
        const val MANUFACTURER = "Samsung"
        const val PRODUCT      = "e3qxbe"
        const val DEVICE       = "e3q"
        const val BOARD        = "e3q"

        val PROP_MAP = mapOf(
            "ro.product.model"        to MODEL,
            "ro.product.brand"        to BRAND,
            "ro.product.manufacturer" to MANUFACTURER,
            "ro.product.name"         to PRODUCT,
            "ro.product.device"       to DEVICE,
            "ro.product.board"        to BOARD,
            "ro.build.characteristics" to "phone",
            "ro.product.marketname"   to "Samsung Galaxy S24 Ultra"
        )
    }

    // Все пакеты Samsung Wearable / Galaxy Watch Manager
    private val TARGET_APPS = setOf(
        "com.samsung.android.app.watchmanager",
        "com.samsung.android.geargplugin",
        "com.samsung.android.gear2plugin",
        "com.samsung.android.modenplugin",
        "com.samsung.android.app.twatchmanager"
    )

    override fun handleLoadPackage(lpparam: LoadPackageParam) {
        if (lpparam.packageName !in TARGET_APPS) return

        spoofBuildFields()
        hookSystemProperties(lpparam)
    }

    // Патчим статические поля android.os.Build
    private fun spoofBuildFields() {
        XposedHelpers.setStaticObjectField(android.os.Build::class.java, "MANUFACTURER", MANUFACTURER)
        XposedHelpers.setStaticObjectField(android.os.Build::class.java, "BRAND",        BRAND)
        XposedHelpers.setStaticObjectField(android.os.Build::class.java, "MODEL",        MODEL)
        XposedHelpers.setStaticObjectField(android.os.Build::class.java, "PRODUCT",      PRODUCT)
        XposedHelpers.setStaticObjectField(android.os.Build::class.java, "DEVICE",       DEVICE)
        XposedHelpers.setStaticObjectField(android.os.Build::class.java, "BOARD",        BOARD)
    }

    // Хукаем SystemProperties.get() — обе перегрузки
    private fun hookSystemProperties(lpparam: LoadPackageParam) {
        val hook = object : XC_MethodHook() {
            override fun afterHookedMethod(param: MethodHookParam) {
                val key = param.args[0] as? String ?: return
                PROP_MAP[key]?.let { param.result = it }
            }
        }

        // get(String)
        try {
            XposedHelpers.findAndHookMethod(
                "android.os.SystemProperties",
                lpparam.classLoader,
                "get",
                String::class.java,
                hook
            )
        } catch (_: Exception) {}

        // get(String, String) — с дефолтным значением
        try {
            XposedHelpers.findAndHookMethod(
                "android.os.SystemProperties",
                lpparam.classLoader,
                "get",
                String::class.java,
                String::class.java,
                hook
            )
        } catch (_: Exception) {}
    }
}
