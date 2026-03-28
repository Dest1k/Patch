package com.knox.spoof

import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XC_MethodReplacement
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam

class SamsungSpoofer : IXposedHookLoadPackage {

    companion object {
        const val MODEL        = "SM-S928B"
        const val BRAND        = "samsung"
        const val MANUFACTURER = "Samsung"
        const val PRODUCT      = "e3qxbe"
        const val DEVICE       = "e3q"
        const val BOARD        = "e3q"

        val PROP_MAP = mapOf(
            // Идентификация устройства
            "ro.product.model"          to MODEL,
            "ro.product.brand"          to BRAND,
            "ro.product.manufacturer"   to MANUFACTURER,
            "ro.product.name"           to PRODUCT,
            "ro.product.device"         to DEVICE,
            "ro.product.board"          to BOARD,
            "ro.build.characteristics"  to "phone",
            "ro.product.marketname"     to "Samsung Galaxy S24 Ultra",
            // Knox / целостность системы
            "ro.boot.verifiedbootstate" to "green",
            "ro.boot.flash.locked"      to "1",
            "ro.debuggable"             to "0",
            "ro.secure"                 to "1",
            "ro.build.tags"             to "release-keys",
            "ro.build.type"             to "user",
            "ro.knox.bitmask"           to "0"
        )
    }

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
        hookKnox(lpparam)
    }

    private fun spoofBuildFields() {
        XposedHelpers.setStaticObjectField(android.os.Build::class.java, "MANUFACTURER", MANUFACTURER)
        XposedHelpers.setStaticObjectField(android.os.Build::class.java, "BRAND",        BRAND)
        XposedHelpers.setStaticObjectField(android.os.Build::class.java, "MODEL",        MODEL)
        XposedHelpers.setStaticObjectField(android.os.Build::class.java, "PRODUCT",      PRODUCT)
        XposedHelpers.setStaticObjectField(android.os.Build::class.java, "DEVICE",       DEVICE)
        XposedHelpers.setStaticObjectField(android.os.Build::class.java, "BOARD",        BOARD)
        // Признаки подписанной production-сборки
        XposedHelpers.setStaticObjectField(android.os.Build::class.java, "TAGS", "release-keys")
        XposedHelpers.setStaticObjectField(android.os.Build::class.java, "TYPE", "user")
    }

    private fun hookSystemProperties(lpparam: LoadPackageParam) {
        val hook = object : XC_MethodHook() {
            override fun afterHookedMethod(param: MethodHookParam) {
                val key = param.args[0] as? String ?: return
                PROP_MAP[key]?.let { param.result = it }
            }
        }

        // android.os.SystemProperties.get(String)
        try {
            XposedHelpers.findAndHookMethod(
                "android.os.SystemProperties", lpparam.classLoader,
                "get", String::class.java, hook)
        } catch (_: Exception) {}

        // android.os.SystemProperties.get(String, String)
        try {
            XposedHelpers.findAndHookMethod(
                "android.os.SystemProperties", lpparam.classLoader,
                "get", String::class.java, String::class.java, hook)
        } catch (_: Exception) {}

        // Samsung-specific: com.samsung.android.os.SemSystemProperties
        try {
            XposedHelpers.findAndHookMethod(
                "com.samsung.android.os.SemSystemProperties", lpparam.classLoader,
                "get", String::class.java, hook)
        } catch (_: Exception) {}

        try {
            XposedHelpers.findAndHookMethod(
                "com.samsung.android.os.SemSystemProperties", lpparam.classLoader,
                "get", String::class.java, String::class.java, hook)
        } catch (_: Exception) {}
    }

    private fun hookKnox(lpparam: LoadPackageParam) {
        // isDeviceRooted() → false
        try {
            XposedHelpers.findAndHookMethod(
                "com.samsung.android.knox.EnterpriseDeviceManager",
                lpparam.classLoader,
                "isDeviceRooted",
                XC_MethodReplacement.returnConstant(false)
            )
        } catch (_: Exception) {}

        // getKnoxVersion() → имитируем оригинальное устройство
        try {
            XposedHelpers.findAndHookMethod(
                "com.samsung.android.knox.EnterpriseDeviceManager",
                lpparam.classLoader,
                "getKnoxVersion",
                XC_MethodReplacement.returnConstant("Knox 3.10")
            )
        } catch (_: Exception) {}

        // getWarrantyBit() / checkWarrantyBit() → 0 (не изменено)
        try {
            XposedHelpers.findAndHookMethod(
                "com.samsung.android.knox.EnterpriseDeviceManager",
                lpparam.classLoader,
                "getWarrantyBit",
                XC_MethodReplacement.returnConstant(0)
            )
        } catch (_: Exception) {}

        // RKP / attestation state
        try {
            XposedHelpers.findAndHookMethod(
                "com.samsung.android.knox.integrity.PolicyEnforcer",
                lpparam.classLoader,
                "getRKPState",
                XC_MethodReplacement.returnConstant(0)
            )
        } catch (_: Exception) {}
    }
}
