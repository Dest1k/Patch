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
        const val FINGERPRINT  = "samsung/e3qxbe/e3q:14/UP1A.231005.007/S928BXXU2AXK2:user/release-keys"

        val PROP_MAP = mapOf(
            "ro.product.model"          to MODEL,
            "ro.product.brand"          to BRAND,
            "ro.product.manufacturer"   to MANUFACTURER,
            "ro.product.name"           to PRODUCT,
            "ro.product.device"         to DEVICE,
            "ro.product.board"          to BOARD,
            "ro.build.characteristics"  to "phone",
            "ro.product.marketname"     to "Samsung Galaxy S24 Ultra",
            "ro.build.fingerprint"      to FINGERPRINT,
            "ro.build.tags"             to "release-keys",
            "ro.build.type"             to "user",
            "ro.boot.verifiedbootstate" to "green",
            "ro.boot.flash.locked"      to "1",
            "ro.debuggable"             to "0",
            "ro.secure"                 to "1",
            "ro.knox.bitmask"           to "0"
        )

        val SAMSUNG_FEATURES = setOf(
            "com.samsung.feature.samsung_experience_mobile",
            "com.samsung.feature.samsung_experience_mobile_lite",
            "com.sec.feature.multi_window_controller",
            "com.sec.feature.cocktailpanel",
            "com.samsung.feature.aremoji"
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
        hookPackageManager(lpparam)
        hookTelephony(lpparam)
    }

    private fun spoofBuildFields() {
        mapOf(
            "MANUFACTURER" to MANUFACTURER,
            "BRAND"        to BRAND,
            "MODEL"        to MODEL,
            "PRODUCT"      to PRODUCT,
            "DEVICE"       to DEVICE,
            "BOARD"        to BOARD,
            "TAGS"         to "release-keys",
            "TYPE"         to "user",
            "FINGERPRINT"  to FINGERPRINT
        ).forEach { (field, value) ->
            try { XposedHelpers.setStaticObjectField(android.os.Build::class.java, field, value) }
            catch (_: Exception) {}
        }
    }

    private fun hookSystemProperties(lpparam: LoadPackageParam) {
        val hook = object : XC_MethodHook() {
            override fun afterHookedMethod(param: MethodHookParam) {
                val key = param.args[0] as? String ?: return
                PROP_MAP[key]?.let { param.result = it }
            }
        }
        for (cls in listOf(
            "android.os.SystemProperties",
            "com.samsung.android.os.SemSystemProperties"
        )) {
            for (args in listOf(
                arrayOf<Class<*>>(String::class.java),
                arrayOf<Class<*>>(String::class.java, String::class.java)
            )) {
                try { XposedHelpers.findAndHookMethod(cls, lpparam.classLoader, "get", *args, hook) }
                catch (_: Exception) {}
            }
        }
    }

    private fun hookKnox(lpparam: LoadPackageParam) {
        val EDM = "com.samsung.android.knox.EnterpriseDeviceManager"

        // На не-Samsung устройствах getInstance() возвращает null,
        // поэтому хуки на instance-методы никогда не срабатывают.
        // Создаём объект через Unsafe без вызова конструктора.
        try {
            val edmClass = XposedHelpers.findClass(EDM, lpparam.classLoader)
            XposedHelpers.findAndHookMethod(
                edmClass,
                "getInstance",
                android.content.Context::class.java,
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        if (param.result != null) return
                        try {
                            val unsafeCls = Class.forName("sun.misc.Unsafe")
                            val theUnsafe = unsafeCls.getDeclaredField("theUnsafe")
                                .also { it.isAccessible = true }.get(null)
                            param.result = unsafeCls
                                .getMethod("allocateInstance", Class::class.java)
                                .invoke(theUnsafe, edmClass)
                        } catch (_: Exception) {}
                    }
                }
            )
        } catch (_: Exception) {}

        data class Stub(val cls: String, val method: String, val ret: Any)
        listOf(
            Stub(EDM, "isDeviceRooted", false),
            Stub(EDM, "getWarrantyBit", 0),
            Stub(EDM, "getKnoxVersion", "Knox 3.10"),
            Stub("com.samsung.android.knox.integrity.PolicyEnforcer", "getRKPState", 0),
            Stub("com.samsung.android.knox.integrity.PolicyEnforcer", "isDeviceRKP",  false)
        ).forEach { (cls, method, ret) ->
            try {
                XposedHelpers.findAndHookMethod(cls, lpparam.classLoader, method,
                    XC_MethodReplacement.returnConstant(ret))
            } catch (_: Exception) {}
        }
    }

    private fun hookPackageManager(lpparam: LoadPackageParam) {
        try {
            XposedHelpers.findAndHookMethod(
                "android.app.ApplicationPackageManager", lpparam.classLoader,
                "hasSystemFeature", String::class.java,
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val feature = param.args[0] as? String ?: return
                        if (feature in SAMSUNG_FEATURES) param.result = true
                    }
                }
            )
        } catch (_: Exception) {}

        val signHook = object : XC_MethodHook() {
            override fun afterHookedMethod(param: MethodHookParam) {
                val pkgName = param.args[0] as? String ?: return
                if (pkgName !in TARGET_APPS) return
                val info = param.result as? android.content.pm.PackageInfo ?: return
                @Suppress("DEPRECATION")
                info.signatures = arrayOf()
                try { XposedHelpers.setObjectField(info, "signingInfo", null) } catch (_: Exception) {}
            }
        }
        try {
            XposedHelpers.findAndHookMethod(
                "android.app.ApplicationPackageManager", lpparam.classLoader,
                "getPackageInfo", String::class.java, Int::class.java, signHook)
        } catch (_: Exception) {}
        try {
            XposedHelpers.findAndHookMethod(
                "android.app.ApplicationPackageManager", lpparam.classLoader,
                "getPackageInfo", String::class.java,
                XposedHelpers.findClass(
                    "android.content.pm.PackageManager\$PackageInfoFlags",
                    lpparam.classLoader),
                signHook)
        } catch (_: Exception) {}
    }

    private fun hookTelephony(lpparam: LoadPackageParam) {
        try {
            XposedHelpers.findAndHookMethod(
                "android.telephony.TelephonyManager", lpparam.classLoader,
                "getPhoneType",
                XC_MethodReplacement.returnConstant(1))
        } catch (_: Exception) {}
    }
}
