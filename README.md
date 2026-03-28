# Samsung S24 Ultra Spoof — LSPatch модуль

Xposed-модуль для LSPatch, который заставляет Samsung Wearable (Galaxy Wearable) думать,
что ваш телефон — **Samsung Galaxy S24 Ultra (SM-S928B)**.

Патчит:
- `android.os.Build` поля: `MODEL`, `BRAND`, `MANUFACTURER`, `PRODUCT`, `DEVICE`, `BOARD`
- `SystemProperties.get()` — оба варианта (с дефолтом и без)
- Ключевые свойства: `ro.product.*`, `ro.build.characteristics`

---

## Что нужно

- Android-телефон (root **не нужен**)
- [LSPatch](https://github.com/LSPosed/LSPatch) — последняя версия (v0.6+)
- APK приложения Samsung Wearable / Galaxy Wearable
- APK этого модуля (собранный из исходников)

---

## Сборка модуля

1. Открой проект в Android Studio.
2. `Build → Generate Signed APK` или просто `Build → Build APK(s)`.
3. Готовый APK будет в `app/build/outputs/apk/debug/app-debug.apk`.

---

## Инструкция по применению

### Шаг 1 — Установить LSPatch

1. Скачай последний релиз LSPatch (`lspatch-v*.apk`) с GitHub.
2. Установи его на телефон.

### Шаг 2 — Установить модуль

1. Установи собранный `app-debug.apk` на телефон как обычное приложение.
   > Иконки и UI у него нет — это нормально.

### Шаг 3 — Пропатчить Samsung Wearable через LSPatch

1. Открой **LSPatch**.
2. Нажми **«+»** → выбери APK приложения Samsung Wearable
   (или укажи уже установленное приложение через "Installed apps").
3. В настройках патча выбери режим **«Embed»** (встроенный) — root не нужен.
4. Нажми **«Embed modules»** → добавь наш модуль (`com.knox.spoof`).
5. Нажми **«Start patch»** и дождись завершения.
6. Установи пропатченный APK вместо оригинального.

### Шаг 4 — Проверить

1. Запусти пропатченный Samsung Wearable.
2. Приложение должно видеть устройство как **Samsung Galaxy S24 Ultra**.

---

## Поддерживаемые пакеты Samsung Wearable

| Пакет | Описание |
|---|---|
| `com.samsung.android.app.watchmanager` | Galaxy Wearable (основной) |
| `com.samsung.android.geargplugin` | Gear плагин |
| `com.samsung.android.gear2plugin` | Gear 2 плагин |
| `com.samsung.android.modenplugin` | Moden плагин |
| `com.samsung.android.app.twatchmanager` | Watch Manager (альтернативный) |

---

## Параметры спуфинга

| Поле | Значение |
|---|---|
| MODEL | SM-S928B |
| BRAND | samsung |
| MANUFACTURER | Samsung |
| PRODUCT | e3qxbe |
| DEVICE | e3q |
| BOARD | e3q |
| ro.build.characteristics | phone |
| ro.product.marketname | Samsung Galaxy S24 Ultra |

---

## Частые вопросы

**Нужен root?**
Нет. LSPatch в режиме Embed работает без root.

**После обновления Samsung Wearable патч слетит?**
Да. После каждого обновления нужно повторно патчить APK через LSPatch.

**Модуль влияет на другие приложения?**
Нет. Хук активируется только внутри пакетов Samsung Wearable.
