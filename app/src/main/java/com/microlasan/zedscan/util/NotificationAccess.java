package com.microlasan.zedscan.util;

import android.content.ComponentName;
import android.content.Context;
import android.provider.Settings;
import android.text.TextUtils;

public final class NotificationAccess {

    private NotificationAccess() {}

    public static boolean isNotificationListenerEnabled(Context context, Class<?> listenerServiceClass) {
        String pkgName = context.getPackageName();
        final String flat = Settings.Secure.getString(
                context.getContentResolver(),
                "enabled_notification_listeners"
        );

        if (TextUtils.isEmpty(flat)) return false;

        final String[] names = flat.split(":");
        for (String name : names) {
            ComponentName cn = ComponentName.unflattenFromString(name);
            if (cn != null) {
                if (TextUtils.equals(pkgName, cn.getPackageName())
                        && TextUtils.equals(listenerServiceClass.getName(), cn.getClassName())) {
                    return true;
                }
            }
        }
        return false;
    }
}
