package com.oniimediaworks.meshinfinity

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

class AndroidStartupReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        AndroidStartupStateStore.recordEvent(context, intent.action)
        AndroidStartupService.start(context)
    }
}
