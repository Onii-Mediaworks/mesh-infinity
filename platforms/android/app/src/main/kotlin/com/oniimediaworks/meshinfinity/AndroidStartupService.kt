package com.oniimediaworks.meshinfinity

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder

class AndroidStartupService : Service() {
    companion object {
        private const val CHANNEL_ID = "mesh_infinity_startup"
        private const val NOTIFICATION_ID = 4101

        fun start(context: Context) {
            val intent = Intent(context, AndroidStartupService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        ensureNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification())
        AndroidStartupStateStore.markStartupServiceStarted(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        AndroidStartupStateStore.markStartupServiceStarted(this)
        return START_STICKY
    }

    override fun onDestroy() {
        AndroidStartupStateStore.markStartupServiceStopped(this)
        super.onDestroy()
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        AndroidStartupStateStore.markStartupServiceStopped(this)
        super.onTaskRemoved(rootIntent)
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return
        }
        val manager = getSystemService(NotificationManager::class.java) ?: return
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Mesh Infinity startup",
            NotificationManager.IMPORTANCE_LOW,
        )
        channel.description = "Keeps the Layer 1 startup path alive across boot and unlock."
        channel.setShowBadge(false)
        manager.createNotificationChannel(channel)
    }

    private fun buildNotification(): Notification {
        val builder =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                Notification.Builder(this, CHANNEL_ID)
            } else {
                Notification.Builder(this)
            }
        return builder
            .setContentTitle("Mesh Infinity")
            .setContentText("Maintaining Layer 1 startup state")
            .setSmallIcon(android.R.drawable.stat_notify_sync_noanim)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .build()
    }
}
