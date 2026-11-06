package com.oniimediaworks.meshinfinity.uispike

import android.os.Bundle
import android.os.Process
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.unit.dp

/**
 * The confined UI: shows the run's mode, the lockdown result and the
 * probes, and exercises what a real chat UI needs: a text field with the
 * soft keyboard, a send round trip to the core, and a long scrolling list.
 * Test tags are exposed as resource ids so UiAutomator (which reads the
 * accessibility tree) can find each element.
 */
class UiActivity : ComponentActivity() {
    @OptIn(ExperimentalComposeUiApi::class)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Column(
                    Modifier
                        .fillMaxSize()
                        .padding(12.dp)
                        .semantics { testTagsAsResourceId = true },
                ) {
                    Text("mode ${UiSession.mode}, confined ${UiSession.confined}, pid ${Process.myPid()}",
                        Modifier.testTag("status"))
                    UiSession.probes.forEach { (name, result) ->
                        Text("$name: ${if (result == 0) "ALLOWED" else "refused ($result)"}")
                    }
                    Composer()
                    Rows()
                }
            }
        }
    }
}

/** A text field and a send button; the core's reply appears below. */
@androidx.compose.runtime.Composable
private fun Composer() {
    var text by rememberSaveable { mutableStateOf("") }
    var reply by rememberSaveable { mutableStateOf("") }
    Row(Modifier.fillMaxWidth()) {
        OutlinedTextField(
            value = text,
            onValueChange = { text = it },
            modifier = Modifier
                .weight(1f)
                .testTag("input"),
            label = { Text("message") },
        )
        Button(
            onClick = { reply = UiSession.request("echo $text") ?: "no reply" },
            modifier = Modifier.testTag("send"),
        ) { Text("send") }
    }
    Text(reply, Modifier.testTag("reply"))
}

/** A long list, for scrolling and frame timing. */
@androidx.compose.runtime.Composable
private fun Rows() {
    LazyColumn(Modifier.fillMaxSize().testTag("list")) {
        items(3000) { index ->
            Text("row $index: a message preview long enough to wrap onto a second line on a phone screen",
                Modifier.padding(vertical = 6.dp))
        }
    }
}
