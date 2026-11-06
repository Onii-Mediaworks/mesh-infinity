/*
 * Phase 0 spike S1: the native half of the UI sandbox.
 *
 * Two sides, one library:
 * - the broker side runs in the main process (the stand-in core) and serves
 *   the confined UI process's file requests from a path policy;
 * - the confined side runs in the `:ui` process and locks it down with
 *   Fibrewall before any UI code draws.
 *
 * It also holds the escape probes: system calls the confined UI must NOT be
 * able to make. Each probe returns 0 when the call succeeded (an escape) or a
 * negative errno when it was refused, so the test can tell the two apart.
 *
 * This file follows Enginehost's runtime_sandbox.c, which runs the same
 * pattern (a GPU-using ART process locked down, broker in the main process)
 * in production.
 */

#include <android/log.h>
#include <errno.h>
#include <fcntl.h>
#include <jni.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "sbx.h"

/* Logcat tag the CI job filters on for broker records. */
#define TAG "MeshUiBroker"

/* At most this many own-opened device paths, each at most PATH_LEN bytes. */
#define OWN_MAX 8
#define PATH_LEN 128

/*
 * Logs what the broker refused, or in a learning run what it would have
 * refused. "syscall" records come from the filter (a call no rule covers),
 * and name the lockdown flag that would allow it (allowed_by).
 */
static void audit(void *context, const struct sbx_access *access, int result) {
    /* The context is non-NULL only in a learning run. */
    int learning = context != NULL;
    if (strcmp(access->op, "syscall") == 0) {
        /* A call the filter traps: asked holds the system call's name. */
        __android_log_print(ANDROID_LOG_WARN, TAG, "%s syscall %s (allowed_by %s)",
                            learning ? "LEARNED" : "REFUSED", access->asked,
                            access->allowed_by ? access->allowed_by : "none");
        return;
    }
    /* Only refusals are interesting; a call that fails on its own is not one. */
    int refused = learning ? access->rule_verdict < 0 : (result == -EACCES || result == -EPERM);
    if (!refused) return;
    __android_log_print(ANDROID_LOG_WARN, TAG, "%s %s %s (%s) need=%u", learning ? "LEARNED" : "REFUSED",
                        access->op, access->asked, access->resolved[0] ? access->resolved : "unresolved",
                        access->need);
}

/* A learning run's decider: allow everything, the audit records it. */
static int learn_decide(void *context, const struct sbx_access *access) {
    (void) context;
    (void) access;
    return 0;
}

/*
 * Broker side, main process. Serves fd on a thread of its own under the
 * rules paths[i] -> modes[i] (SBX_READ, SBX_WRITE). Takes ownership of fd.
 * With learn, nothing is refused and every would-be refusal is logged.
 */
JNIEXPORT jint JNICALL
Java_com_oniimediaworks_meshinfinity_uispike_NativeSandbox_serve0(JNIEnv *env, jclass clazz, jint fd,
                                                                  jobjectArray paths, jintArray modes,
                                                                  jboolean learn) {
    (void) clazz;
    struct sbx_policy *policy = sbx_policy_new();
    if (!policy) {
        close(fd);
        return -ENOMEM;
    }
    /* Any non-NULL context marks the audit as learning. */
    static int learning_marker;
    if (learn) sbx_policy_set_decider(policy, learn_decide, NULL);
    sbx_policy_set_audit(policy, audit, learn ? &learning_marker : NULL);

    /* Copy each Java rule into the policy. */
    jsize count = (*env)->GetArrayLength(env, paths);
    jint *mode = (*env)->GetIntArrayElements(env, modes, NULL);
    if (!mode) {
        sbx_policy_free(policy);
        close(fd);
        return -ENOMEM;
    }
    int result = 0;
    for (jsize i = 0; i < count && result == 0; i++) {
        jstring path = (jstring) (*env)->GetObjectArrayElement(env, paths, i);
        const char *chars = (*env)->GetStringUTFChars(env, path, NULL);
        if (chars) {
            result = sbx_policy_add(policy, chars, (unsigned) mode[i]);
            if (result != 0) __android_log_print(ANDROID_LOG_ERROR, TAG, "rule %s refused: %d", chars, result);
            (*env)->ReleaseStringUTFChars(env, path, chars);
        }
        (*env)->DeleteLocalRef(env, path);
    }
    (*env)->ReleaseIntArrayElements(env, modes, mode, JNI_ABORT);

    /* The broker owns the policy once it starts; on failure it is ours to free. */
    if (result == 0) result = sbx_broker_start(policy, fd);
    if (result != 0) {
        sbx_policy_free(policy);
        close(fd);
    }
    return result;
}

/*
 * Confined side, `:ui` process. Locks the whole process down on fd, after
 * opening the own_opens devices itself (binder, GPU). Returns 0 when every
 * thread is confined, else a negative errno and nothing is installed.
 */
JNIEXPORT jint JNICALL
Java_com_oniimediaworks_meshinfinity_uispike_NativeSandbox_lockdown0(JNIEnv *env, jclass clazz, jint fd,
                                                                     jobjectArray own_opens, jboolean learn) {
    (void) clazz;
    /* Copy the device paths into fixed storage the options can point at. */
    char paths[OWN_MAX][PATH_LEN];
    const char *list[OWN_MAX];
    unsigned used = 0;
    jsize count = (*env)->GetArrayLength(env, own_opens);
    for (jsize i = 0; i < count && used < OWN_MAX; i++) {
        jstring path = (jstring) (*env)->GetObjectArrayElement(env, own_opens, i);
        const char *chars = (*env)->GetStringUTFChars(env, path, NULL);
        if (chars && strlen(chars) < PATH_LEN) {
            strcpy(paths[used], chars);
            list[used] = paths[used];
            used++;
        }
        if (chars) (*env)->ReleaseStringUTFChars(env, path, chars);
        (*env)->DeleteLocalRef(env, path);
    }

    /*
     * Logging stays possible (liblog's datagram socket), everything else
     * about sockets is refused: the UI process holds the protocol socket it
     * was given and needs no other.
     */
    struct sbx_lockdown_options options = {
        .flags = SBX_LOCK_LOG_SOCKET,
        .own_opens = list,
        .own_open_count = used,
    };
    if (learn) options.flags |= SBX_LOCK_LEARN;
    int result = sbx_lockdown(fd, &options);
    if (result != 0) close(fd);
    __android_log_print(result == 0 ? ANDROID_LOG_INFO : ANDROID_LOG_ERROR, TAG, "lockdown %s: %d",
                        learn ? "(learning)" : "(enforcing)", result);
    return result;
}

/* Probe: open path read-only. 0 = opened (escape), else -errno. */
JNIEXPORT jint JNICALL
Java_com_oniimediaworks_meshinfinity_uispike_NativeSandbox_probeOpen(JNIEnv *env, jclass clazz, jstring path) {
    (void) clazz;
    const char *chars = (*env)->GetStringUTFChars(env, path, NULL);
    if (!chars) return -ENOMEM;
    int opened = open(chars, O_RDONLY | O_CLOEXEC);
    int result = opened >= 0 ? 0 : -errno;
    if (opened >= 0) close(opened);
    (*env)->ReleaseStringUTFChars(env, path, chars);
    return result;
}

/* Probe: create an internet socket. 0 = created (escape), else -errno. */
JNIEXPORT jint JNICALL
Java_com_oniimediaworks_meshinfinity_uispike_NativeSandbox_probeInetSocket(JNIEnv *env, jclass clazz) {
    (void) env;
    (void) clazz;
    int made = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (made < 0) return -errno;
    close(made);
    return 0;
}

/* Probe: attach to another process with ptrace. 0 = attached (escape), else -errno. */
JNIEXPORT jint JNICALL
Java_com_oniimediaworks_meshinfinity_uispike_NativeSandbox_probePtrace(JNIEnv *env, jclass clazz, jint pid) {
    (void) env;
    (void) clazz;
    if (ptrace(PTRACE_ATTACH, (pid_t) pid, NULL, NULL) == 0) {
        /* Never leave the core stopped, even in a failing run. */
        ptrace(PTRACE_DETACH, (pid_t) pid, NULL, NULL);
        return 0;
    }
    return -errno;
}

/* Probe: send signal 0 to another process. 0 = allowed (escape), else -errno. */
JNIEXPORT jint JNICALL
Java_com_oniimediaworks_meshinfinity_uispike_NativeSandbox_probeSignal(JNIEnv *env, jclass clazz, jint pid) {
    (void) env;
    (void) clazz;
    return kill((pid_t) pid, 0) == 0 ? 0 : -errno;
}

/*
 * Probe: run a program. A child is forked and tries execve; its exit code
 * carries the errno back. 0 = the program ran (escape), else -errno.
 * The child only calls execve and _exit, which is safe after fork in a
 * multi-threaded process.
 */
JNIEXPORT jint JNICALL
Java_com_oniimediaworks_meshinfinity_uispike_NativeSandbox_probeExec(JNIEnv *env, jclass clazz) {
    (void) env;
    (void) clazz;
    pid_t child = fork();
    if (child < 0) return -errno;
    if (child == 0) {
        char *const argv[] = {"/system/bin/true", NULL};
        char *const envp[] = {NULL};
        execve(argv[0], argv, envp);
        /* Only reached when execve failed: report its errno as the exit code. */
        _exit(errno & 0x7f);
    }
    int status = 0;
    if (waitpid(child, &status, 0) < 0) return -errno;
    if (WIFEXITED(status)) return WEXITSTATUS(status) == 0 ? 0 : -WEXITSTATUS(status);
    /* Killed by a signal (the filter's trap): refused. */
    return -EPERM;
}
