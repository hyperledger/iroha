// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0
// Test mailbox publication only; no wallet bridge, custody handle, or production ABI.
#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#ifndef ENROLLMENT_PROBE_HOST_TEST
#include <jni.h>
#endif

static int leaf(const char *value, size_t size) {
    if (size == 0 || size > 128 || (size == 1 && value[0] == '.') ||
        (size == 2 && value[0] == '.' && value[1] == '.')) return 0;
    for (size_t i = 0; i < size; ++i) {
        const unsigned char c = (unsigned char)value[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.')) return 0;
    }
    return 1;
}

static int parent_path(const char *value) {
    if (value[0] != '/' || strlen(value) > 4096) return 0;
    const char *part = value + 1;
    for (const char *end = part;; ++end) {
        if (*end == '/' || *end == '\0') {
            if (!leaf(part, (size_t)(end - part))) return 0;
            if (*end == '\0') return 1;
            part = end + 1;
        }
    }
}

static int private_regular(const struct stat *row) {
    return S_ISREG(row->st_mode) && row->st_uid == geteuid() && row->st_nlink == 1 &&
        (row->st_mode & 07777) == 0600;
}

static int same_original(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_size == b->st_size;
}

// Caller's same-UID ancestors are trusted immutable; retain the selected parent through every
// check and syscall. An uncertain return after naming is still a published attempt marker.
static int publish_in_directory(const char *parent, const char *stage, const char *target) {
    const char prefix[] = ".kagemusha-publication-";
    if (!parent_path(parent) || !leaf(stage, strlen(stage)) || !leaf(target, strlen(target)) ||
        strncmp(stage, prefix, sizeof(prefix) - 1) != 0 ||
        strncmp(target, prefix, sizeof(prefix) - 1) == 0 || !strcmp(stage, target)) return EINVAL;
    int result = 0;
    int staged = -1;
    int directory = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0) return errno;
    struct stat owner, selected, named, retained;
    if (fstat(directory, &owner) < 0) { result = errno; goto done; }
    if (!S_ISDIR(owner.st_mode) || owner.st_uid != geteuid() ||
        (owner.st_mode & 07777) != 0700) { result = EPERM; goto done; }
    staged = openat(directory, stage, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (staged < 0) { result = errno; goto done; }
    if (fstat(staged, &selected) < 0 || fstatat(directory, stage, &named, AT_SYMLINK_NOFOLLOW) < 0) {
        result = errno; goto done;
    }
    if (!private_regular(&selected) || !private_regular(&named) || !same_original(&selected, &named)) {
        result = EPERM; goto done;
    }
    // The Linux syscall is available independently of bionic's API-30 renameat2 wrapper.
    // ENOSYS/EINVAL/EOPNOTSUPP/EACCES fail closed; no link, copy, or replacing-rename fallback.
    if (syscall(SYS_renameat2, directory, stage, directory, target, RENAME_NOREPLACE) < 0) {
        result = errno; goto done;
    }
    if (fstat(staged, &retained) < 0 || fstatat(directory, target, &named, AT_SYMLINK_NOFOLLOW) < 0) {
        result = errno; goto done;
    }
    if (!private_regular(&retained) || !private_regular(&named) ||
        !same_original(&selected, &retained) || !same_original(&retained, &named)) result = EIO;
done:
    if (staged >= 0 && close(staged) < 0 && result == 0) result = errno;
    if (close(directory) < 0 && result == 0) result = errno;
    return result;
}

#ifndef ENROLLMENT_PROBE_HOST_TEST
JNIEXPORT jint JNICALL
Java_org_hyperledger_iroha_sdk_offline_wallet_EnrollmentProbeRename_publish(
    JNIEnv *env, jobject self, jstring parent_value, jstring stage_value, jstring target_value) {
    (void)self;
    if (!parent_value || !stage_value || !target_value) return EINVAL;
    const char *parent = (*env)->GetStringUTFChars(env, parent_value, NULL);
    if (!parent) return ENOMEM;
    const char *stage = (*env)->GetStringUTFChars(env, stage_value, NULL);
    if (!stage) { (*env)->ReleaseStringUTFChars(env, parent_value, parent); return ENOMEM; }
    const char *target = (*env)->GetStringUTFChars(env, target_value, NULL);
    int result = target ? publish_in_directory(parent, stage, target) : ENOMEM;
    if (target) (*env)->ReleaseStringUTFChars(env, target_value, target);
    (*env)->ReleaseStringUTFChars(env, stage_value, stage);
    (*env)->ReleaseStringUTFChars(env, parent_value, parent);
    return result;
}
#endif
