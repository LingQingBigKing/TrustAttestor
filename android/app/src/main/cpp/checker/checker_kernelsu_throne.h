#pragma once

#include <jni.h>

#include <string>

// The watch is installed in the App Zygote before it forks an isolated service.
// The child only reads/drains the inherited non-blocking inotify descriptor.
std::string InstallThroneHuntWatch(JNIEnv* env, jstring source_dir);
std::string ThroneHuntWatchState();
std::string ThroneHuntWatchDrain();
std::string ThroneHuntWatchReset();

void ResetThroneHuntEvidence();
void FindThroneHuntDetection(JNIEnv* env, jobject context);

