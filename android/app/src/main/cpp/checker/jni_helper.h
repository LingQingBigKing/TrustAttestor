#pragma once

#include <jni.h>

inline jclass cl_service_manager = nullptr;
inline jclass cl_parcel = nullptr;
inline jclass cl_binder = nullptr;
inline jclass cl_file_descriptor = nullptr;
inline jclass cl_parcel_file_descriptor = nullptr;

inline jmethodID mid_get_service = nullptr;
inline jmethodID mid_obtain = nullptr;
inline jmethodID mid_recycle = nullptr;
inline jmethodID mid_transact = nullptr;
inline jmethodID mid_write_int = nullptr;
inline jmethodID mid_write_string = nullptr;
inline jmethodID mid_write_file_descriptor = nullptr;
inline jmethodID mid_write_strong_binder = nullptr;
inline jmethodID mid_write_interface_token = nullptr;
inline jmethodID mid_create_pipe = nullptr;
inline jmethodID mid_get_file_descriptor = nullptr;
inline jmethodID mid_get_fd = nullptr;
inline jmethodID mid_file_descriptor_cstr = nullptr;

inline jfieldID fid_stdin = nullptr;

void InitJNIHelper(JNIEnv* env);

jobject LoadDex(JNIEnv* env, const uint8_t* dex, size_t len);

jclass FindClassFromLoader(JNIEnv* env, jobject class_loader, const char* class_name);
