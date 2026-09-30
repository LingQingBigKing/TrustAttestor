#include "jni_helper.h"
#include "logging.h"

static bool CheckAndClearJniException(JNIEnv* env, const char* where) {
    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
        LOGE("JNI error at {}", where);
        return true;
    }
    return false;
}

void InitJNIHelper(JNIEnv* env) {
    static bool initialized = false;
    if (initialized) return;
    jclass local_service_manager = env->FindClass("android/os/ServiceManager");
    if (CheckAndClearJniException(env, "FindClass(ServiceManager)") || local_service_manager == nullptr) return;
    cl_service_manager = reinterpret_cast<jclass>(env->NewGlobalRef(local_service_manager));
    env->DeleteLocalRef(local_service_manager);

    jclass local_parcel = env->FindClass("android/os/Parcel");
    if (CheckAndClearJniException(env, "FindClass(Parcel)") || local_parcel == nullptr) return;
    cl_parcel = reinterpret_cast<jclass>(env->NewGlobalRef(local_parcel));
    env->DeleteLocalRef(local_parcel);

    jclass local_binder = env->FindClass("android/os/IBinder");
    if (CheckAndClearJniException(env, "FindClass(IBinder)") || local_binder == nullptr) return;
    cl_binder = reinterpret_cast<jclass>(env->NewGlobalRef(local_binder));
    env->DeleteLocalRef(local_binder);

    jclass local_file_descriptor = env->FindClass("java/io/FileDescriptor");
    if (CheckAndClearJniException(env, "FindClass(FileDescriptor)") || local_file_descriptor == nullptr) return;
    cl_file_descriptor = reinterpret_cast<jclass>(env->NewGlobalRef(local_file_descriptor));
    env->DeleteLocalRef(local_file_descriptor);

    jclass local_parcel_file_descriptor = env->FindClass("android/os/ParcelFileDescriptor");
    if (CheckAndClearJniException(env, "FindClass(ParcelFileDescriptor)") || local_parcel_file_descriptor == nullptr) return;
    cl_parcel_file_descriptor = reinterpret_cast<jclass>(env->NewGlobalRef(local_parcel_file_descriptor));
    env->DeleteLocalRef(local_parcel_file_descriptor);

    mid_get_service = env->GetStaticMethodID(cl_service_manager, "getService", "(Ljava/lang/String;)Landroid/os/IBinder;");
    if (CheckAndClearJniException(env, "GetStaticMethodID(getService)") || mid_get_service == nullptr) return;

    mid_obtain = env->GetStaticMethodID(cl_parcel, "obtain", "()Landroid/os/Parcel;");
    if (CheckAndClearJniException(env, "GetStaticMethodID(obtain)") || mid_obtain == nullptr) return;

    mid_recycle = env->GetMethodID(cl_parcel, "recycle", "()V");
    if (CheckAndClearJniException(env, "GetMethodID(recycle)") || mid_recycle == nullptr) return;

    mid_transact = env->GetMethodID(cl_binder, "transact", "(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z");
    if (CheckAndClearJniException(env, "GetMethodID(transact)") || mid_transact == nullptr) return;

    mid_write_int = env->GetMethodID(cl_parcel, "writeInt", "(I)V");
    if (CheckAndClearJniException(env, "GetMethodID(writeInt)") || mid_write_int == nullptr) return;

    mid_write_string = env->GetMethodID(cl_parcel, "writeString", "(Ljava/lang/String;)V");
    if (CheckAndClearJniException(env, "GetMethodID(writeString)") || mid_write_string == nullptr) return;

    mid_write_file_descriptor = env->GetMethodID(cl_parcel, "writeFileDescriptor", "(Ljava/io/FileDescriptor;)V");
    if (CheckAndClearJniException(env, "GetMethodID(writeFileDescriptor)") || mid_write_file_descriptor == nullptr) return;

    mid_write_strong_binder = env->GetMethodID(cl_parcel, "writeStrongBinder", "(Landroid/os/IBinder;)V");
    if (CheckAndClearJniException(env, "GetMethodID(writeStrongBinder)") || mid_write_strong_binder == nullptr) return;

    mid_write_interface_token = env->GetMethodID(cl_parcel, "writeInterfaceToken", "(Ljava/lang/String;)V");
    if (CheckAndClearJniException(env, "GetMethodID(writeInterfaceToken)") || mid_write_interface_token == nullptr) return;

    mid_create_pipe = env->GetStaticMethodID(cl_parcel_file_descriptor, "createPipe", "()[Landroid/os/ParcelFileDescriptor;");
    if (CheckAndClearJniException(env, "GetStaticMethodID(createPipe)") || mid_create_pipe == nullptr) return;

    mid_get_file_descriptor = env->GetMethodID(cl_parcel_file_descriptor, "getFileDescriptor", "()Ljava/io/FileDescriptor;");
    if (CheckAndClearJniException(env, "GetMethodID(getFileDescriptor)") || mid_get_file_descriptor == nullptr) return;

    mid_get_fd = env->GetMethodID(cl_parcel_file_descriptor, "getFd", "()I");
    if (CheckAndClearJniException(env, "GetMethodID(getFd)") || mid_get_fd == nullptr) return;

    mid_file_descriptor_cstr = env->GetMethodID(cl_file_descriptor, "<init>", "(I)V");
    if (CheckAndClearJniException(env, "GetMethodID(file_descriptor_init)") || mid_file_descriptor_cstr == nullptr) return;

    fid_stdin = env->GetStaticFieldID(cl_file_descriptor, "in", "Ljava/io/FileDescriptor;");
    if (CheckAndClearJniException(env, "GetStaticFieldID(FileDescriptor.in)") || fid_stdin == nullptr) return;
    initialized = true;
}

jobject LoadDex(JNIEnv* env, const uint8_t* dex, size_t len) {
    auto cl_class_loader = env->FindClass("java/lang/ClassLoader");
    auto mid_get_system_class_loader = env->GetStaticMethodID(
            cl_class_loader, "getSystemClassLoader", "()Ljava/lang/ClassLoader;");
    auto sys_classloader = env->CallStaticObjectMethod(cl_class_loader, mid_get_system_class_loader);
    auto cl_in_memory_classloader = env->FindClass("dalvik/system/InMemoryDexClassLoader");
    auto mid_init = env->GetMethodID(
            cl_in_memory_classloader, "<init>", "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
    auto dex_buffer = env->NewDirectByteBuffer((void*) dex, len);
    auto my_cl = env->NewObject(cl_in_memory_classloader, mid_init, dex_buffer, sys_classloader);
    env->DeleteLocalRef(dex_buffer);
    env->DeleteLocalRef(cl_in_memory_classloader);
    env->DeleteLocalRef(sys_classloader);
    env->DeleteLocalRef(cl_class_loader);
    return my_cl;
}

jclass FindClassFromLoader(JNIEnv* env, jobject class_loader, const char* class_name) {
    if (class_loader == nullptr) return nullptr;
    auto clz = env->FindClass("java/lang/ClassLoader");
    if (clz == nullptr) return nullptr;
    auto mid = env->GetMethodID(clz, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    if (!mid) {
        mid = env->GetMethodID(clz, "findClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    }
    if (mid) [[likely]] {
        auto name = env->NewStringUTF(class_name);
        if (name == nullptr) {
            env->DeleteLocalRef(clz);
            return nullptr;
        }
        auto target = env->CallObjectMethod(class_loader, mid, name);
        env->DeleteLocalRef(name);
        env->DeleteLocalRef(clz);
        return (jclass) target;
    }
    env->DeleteLocalRef(clz);
    return nullptr;
}
