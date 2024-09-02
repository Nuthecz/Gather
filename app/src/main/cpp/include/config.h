//
// Created by NU on 2024/8/31.
//

#ifndef GATHER_CONFIG_H
#define GATHER_CONFIG_H

#pragma once
#include <android/log.h>
#include <string>

// 配置日志
#define TAG "tcz"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__);
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO , TAG, __VA_ARGS__);
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__);
#define LOGV(...) __android_log_print(ANDROID_LOG_VERBOSE, TAG, __VA_ARGS__);
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__);

#endif //GATHER_CONFIG_H
