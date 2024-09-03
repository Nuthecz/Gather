//
// Created by NU on 2024/8/31.
//

#ifndef GATHER_HOOKDETECTION_H
#define GATHER_HOOKDETECTION_H

#pragma once

#include "../include/elf_util.h"
#include "../include/config.h"
#include <jni.h>
#include <list>
#include <string>
#include <set>
#include <zlib.h>
#include <fcntl.h>

// 通过 CRC32 比较内存和本地文件数据比较 open 处是否被修改
void openHookStatus();

// 通过 CRC32 比较内存和本地文件数据比较 .text 和 .plt段 是否被修改
void segmentHookStatus();

// 通过 CRC32 比较内存和本地文件数据比较 PrettyMethod 是否被修改
void prettyMethodHookStatus();

// 利用 java 层调用栈检测 hook 工具存在状态，主要是解析 StackTraceElement[] 这个数组来进行检测
void callStackDetection(JNIEnv *env);

#endif //GATHER_HOOKDETECTION_H
