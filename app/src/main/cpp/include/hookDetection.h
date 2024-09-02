//
// Created by NU on 2024/8/31.
//

#ifndef GATHER_HOOKDETECTION_H
#define GATHER_HOOKDETECTION_H

#pragma once
#include "../include/elf_util.h"
#include "../include/config.h"

// 通过 CRC32 比较内存和本地文件数据比较 open 处是否被修改
void calculateOpen();

// 通过 CRC32 比较内存和本地文件数据比较 .text 和 .plt段 是否被修改
void calculateSegment();

#endif //GATHER_HOOKDETECTION_H
