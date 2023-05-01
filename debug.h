/*
 * debug.h - Debugging utilities
 *
 * Part of the "msx" project.
 * Originally from another project under the MIT License.
 *
 * Copyright (c) 2023 miloserdev
 *
 * This file is distributed under the terms of the MIT License.
 * See the LICENSE file in the root of this repository.
 */

#ifndef         __MSX_DEBUG__
#define         __MSX_DEBUG__


#include <stdio.h>
#include <stdint.h>

#define debug(__format, ...) { printf("___ %s : %s : %d ___ >>> "__format" \n", __func__, __FILE__, __LINE__, __VA_ARGS__); }


#endif