/*
 * Copyright (c) 1999 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * "Portions Copyright (c) 1999 Apple Computer, Inc.  All Rights
 * Reserved.  This file contains Original Code and/or Modifications of
 * Original Code as defined in and that are subject to the Apple Public
 * Source License Version 1.0 (the 'License').  You may not use this file
 * except in compliance with the License.  Please obtain a copy of the
 * License at http://www.apple.com/publicsource and read it before using
 * this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License."
 *
 * @APPLE_LICENSE_HEADER_END@
 */

/*
 * http://www.opensource.apple.com/source/system_cmds/system_cmds-496/fs_usage.tproj/fs_usage.c?txt
 * ReadSharedCacheMap has been modified to retrieve the dyld address info from dyld cache map file
 */


#include "dyldcache_parser.h"

int scanline(char *inputstring, char **argv, int maxtokens) {
    int n = 0;
    char **ap = argv, *p, *val;

    for (p = inputstring; n < maxtokens && p != NULL; ) {

        while ((val = strsep(&p, " \t")) != NULL && *val == '\0');

        *ap++ = val;
        n++;
    }
    *ap = 0;

    return n;
}

/*
 * caller is responsible for freeing the memory allocated here
 */

library_all_infos_struct* ReadSharedCacheMap(const char *path) {
    uint64_t b_address, e_address;
    char frameworkName[256];
    char *tokens[64];
    char buf[1024];
    char *fnp;
    FILE *fd;
    int    ntokens;
    int    type;
    int    linkedit_found = 0;
    char *substring, *ptr;
    int numFrameworks = 0;

    bzero(buf, sizeof(buf));
    bzero(tokens, sizeof(tokens));

    if ((fd = fopen(path, "r")) == 0)
    {
        return 0;
    }
    while (fgets(buf, 1023, fd)) {
        if (strncmp(buf, "mapping", 7))
            break;
    }
    buf[strlen(buf)-1] = 0;

    frameworkName[0] = 0;

    int start;

    library_all_infos_struct* lib_all_infos =safe_malloc(sizeof(library_all_infos_struct));
    lib_all_infos->count = 0;
    for (;;) {
        //Extract lib name from path name

        ptr = buf;
        substring = ptr;
        start = 0;
        while (*ptr)  {
            if (*ptr == '/' && start == 0) {
                substring = ptr;
                start = 1;
            }
            ptr++;
        }

        strncpy(frameworkName, substring, 256);
        frameworkName[255] = 0;

        fnp = (char *)malloc(strlen(frameworkName) + 1);
        strcpy(fnp, frameworkName);

        while (fgets(buf, 1023, fd) && numFrameworks < (MAXINDEX - 2)) {
            /*
             * Get rid of EOL
             */
            buf[strlen(buf)-1] = 0;

            ntokens = scanline(buf, tokens, 64);

            if (ntokens < 4)
                continue;

            if (strncmp(tokens[0], "__TEXT", 6) == 0)
                type = TEXT_R;
            else if (strncmp(tokens[0], "__DATA", 6) == 0)
                type = DATA_R;
            else if (strncmp(tokens[0], "__OBJC", 6) == 0)
                type = OBJC_R;
            else if (strncmp(tokens[0], "__IMPORT", 8) == 0)
                type = IMPORT_R;
            else if (strncmp(tokens[0], "__UNICODE", 9) == 0)
                type = UNICODE_R;
            else if (strncmp(tokens[0], "__IMAGE", 7) == 0)
                type = IMAGE_R;
            else if (strncmp(tokens[0], "__LINKEDIT", 10) == 0)
                type = LINKEDIT_R;
            else
                type = -1;

            if (type == LINKEDIT_R && linkedit_found)
                break;

            if (type != -1) {
                b_address = strtoull(tokens[1], 0, 16);
                e_address = strtoull(tokens[3], 0, 16);

                library_info_struct* new_lib_info = safe_malloc(sizeof(library_info_struct));

                new_lib_info->b_address    = b_address;
                new_lib_info->e_address    = e_address;
                new_lib_info->r_type    = type;
                new_lib_info->name        = fnp;

                lib_all_infos->lib_info[lib_all_infos->count++] = new_lib_info;

                if (type == LINKEDIT_R) {
                    linkedit_found = 1;
                }
// #if DEBUG
//                 printf("%s(%d): %qx-%qx\n", frameworkInfo[numFrameworks].name, type, b_address, e_address);
// #endif

                numFrameworks++;
            }
            if (type == LINKEDIT_R)
                break;
        }
        if (fgets(buf, 1023, fd) == 0)
            break;

        buf[strlen(buf)-1] = 0;
    }
    fclose(fd);

// #if DEBUG
//     for(int i=0;i<lib_all_infos->count;i++)
//     {
//         library_info_struct* dyldinfo = lib_all_infos->lib_info[i];

//         printf("%p %p %d %s \n", dyldinfo->b_address, dyldinfo->e_address, dyldinfo->r_type, dyldinfo->name);

//     }
// #endif

    return lib_all_infos;
}

/*
 * caller is responsible for freeing the memory allocated here
 */

dyld_map* find_dyld_map(library_all_infos_struct* dyld_infos, char *dylib_path) {

    dyld_map* dyld_map_info = safe_malloc(sizeof(dyld_map));
    int text_found=0, data_found=0;

    for(uint32_t i=0; i<=dyld_infos->count; i++) {
        library_info_struct* info = dyld_infos->lib_info[i];

        if (!(strncmp(info->name, dylib_path, strlen(dylib_path)))) {

            if (info->r_type == TEXT_R) {
                dyld_map_info->name = info->name;
                dyld_map_info->image_start_address = info->b_address;
                dyld_map_info->image_end_address = info->e_address;

                text_found =1;
            }
            else if (info->r_type == DATA_R) {
                dyld_map_info->name = info->name;
                dyld_map_info->data_start_address = info->b_address;
                dyld_map_info->data_end_address = info->b_address;
                data_found =1;

            }

        }
        if (text_found==1 && data_found==1) {
            return dyld_map_info;

        }
    }
    return NULL;
}
