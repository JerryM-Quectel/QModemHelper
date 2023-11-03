/*
    Copyright 2023 Quectel Wireless Solutions Co.,Ltd

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

#ifndef __QL_USB_H__
#define __QL_USB_H__

#include <sys/types.h>


#define MAX_NUM_ENDPOINTS 0xff
#define MAX_NUM_INTERFACES 0xff

#define SWITCHED_TO_EDL 1
#define SWITCHED_TO_SBL 0

struct qdl_device
{
    int fd;
    int in_ep;
    int out_ep;
    size_t in_maxpktsize;
    size_t out_maxpktsize;
};

int qdl_write(struct qdl_device *qdl, const void *buf, size_t len);
int qdl_read(struct qdl_device *qdl, void *buf, size_t len, unsigned int timeout);
int qdl_open(struct qdl_device *qdl);
int qdl_close(struct qdl_device *qdl);
int flash_mode_check(void);



#endif