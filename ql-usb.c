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

#define _GNU_SOURCE
#include <linux/usbdevice_fs.h>
#include <linux/usb/ch9.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <err.h>
#include <libudev.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <syslog.h>
#include <dirent.h>

#include "ql-usb.h"


int check_quec_usb_desc(int fd, struct qdl_device *qdl, int *intf)
{
    const struct usb_interface_descriptor *ifc;
    const struct usb_endpoint_descriptor *ept;
    const struct usb_device_descriptor *dev;
    const struct usb_config_descriptor *cfg;
    const struct usb_descriptor_header *hdr;
    unsigned type;
    unsigned out;
    unsigned in;
    unsigned k;
    unsigned l;
    ssize_t n;
    size_t out_size;
    size_t in_size;
    void *ptr;
    void *end;
    char desc[1024];

    n = read(fd, desc, sizeof(desc));
    if (n < 0)
    {
        return n;
    }
    ptr = (void*)desc;
    end = ptr + n;
    dev = ptr;

    /* Consider only devices with vid 0x2c7c */
    if ((dev->idVendor != 0x2c7c) && (dev->idVendor != 0x05c6)) 
    {
        return -EINVAL;
    }
    else
    {
        if (dev->idProduct == 9008)
        {
            return SWITCHED_TO_EDL;
        }
    }

    printf("D: idVendor=%04x idProduct=%04x\n",  dev->idVendor, dev->idProduct);
    ptr += dev->bLength;

    if (ptr >= end || dev->bDescriptorType != USB_DT_DEVICE)
        return -EINVAL;

    cfg = ptr;
    ptr += cfg->bLength;
    if (ptr >= end || cfg->bDescriptorType != USB_DT_CONFIG)
        return -EINVAL;

    unsigned numInterfaces = cfg->bNumInterfaces;
    printf("C: bNumInterfaces: %d\n", numInterfaces);

    if (numInterfaces <= 0 || numInterfaces > MAX_NUM_INTERFACES)
    {
        syslog(0, "invalid no of interfaces: %d\n", numInterfaces);
        return -EINVAL;
    }
    for (k = 0; k < numInterfaces; k++)
    {
        if (ptr >= end)
        {
            return -EINVAL;
        }

        do
        {
            ifc = ptr;
            if (ifc->bLength < USB_DT_INTERFACE_SIZE)
            {
                syslog(0, "Exiting here ifc->bLengh:%d Interface size: %d\n", ifc->bLength, USB_DT_INTERFACE_SIZE);
            }
            ptr += ifc->bLength;

        } while (ptr < end && ifc->bDescriptorType != USB_DT_INTERFACE);

        printf("I: If#= %d Alt= %d #EPs= %d Cls=%02x Sub=%02x Prot=%02x\n",
                ifc->bInterfaceNumber, ifc->bAlternateSetting,
                ifc->bNumEndpoints, ifc->bInterfaceClass,
                ifc->bInterfaceSubClass, ifc->bInterfaceProtocol);
        in = -1;
        out = -1;
        in_size = 0;
        out_size = 0;

        unsigned noOfEndpoints = ifc->bNumEndpoints;
        if (noOfEndpoints <= 0 || noOfEndpoints > MAX_NUM_ENDPOINTS)
        {
            syslog(0, "invalid no of endpoints: %d\n", noOfEndpoints);
            continue;
        }
        for (l = 0; l < noOfEndpoints; l++)
        {
            if (ptr >= end)
            {
                syslog(0, "%s %d end has been reached\n",__FILE__, __LINE__);
                return -EINVAL;
            }

            do
            {
                ept = ptr;
                if (ept->bLength < USB_DT_ENDPOINT_SIZE)
                {
                    syslog(0, "%s %d endpoint length:%d expected size: %d \n",__FILE__, __LINE__, ept->bLength,  USB_DT_ENDPOINT_SIZE);
                    return -EINVAL;
                }
                ptr += ept->bLength;
            } while (ptr < end && ept->bDescriptorType != USB_DT_ENDPOINT);

            printf("E: Ad=%02x Atr=%02x MxPS= %d Ivl=%dms\n",
                ept->bEndpointAddress,
                ept->bmAttributes,
                ept->wMaxPacketSize,
                ept->bInterval);

            type = ept->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK;
            if (type != USB_ENDPOINT_XFER_BULK)
                continue;

            if (ept->bEndpointAddress & USB_DIR_IN)
            {
                in = ept->bEndpointAddress;
                in_size = ept->wMaxPacketSize;
            }
            else
            {
                out = ept->bEndpointAddress;
                out_size = ept->wMaxPacketSize;
            }

            if (ptr >= end)
                break;

            hdr = ptr;
            if (hdr->bDescriptorType == USB_DT_SS_ENDPOINT_COMP)
                ptr += USB_DT_SS_EP_COMP_SIZE;
        }

        if (ifc->bInterfaceClass != 0xff)
            continue;

        if (ifc->bInterfaceSubClass != 0xff)
            continue;

        if (ifc->bInterfaceProtocol != 0xff &&
            ifc->bInterfaceProtocol != 16 &&
            ifc->bInterfaceProtocol != 17)
            continue;

        qdl->fd = fd;
        qdl->in_ep = in;
        qdl->out_ep = out;
        qdl->in_maxpktsize = in_size;
        qdl->out_maxpktsize = out_size;

        if( qdl->in_maxpktsize <= 0 || qdl->out_maxpktsize <= 0 )
        {
            syslog(0, "%s %d invalid max packet size received.\n",__FILE__, __LINE__);
            return -ENOENT;
        }
        
        *intf = ifc->bInterfaceNumber;

        return SWITCHED_TO_SBL;
    }

    return -ENOENT;
}

int qdl_read(struct qdl_device *qdl, void *buf, size_t len, unsigned int timeout)
{
    struct usbdevfs_bulktransfer bulk = {};
    bulk.ep = qdl->in_ep;
    bulk.len = len;
    bulk.data = buf;
    bulk.timeout = timeout;
    return ioctl(qdl->fd, USBDEVFS_BULK, &bulk);
}

int qdl_write(struct qdl_device *qdl, const void *buf, size_t len)
{
    unsigned char *data = (unsigned char*) buf;
    struct usbdevfs_bulktransfer bulk = {};
    unsigned count = 0;
    size_t len_orig = len;
    int n;
    while(len > 0)
    {
        int xfer;
        xfer = (len > qdl->out_maxpktsize) ? qdl->out_maxpktsize : len;

        bulk.ep = qdl->out_ep;
        bulk.len = xfer;
        bulk.data = data;
        bulk.timeout = 1000;

        n = ioctl(qdl->fd, USBDEVFS_BULK, &bulk);
        if(n != xfer)
        {
            fprintf(stderr, "ERROR: n = %d, errno = %d (%s)\n", n, errno, strerror(errno));
            return -1;
        }
        count += xfer;
        len -= xfer;
        data += xfer;
    }    
    if (len_orig % qdl->out_maxpktsize == 0)
    {
        bulk.ep = qdl->out_ep;
        bulk.len = 0;
        bulk.data = NULL;
        bulk.timeout = 1000;

        n = ioctl(qdl->fd, USBDEVFS_BULK, &bulk);
        if (n < 0)
            return n;
    }
    return count;
}

int qdl_close(struct qdl_device *qdl)
{
    int bInterfaceNumber = 3;
    ioctl(qdl->fd, USBDEVFS_RELEASEINTERFACE, &bInterfaceNumber);
    close(qdl->fd);
    return 0;
}

int qdl_open(struct qdl_device *qdl)
{
    struct udev_enumerate *enumerate;
    struct udev_list_entry *devices;
    struct udev_list_entry *dev_list_entry;
    struct udev_monitor *mon;
    struct udev_device *dev;
    const char *dev_node;
    struct udev *udev;
    const char *path;
    struct usbdevfs_ioctl cmd;
    int intf = -1;
    int ret;
    int fd;

    udev = udev_new();
    if (!udev)
        err(1, "failed to initialize udev");

    mon = udev_monitor_new_from_netlink(udev, "udev");
    udev_monitor_filter_add_match_subsystem_devtype(mon, "usb", NULL);
    udev_monitor_enable_receiving(mon);

    enumerate = udev_enumerate_new(udev);
    udev_enumerate_add_match_subsystem(enumerate, "usb");
    udev_enumerate_scan_devices(enumerate);
    devices = udev_enumerate_get_list_entry(enumerate);

    udev_list_entry_foreach(dev_list_entry, devices)
    {
        path = udev_list_entry_get_name(dev_list_entry);
        dev = udev_device_new_from_syspath(udev, path);
        dev_node = udev_device_get_devnode(dev);

        if (!dev_node)
        {
            continue;
        }
        fd = open(dev_node, O_RDWR);
        if (fd < 0)
            continue;
        printf("D: %s \n", dev_node);
        ret = check_quec_usb_desc(fd, qdl, &intf);
        if (!ret)
        {
            goto found;
        }
        close(fd);
    }

    udev_enumerate_unref(enumerate);
    udev_monitor_unref(mon);
    udev_unref(udev);
    return -ENOENT;

found:
    udev_enumerate_unref(enumerate);
    udev_monitor_unref(mon);
    udev_unref(udev);

    cmd.ifno = intf;
    cmd.ioctl_code = USBDEVFS_DISCONNECT;
    cmd.data = NULL;

    ret = ioctl(qdl->fd, USBDEVFS_IOCTL, &cmd);
    if (ret && errno != ENODATA)
        err(1, "failed to disconnect kernel driver");

    ret = ioctl(qdl->fd, USBDEVFS_CLAIMINTERFACE, &intf);
    if (ret < 0)
        err(1, "failed to claim USB interface");

    return 0;
}

static int file_get_value(const char *fpath, int base)
{
    int value = -1;
    FILE *fp = fopen(fpath, "r");

    if (fp)
    {
        if (fscanf(fp, base == 16 ? "%x" : "%d", &value))
        {
        };
        fclose(fp);
    }

    return value;
}


int flash_mode_check(void)
{
    struct dirent *ent = NULL;
    DIR *pDir;
    const char *rootdir = "/sys/bus/usb/devices";
    int find = 0;
    int idVendor;
    int numInterfaces;

    pDir = opendir(rootdir);
    if (!pDir)
    {
        return 0;
    }

    while ((ent = readdir(pDir)) != NULL)
    {
        int mbim_intf = 0; /* mbim fixed 0 interface*/
        char path[512] = {'\0'};

        snprintf(path, sizeof(path), "%s/%s/idVendor", rootdir, ent->d_name);
        idVendor = file_get_value(path, 16);
        if (idVendor != 0x2c7c)
            continue;

        snprintf(path, sizeof(path), "%s/%s/bNumInterfaces", rootdir, ent->d_name);
        numInterfaces = file_get_value(path, 10);

        if (numInterfaces == 4)
        {
            int bInterfaceClass;
            int bInterfaceProtocol;
            int bInterfaceSubClass;
            int bNumEndpoints;

            snprintf(path, sizeof(path), "%s/%s:1.%d/bInterfaceClass", rootdir, ent->d_name, mbim_intf);
            bInterfaceClass = file_get_value(path, 16);

            snprintf(path, sizeof(path), "%s/%s:1.%d/bInterfaceProtocol", rootdir, ent->d_name, mbim_intf);
            bInterfaceProtocol = file_get_value(path, 16);

            snprintf(path, sizeof(path), "%s/%s:1.%d/bInterfaceSubClass", rootdir, ent->d_name, mbim_intf);
            bInterfaceSubClass = file_get_value(path, 16);

            snprintf(path, sizeof(path), "%s/%s:1.%d/bNumEndpoints", rootdir, ent->d_name, mbim_intf);
            bNumEndpoints = file_get_value(path, 16);

            if (bInterfaceClass == 0x02 && bInterfaceProtocol == 0x00 && bInterfaceSubClass == 0x0e) // mbim interface
            {
                if (bNumEndpoints == 0)
                {
                    find = 1;
                }
            }
        }
    }
    closedir(pDir);

    return find;
}


