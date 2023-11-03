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

#include "ql-sahara-core.h"
#include "ql-usb.h"


#define dbg_time printf
bool qdl_debug;


static uint32_t le_uint32(uint32_t v32);
static uint8_t to_hex(uint8_t ch);
static void print_hex_dump(const char *prefix, const void *buf, size_t len);
static FILE *create_reset_single_image(void);

const char *boot_sahara_cmd_id_str[QUEC_SAHARA_FW_UPDATE_END_ID+1] = {
        "SAHARA_NO_CMD_ID",               // = 0x00,
        " SAHARA_HELLO_ID",               // = 0x01, // sent from target to host
        "SAHARA_HELLO_RESP_ID",           // = 0x02, // sent from host to target
        "SAHARA_READ_DATA_ID",            // = 0x03, // sent from target to host
        "SAHARA_END_IMAGE_TX_ID",         // = 0x04, // sent from target to host
        "SAHARA_DONE_ID",                 // = 0x05, // sent from host to target
        "SAHARA_DONE_RESP_ID",            // = 0x06, // sent from target to host
        "SAHARA_RESET_ID",                // = 0x07, // sent from host to target
        "SAHARA_RESET_RESP_ID",           // = 0x08, // sent from target to host
        "SAHARA_MEMORY_DEBUG_ID",         // = 0x09, // sent from target to host
        "SAHARA_MEMORY_READ_ID",          // = 0x0A, // sent from host to target
        "SAHARA_CMD_READY_ID",            // = 0x0B, // sent from target to host
        "SAHARA_CMD_SWITCH_MODE_ID",      // = 0x0C, // sent from host to target
        "SAHARA_CMD_EXEC_ID",             // = 0x0D, // sent from host to target
        "SAHARA_CMD_EXEC_RESP_ID",        // = 0x0E, // sent from target to host
        "SAHARA_CMD_EXEC_DATA_ID",        // = 0x0F, // sent from host to target
        "SAHARA_64_BITS_MEMORY_DEBUG_ID", // = 0x10, // sent from target to host
        "SAHARA_64_BITS_MEMORY_READ_ID",  // = 0x11, // sent from host to target
        "SAHARA_64_BITS_READ_DATA_ID",    // = 0x12,
        "NOP",                            // = 0x13,
        "NOP",
        "NOP",
        "NOP",
        "NOP",
        "NOP",
        "NOP",
        "NOP",
        "NOP",
        "NOP",
        "NOP",
        "NOP",
        "NOP",
        "QUEC_SAHARA_FW_UPDATE_PROCESS_REPORT_ID",
        "QUEC_SAHARA_FW_UPDATE_END_ID"
};

uint32_t le_uint32(uint32_t v32)
{
    const uint32_t is_bigendian = 1;
    uint32_t tmp = v32;
    if ((*(uint8_t *)&is_bigendian) == 0)
    {
        uint8_t *s = (uint8_t *)(&v32);
        uint8_t *d = (uint8_t *)(&tmp);
        d[0] = s[3];
        d[1] = s[2];
        d[2] = s[1];
        d[3] = s[0];
    }
    return tmp;
}

static uint8_t to_hex(uint8_t ch)
{
    ch &= 0xf;
    return ch <= 9 ? '0' + ch : 'a' + ch - 10;
}


static void print_hex_dump(const char *prefix, const void *buf, size_t len)
{
    const uint8_t *ptr = buf;
    size_t linelen;
    uint8_t ch;
    char line[16 * 3 + 16 + 1];
    int li;
    size_t i;
    size_t j;

    for (i = 0; i < len; i += 16)
    {
        linelen = MIN(16, len - i);
        li = 0;

        for (j = 0; j < linelen; j++)
        {
            ch = ptr[i + j];
            line[li++] = to_hex(ch >> 4);
            line[li++] = to_hex(ch);
            line[li++] = ' ';
        }

        for (; j < 16; j++)
        {
            line[li++] = ' ';
            line[li++] = ' ';
            line[li++] = ' ';
        }

        for (j = 0; j < linelen; j++)
        {
            ch = ptr[i + j];
            line[li++] = isprint(ch) ? ch : '.';
        }

        line[li] = '\0';

        syslog(0, "%s %04zx: %s\n", prefix, i, line);
    }
}


FILE *create_reset_single_image(void)
{
    int fd;
    FILE *fp = NULL;

    struct single_image_hdr *img_hdr;

    img_hdr = malloc(SINGLE_IMAGE_HDR_SIZE);
    if (img_hdr == NULL)
        return NULL;

    memset(img_hdr, 0, SINGLE_IMAGE_HDR_SIZE);

    img_hdr->magic[0] = 'R';
    img_hdr->magic[1] = 'S';
    img_hdr->magic[2] = 'T';

    fd = open("/tmp", O_TMPFILE | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0)
        goto EXIT;

    fp = fdopen(fd, "w+");

    if (fwrite(img_hdr, 1, SINGLE_IMAGE_HDR_SIZE, fp) != SINGLE_IMAGE_HDR_SIZE)
    {
        dbg("fail to write\n");
        fclose(fp);
        fp = NULL;
    }
    else 
    {
        fseek(fp, 0, SEEK_SET);
    }

EXIT:
    free(img_hdr);
    return fp;
}


int sahara_rx_data(struct qdl_device *qdl, void *rx_buffer, size_t bytes_to_read)
{
    struct sahara_pkt * rx_pkt = NULL;
    size_t bytes_read = 0;
    if (!bytes_to_read)
    {
        bytes_read = qdl_read(qdl, rx_buffer, sizeof(struct sahara_pkt), 5000);
        rx_pkt = (struct sahara_pkt *)rx_buffer;
        dbg("RECEIVED <-- %s %ld bytes\n", boot_sahara_cmd_id_str[le_uint32(rx_pkt->cmd)], bytes_read);
        return bytes_read;
    }

    return 0;
}

static void sahara_hello_multi(struct qdl_device *qdl, struct sahara_pkt *pkt)
{
    struct sahara_pkt resp;

    assert(pkt->length == 0x30);
    resp.cmd = 2;
    resp.length = 0x30;
    resp.hello_resp.version = 2;
    resp.hello_resp.compatible = pkt->hello_req.compatible;
    resp.hello_resp.status = 0;
    resp.hello_resp.mode = 0x10; // Super Special Quectel mode

    qdl_write(qdl, &resp, resp.length);
    return;
}


static int start_image_transfer(void *usb_handle, void *tx_buffer, struct sahara_pkt *rx_pkt, FILE *file_handle)
{
    int retval = 0;

    uint32_t bytes_read = 0, bytes_to_read_next;
    uint32_t DataOffset = le_uint32(rx_pkt->read_req.offset);
    uint32_t DataLength = le_uint32(rx_pkt->read_req.length);

    printf("0x%08x 0x%08x 0x%08x\n", le_uint32(rx_pkt->read_req.image), DataOffset, DataLength);

    if (fseek(file_handle, (long)DataOffset, SEEK_SET)) {
        printf("%d errno: %d (%s)", __LINE__, errno, strerror(errno));
        return 0;
    }

    while (bytes_read < DataLength) {
        bytes_to_read_next = MIN((uint32_t)DataLength - bytes_read, SAHARA_RAW_BUFFER_SIZE);
        retval = fread(tx_buffer, 1, bytes_to_read_next, file_handle);
    
        if (retval < 0) {
            printf("file read failed: %s\n", strerror(errno));
            return 0;
        }
    
        if ((uint32_t) retval != bytes_to_read_next) {
            printf("Read %d bytes, but was asked for 0x%08x bytes\n", retval, DataLength);
            return 0;
	}

	/*send the image data*/
	if (0 == qdl_write (usb_handle, tx_buffer, bytes_to_read_next)) {
            printf("Tx Sahara Image Failed\n");
            return 0;
	}
    
	bytes_read += bytes_to_read_next;
    }

    return 1;
}

int sahara_flash_all(char *main_file_path, char *oem_file_path, char *carrier_file_path)
{
    int ret;
    int i, count;
    void *tx_buffer;
    FILE *file_handle;

    struct qdl_device qdl;
    struct sahara_pkt *pspkt;
    char buffer[QBUFFER_SIZE];
    int nBytes = 0;
    char * files[4];
    char * current_file_name;
    bool done = false;
    ret = qdl_open(&qdl);

    if (ret)
    {
        syslog(0, "Could not find a Quectel device ready to flash!\n");
        return -1;
    }
    else
    {
        syslog(0, "%s: Found a Quectel device ready to flash!\n",__FUNCTION__);
    }

    count = 0;
    if ( strlen(main_file_path) )
        files[count++] = main_file_path;

    if ( strlen(carrier_file_path) )
        files[count++] = carrier_file_path;

    if ( strlen(oem_file_path) )
        files[count++] = oem_file_path;

    if (!count) {
	    qdl_close(&qdl);
	    return -1;
    }
    files[count++] = NULL; // for rest image

    memset(buffer, 0 , QBUFFER_SIZE );
    nBytes = sahara_rx_data(&qdl, buffer, 0);
    pspkt = (struct sahara_pkt *)buffer;

    if (le_uint32(pspkt->cmd) != 0x01)
    {
        dbg("Received a different command: %x while waiting for hello packet \n Bytes received %d\n", pspkt->cmd, nBytes);
        qdl_close(&qdl);
        return -1;
    }
    sahara_hello_multi(&qdl, pspkt);

    tx_buffer = malloc(SAHARA_RAW_BUFFER_SIZE);
    if (!tx_buffer)
    {
        qdl_close(&qdl);
        return -1;
    }

    for(i = 0; i < count; i++)
    {
        current_file_name = files[i];
        if (current_file_name) {
            syslog(0, "\nFlashing : %s\n", current_file_name);
            file_handle = fopen(current_file_name, "rb");
        } else {
            syslog(0, "\nFlashing reset image\n");
            file_handle = create_reset_single_image();
        }

        if (!file_handle)
        {
            qdl_close(&qdl);
            free(tx_buffer);
        }

        done = false;
        while(!done) {
            memset(buffer, 0 , QBUFFER_SIZE );
            nBytes = sahara_rx_data(&qdl, buffer, 0);
            if (nBytes < 0)
            {
                continue;
            }
            pspkt = (struct sahara_pkt *)buffer;
            if ((uint32_t)nBytes != pspkt->length)
            {
                fprintf(stderr, "Sahara pkt length not matching");

                fclose(file_handle);
                free(tx_buffer);
                qdl_close(&qdl);
                return -EINVAL;
            }

            if (pspkt->cmd == 3)
            {
                start_image_transfer(&qdl, tx_buffer, pspkt, file_handle);
                continue;
            }
            if  (pspkt->cmd == QUEC_SAHARA_FW_UPDATE_PROCESS_REPORT_ID)
            {
                dbg("Writing %d percent %c", le_uint32(pspkt->packet_fw_update_process_report.percent), (le_uint32(pspkt->packet_fw_update_process_report.percent == 100) ? '\n' : '\r'));
                continue;
            }

            if (pspkt->cmd == QUEC_SAHARA_FW_UPDATE_END_ID)
            {
                if (le_uint32(pspkt->packet_fw_update_end.successful))
                    dbg("firmware flash error (%d)", le_uint32(pspkt->packet_fw_update_end.successful));
                else
                {
                    dbg("firmware flash successful");
                }
                done = true;
            }
        }

        fclose(file_handle);
    }
    free(tx_buffer);
    qdl_close(&qdl);
    return 0;
}


static int firehose_sahara_start(void *usb_handle, void *tx_buffer, void *rx_buffer, FILE *file_handle) {
    struct sahara_pkt *rx_pkt = (struct sahara_pkt *)rx_buffer;
    struct sahara_pkt *tx_pkt = (struct sahara_pkt *)tx_buffer;   

    printf("STATE <-- SAHARA_WAIT_HELLO\n");
    if (0 == sahara_rx_data(usb_handle, rx_buffer, 0)) 
    {
        return -1;
    }

    if (le_uint32(rx_pkt->cmd) != 0x01)  // hello id
    { 
        printf("Received a different command: %x while waiting for hello packet", rx_pkt->cmd);
        return -1;
    }
    
    tx_pkt->cmd = 0x02;
    tx_pkt->length = 0x30;
    tx_pkt->hello_resp.version = rx_pkt->hello_req.version;
    tx_pkt->hello_resp.compatible = rx_pkt->hello_req.compatible;
    tx_pkt->hello_resp.status = 0;
    tx_pkt->hello_resp.mode = rx_pkt->hello_req.mode;

    switch (le_uint32(rx_pkt->hello_req.mode)) {
        case 0x00: 
            printf("RECEIVED <-- SAHARA_MODE_IMAGE_TX_PENDING\n");
        break;
        case 0x01: 
            printf("RECEIVED <-- SAHARA_MODE_IMAGE_TX_COMPLETE\n");
        break;
        case 0x02: 
            printf("RECEIVED <-- SAHARA_MODE_MEMORY_DEBUG\n");
        break;
        case 0x03: 
            printf("RECEIVED <-- SAHARA_MODE_COMMAND\n");
        break;
        default:
            printf("RECEIVED <-- SAHARA_MODE_0x%x\n", le_uint32(rx_pkt->hello_req.mode));
        break;
    }

    if (le_uint32(rx_pkt->hello_req.mode) != 0x00) {
        printf("ERROR NOT SAHARA_MODE_IMAGE_TX_PENDING\n");
        tx_pkt->hello_resp.mode = 0x00;
    }

    /*Send the Hello  Resonse Request*/
    printf("SENDING --> SAHARA_HELLO_RESPONSE\n");
    if (0 == qdl_write (usb_handle, tx_buffer, tx_pkt->length))
    {
        printf("Tx Sahara Data Failed \n");
        return -1;
    }

    while (1) {
        printf("STATE <-- SAHARA_WAIT_COMMAND\n");
        if (0 == sahara_rx_data(usb_handle, rx_buffer, 0))
            return -1;

        if (le_uint32(rx_pkt->cmd) == 0x03) {
            start_image_transfer(usb_handle, tx_buffer, rx_pkt, file_handle);
        }
        else if (le_uint32(rx_pkt->cmd) == 0x04) {
            printf("image_id = %d, status = %d\n", le_uint32(rx_pkt->eoi.image), le_uint32(rx_pkt->eoi.status));
            if (le_uint32(rx_pkt->eoi.status) == 0x00) 
            {
                tx_pkt->cmd = 0x05;
                tx_pkt->length = 0x08;

                // Send the image data
                printf("SENDING --> SAHARA_DONE\n");
                if (0 == qdl_write (usb_handle, tx_buffer, 8)) 
                {
                    printf("Sending DONE packet failed\n");
                    return -1;
                }

                break;
            } 
            else 
            {
                return -1;
            }
        }
        else if (le_uint32(rx_pkt->cmd) == 0x01) {
             continue;
        }
        else {
            printf("Received an unknown command: %d ", le_uint32(rx_pkt->cmd));
            // send_reset_command (usb_handle, tx_buffer);
            return -1;
        }
    }

    printf("STATE <-- SAHARA_WAIT_DONE_RESP\n");
    if (0 == sahara_rx_data(usb_handle, rx_buffer, 0))
        return -1;

    printf("Successfully uploaded all images\n");

    return 0;
}

int firehose_sahara(void *usb_handle, const char *firehose_mbn) 
{
    int ret = 0;
    FILE *file_handle;
    void *tx_buffer;
    void *rx_buffer;

    file_handle = fopen(firehose_mbn, "rb\n");
    if (file_handle == NULL) {
        printf("%s %d %s errno: %d (%s)", __func__, __LINE__, firehose_mbn, errno, strerror(errno));
        return -1;
    }

    rx_buffer = malloc (SAHARA_RAW_BUFFER_SIZE);
    tx_buffer = malloc (SAHARA_RAW_BUFFER_SIZE);

    if (NULL == rx_buffer || NULL == tx_buffer) {
        printf("Failed to allocate sahara buffers\n");
        return -1;
    }

    ret = firehose_sahara_start(usb_handle, tx_buffer, rx_buffer, file_handle);
    
    free(rx_buffer);
    free(tx_buffer);
    fclose(file_handle);

    return ret;
}