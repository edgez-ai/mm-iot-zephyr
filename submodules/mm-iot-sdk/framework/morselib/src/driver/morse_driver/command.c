/*
 * Copyright 2017-2025 Morse Micro
 * SPDX-License-Identifier: GPL-3.0-or-later OR LicenseRef-MorseMicroCommercial
 *
 */

#include <errno.h>
#include <zephyr/sys/printk.h>

#include "command.h"
#include "common/morse_command_utils.h"
#include "skbq.h"
#include "mac.h"
#include "skb_header.h"
#include "ps.h"
#include "common/morse_error.h"

#define MM_BA_TIMEOUT        (5000)
#define MM_MAX_COMMAND_RETRY 3

#ifdef ENABLE_DRVCMD_TRACE
#include "mmtrace.h"
static mmtrace_channel drvcmd_channel_handle;
#define DRVCMD_TRACE_INIT()                                         \
    do {                                                            \
        drvcmd_channel_handle = mmtrace_register_channel("drvcmd"); \
    } while (0)
#define DRVCMD_TRACE(_fmt, ...) mmtrace_printf(drvcmd_channel_handle, _fmt, ##__VA_ARGS__)
#else
#define DRVCMD_TRACE_INIT() \
    do {                    \
    } while (0)
#define DRVCMD_TRACE(_fmt, ...) \
    do {                        \
    } while (0)
#endif

struct mmdrv_cmd_metadata
{
    int ret;
    uint32_t length;
    struct morse_cmd_resp *dest_resp;
    uint32_t resp_maxlen;
};

static const char *morse_cmd_id_name(uint16_t id)
{
    switch (id)
    {
        case MORSE_CMD_ID_SET_CHANNEL:
            return "SET_CHANNEL";
        case MORSE_CMD_ID_GET_VERSION:
            return "GET_VERSION";
        case MORSE_CMD_ID_ADD_INTERFACE:
            return "ADD_INTERFACE";
        case MORSE_CMD_ID_REMOVE_INTERFACE:
            return "REMOVE_INTERFACE";
        case MORSE_CMD_ID_BSS_CONFIG:
            return "BSS_CONFIG";
        case MORSE_CMD_ID_SCAN_CONFIG:
            return "SCAN_CONFIG";
        case MORSE_CMD_ID_SET_STA_STATE:
            return "SET_STA_STATE";
        case MORSE_CMD_ID_CONFIG_PS:
            return "CONFIG_PS";
        case MORSE_CMD_ID_HEALTH_CHECK:
            return "HEALTH_CHECK";
        case MORSE_CMD_ID_UPDATE_OUI_FILTER:
            return "UPDATE_OUI_FILTER";
        case MORSE_CMD_ID_HW_SCAN:
            return "HW_SCAN";
        case MORSE_CMD_ID_SET_CONTROL_RESPONSE:
            return "SET_CONTROL_RESPONSE";
        case MORSE_CMD_ID_MAC_STATS_LOG:
            return "MAC_STATS_LOG";
        case MORSE_CMD_ID_UPHY_STATS_LOG:
            return "UPHY_STATS_LOG";
        default:
            return "UNKNOWN";
    }
}

int morse_cmd_tx(struct driver_data *driverd,
                 struct morse_cmd_resp *resp,
                 struct morse_cmd_req *cmd,
                 uint32_t resp_maxlen,
                 uint32_t timeout)
{
    int cmd_len, ret = 0;
    uint16_t cmd_seq;
    int retry = 0;
    struct mmpkt *mmpkt;
    struct mmpktview *view;

    DRVCMD_TRACE("cmd req %x", le16toh(cmd->hdr.message_id));

    if (driverd->cfg == NULL || driverd->cfg->ops == NULL)
    {

        return -ENODEV;
    }

    struct morse_skbq *cmd_q = driverd->cfg->ops->skbq_cmd_tc_q(driverd);
    if (cmd_q == NULL)
    {

        return -ENODEV;
    }

    uint16_t cmd_id = le16toh(cmd->hdr.message_id);
    uint16_t vif_id = le16toh(cmd->hdr.vif_id);
    cmd_len = sizeof(*cmd) + le16toh(cmd->hdr.len);
    cmd->hdr.flags = htole16(MORSE_CMD_TYPE_REQ);
    printk("[MM_CMD] TX begin id=0x%04x(%s) vif=%u len=%d resp_max=%lu timeout=%lu\n",
           cmd_id, morse_cmd_id_name(cmd_id), vif_id, cmd_len,
           (unsigned long)resp_maxlen, (unsigned long)timeout);
    MMLOG_INF("MM_CMD TX begin id=0x%04x(%s) vif=%u len=%d resp_max=%lu timeout=%lu\n",
              cmd_id,
              morse_cmd_id_name(cmd_id),
              vif_id,
              cmd_len,
              (unsigned long)resp_maxlen,
              (unsigned long)timeout);

    if (!mmosal_mutex_get(driverd->cmd.wait, UINT32_MAX))
    {
        MMLOG_ERR("MM_CMD TX mutex_failed id=0x%04x(%s)\n",
                  cmd_id, morse_cmd_id_name(cmd_id));
        return -ESTALE;
    }


    if (!driverd->started)
    {
        mmosal_mutex_release(driverd->cmd.wait);
        MMLOG_ERR("MM_CMD TX not_started id=0x%04x(%s)\n",
                  cmd_id, morse_cmd_id_name(cmd_id));
        return -ESTALE;
    }

    mmhal_set_deep_sleep_veto(MORSELIB_VETO_COMMAND);

    driverd->cmd.seq++;
    if (driverd->cmd.seq > MORSE_CMD_IID_SEQ_MAX)
    {
        driverd->cmd.seq = 1;
    }
    cmd_seq = driverd->cmd.seq << MORSE_CMD_IID_SEQ_SHIFT;


    morse_ps_disable_async(driverd, PS_WAKER_COMMAND);

    do {
        cmd->hdr.host_id = htole16(cmd_seq | retry);
        printk("[MM_CMD] TX send id=0x%04x(%s) host=0x%04x vif=%u try=%d\n",
               cmd_id, morse_cmd_id_name(cmd_id), le16toh(cmd->hdr.host_id), vif_id, retry);
        MMLOG_INF("MM_CMD TX send id=0x%04x(%s) host=0x%04x vif=%u try=%d\n",
                  cmd_id,
                  morse_cmd_id_name(cmd_id),
                  le16toh(cmd->hdr.host_id),
                  vif_id,
                  retry);

        mmpkt = morse_skbq_alloc_mmpkt_for_cmd(cmd_len);
        if (!mmpkt)
        {
            ret = -ENOMEM;
            MMLOG_ERR("MM_CMD TX alloc_failed id=0x%04x(%s) len=%d\n",
                      cmd_id, morse_cmd_id_name(cmd_id), cmd_len);
            break;
        }

        view = mmpkt_open(mmpkt);
        mmpkt_append_data(view, (uint8_t *)cmd, cmd_len);
        mmpkt_close(&view);

        DRVCMD_TRACE("cmd hostid %x", le16toh(cmd->hdr.host_id));
        MMLOG_DBG("CMD 0x%04x:%04x\n", le16toh(cmd->hdr.message_id), le16toh(cmd->hdr.host_id));

        MMOSAL_DEV_ASSERT(driverd->cmd.rspview == NULL);

        MMOSAL_MUTEX_GET_INF(driverd->cmd.lock);
        timeout = timeout ? timeout : MM_CMD_TIMEOUT_DEFAULT;
        ret = morse_skbq_mmpkt_tx(cmd_q, mmpkt, MORSE_SKB_CHAN_COMMAND);
        if (ret == 0)
        {

            driverd->cmd.pending_cmd_id = le16toh(cmd->hdr.message_id);
            driverd->cmd.pending_cmd_host_id = le16toh(cmd->hdr.host_id);
        }
        MMOSAL_MUTEX_RELEASE(driverd->cmd.lock);

        if (ret != 0)
        {
            printk("[MM_CMD] TX queue_failed id=0x%04x(%s) host=0x%04x ret=%d\n",
                   cmd_id, morse_cmd_id_name(cmd_id), le16toh(cmd->hdr.host_id), ret);
            MMLOG_ERR("MM_CMD TX queue_failed id=0x%04x(%s) host=0x%04x ret=%d\n",
                      cmd_id,
                      morse_cmd_id_name(cmd_id),
                      le16toh(cmd->hdr.host_id),
                      ret);
            break;
        }

        DRVCMD_TRACE("cmd wait");
        mmosal_semb_wait(driverd->cmd.semb, timeout);
        MMOSAL_MUTEX_GET_INF(driverd->cmd.lock);


        if ((retry + 1) == MM_MAX_COMMAND_RETRY)
        {
            driverd->cmd.pending_cmd_id = 0;
            driverd->cmd.pending_cmd_host_id = 0;
        }

        struct mmpktview *rspview = driverd->cmd.rspview;
        driverd->cmd.rspview = NULL;
        MMOSAL_MUTEX_RELEASE(driverd->cmd.lock);

        if (rspview == NULL)
        {
            DRVCMD_TRACE("cmd t/o");
            printk("[MM_CMD] RX timeout id=0x%04x(%s) host=0x%04x try=%d timeout=%lu\n",
                   cmd_id, morse_cmd_id_name(cmd_id), le16toh(cmd->hdr.host_id), retry,
                   (unsigned long)timeout);
            MMLOG_INF("Try:%d Command %04x:%04x timeout after %lu ms\n",
                      retry,
                      le16toh(cmd->hdr.message_id),
                      le16toh(cmd->hdr.host_id),
                      timeout);
            MMLOG_ERR("MM_CMD RX timeout id=0x%04x(%s) host=0x%04x try=%d timeout=%lu\n",
                      cmd_id,
                      morse_cmd_id_name(cmd_id),
                      le16toh(cmd->hdr.host_id),
                      retry,
                      (unsigned long)timeout);
            ret = -ETIMEDOUT;
        }
        else
        {
            uint32_t rxrsp_pkt_len = mmpkt_get_data_length(rspview);
            if (rxrsp_pkt_len < sizeof(struct morse_cmd_resp))
            {
                MMLOG_WRN("Malformed response: %s\n", "too short");
                ret = -EBADMSG;
            }
            else
            {
                struct morse_cmd_resp *rxrsp =
                    (struct morse_cmd_resp *)mmpkt_get_data_start(rspview);
                int32_t fw_status = (int32_t)le32toh(rxrsp->status);


                MMOSAL_DEV_ASSERT(rxrsp->hdr.message_id == cmd->hdr.message_id);
                MMOSAL_DEV_ASSERT((rxrsp->hdr.host_id & MORSE_CMD_IID_SEQ_MASK) ==
                                  (cmd->hdr.host_id & MORSE_CMD_IID_SEQ_MASK));

                uint32_t rxrsp_len = le16toh(rxrsp->hdr.len) + sizeof(struct morse_cmd_header);
                if (rxrsp_len > rxrsp_pkt_len)
                {
                    MMLOG_WRN("Malformed response: %s\n", "overflow");
                    ret = -EBADMSG;
                }
                else if ((resp_maxlen >= sizeof(struct morse_cmd_resp)) && resp != NULL)
                {
                    ret = 0;
                    uint32_t copy_length = MM_MIN(rxrsp_len, resp_maxlen);
                    memcpy(resp, rxrsp, copy_length);
                    printk("[MM_CMD] RX resp_copy id=0x%04x(%s) host=0x%04x vif=%u fw_status=%ld rsp_len=%lu copy_len=%lu\n",
                           cmd_id, morse_cmd_id_name(cmd_id), le16toh(rxrsp->hdr.host_id),
                           le16toh(rxrsp->hdr.vif_id), (long)fw_status,
                           (unsigned long)rxrsp_len, (unsigned long)copy_length);
                    MMLOG_INF("MM_CMD RX resp_copy id=0x%04x(%s) host=0x%04x vif=%u fw_status=%ld rsp_len=%lu copy_len=%lu\n",
                              cmd_id,
                              morse_cmd_id_name(cmd_id),
                              le16toh(rxrsp->hdr.host_id),
                              le16toh(rxrsp->hdr.vif_id),
                              (long)fw_status,
                              (unsigned long)rxrsp_len,
                              (unsigned long)copy_length);
                }
                else
                {
                    ret = (int)le32toh(rxrsp->status);
                    printk("[MM_CMD] RX status id=0x%04x(%s) host=0x%04x vif=%u ret=%d rsp_len=%lu pkt_len=%lu\n",
                           cmd_id, morse_cmd_id_name(cmd_id), le16toh(rxrsp->hdr.host_id),
                           le16toh(rxrsp->hdr.vif_id), ret, (unsigned long)rxrsp_len,
                           (unsigned long)rxrsp_pkt_len);
                    MMLOG_INF("MM_CMD RX status id=0x%04x(%s) host=0x%04x vif=%u ret=%d rsp_len=%lu pkt_len=%lu\n",
                              cmd_id,
                              morse_cmd_id_name(cmd_id),
                              le16toh(rxrsp->hdr.host_id),
                              le16toh(rxrsp->hdr.vif_id),
                              ret,
                              (unsigned long)rxrsp_len,
                              (unsigned long)rxrsp_pkt_len);
                }
            }

            struct mmpkt *rsppkt = mmpkt_from_view(rspview);
            mmpkt_close(&rspview);
            mmpkt_release(rsppkt);

            DRVCMD_TRACE("cmd ret %d", ret);

            MMLOG_DBG("Command 0x%04x:%04x status %d (0x%08x)\n",
                      le16toh(cmd->hdr.message_id),
                      le16toh(cmd->hdr.host_id),
                      ret,
                      (unsigned)ret);
            if (ret)
            {
                MMLOG_WRN("Command 0x%04x:%04x error %d\n",
                          le16toh(cmd->hdr.message_id),
                          le16toh(cmd->hdr.host_id),
                          ret);
            }
        }

        spin_lock(&cmd_q->lock);
        morse_skbq_tx_finish(cmd_q, mmpkt, NULL);
        spin_unlock(&cmd_q->lock);

        retry++;

    } while ((ret == -ETIMEDOUT || ret == -EBADMSG) && retry < MM_MAX_COMMAND_RETRY);

    morse_ps_enable_async(driverd, PS_WAKER_COMMAND);
    mmhal_clear_deep_sleep_veto(MORSELIB_VETO_COMMAND);
    MMOSAL_MUTEX_RELEASE(driverd->cmd.wait);

    if (ret == -ETIMEDOUT)
    {
        MMLOG_ERR("Command %02x:%02x timed out\n",
                  le16toh(cmd->hdr.message_id),
                  le16toh(cmd->hdr.host_id));
    }
    else if (ret != 0)
    {

        if (!(ret == MORSE_RET_EPERM && le16toh(cmd->hdr.message_id) == MORSE_CMD_ID_SET_CHANNEL))
        {
            MMLOG_ERR("Command %02x:%02x failed with rc %d (0x%x)\n",
                      le16toh(cmd->hdr.message_id),
                      le16toh(cmd->hdr.host_id),
                      ret,
                      (unsigned)ret);
        }
    }
    DRVCMD_TRACE("cmd done %d", ret);
    printk("[MM_CMD] TX done id=0x%04x(%s) host=0x%04x ret=%d tries=%d\n",
           cmd_id, morse_cmd_id_name(cmd_id), le16toh(cmd->hdr.host_id), ret, retry);
    MMLOG_INF("MM_CMD TX done id=0x%04x(%s) host=0x%04x ret=%d tries=%d\n",
              cmd_id,
              morse_cmd_id_name(cmd_id),
              le16toh(cmd->hdr.host_id),
              ret,
              retry);

    return ret;
}

int morse_cmd_resp_process(struct driver_data *driverd, struct mmpkt *mmpkt, uint8_t channel)
{
    int ret = -ESRCH;
    struct mmpktview *view = mmpkt_open(mmpkt);
    struct morse_cmd_resp *src_resp = (struct morse_cmd_resp *)(mmpkt_get_data_start(view));
    uint16_t cmd_id;
    uint16_t cmd_host_id;
    uint16_t resp_id = le16toh(src_resp->hdr.message_id);
    uint16_t resp_host_id = le16toh(src_resp->hdr.host_id);
    bool notify = false;

    MM_UNUSED(driverd);
    MM_UNUSED(channel);

    MMLOG_DBG("EVT 0x%04x:0x%04x\n", resp_id, resp_host_id);
    DRVCMD_TRACE("cmd rsp %x:%x", resp_id, resp_host_id);
    MMLOG_INF("MM_CMD RX raw id=0x%04x(%s) host=0x%04x flags=0x%04x len=%u chan=%u\n",
              resp_id,
              morse_cmd_id_name(resp_id),
              resp_host_id,
              le16toh(src_resp->hdr.flags),
              le16toh(src_resp->hdr.len),
              channel);

    MMOSAL_MUTEX_GET_INF(driverd->cmd.lock);
    cmd_id = driverd->cmd.pending_cmd_id;
    cmd_host_id = driverd->cmd.pending_cmd_host_id;

    if (!MORSE_CMD_IS_RESP(src_resp))
    {
        MMLOG_INF("MM_CMD RX event id=0x%04x(%s) host=0x%04x pending=0x%04x:0x%04x\n",
                  resp_id,
                  morse_cmd_id_name(resp_id),
                  resp_host_id,
                  cmd_id,
                  cmd_host_id);
        ret = morse_mac_event_recv(driverd, view);
        goto exit;
    }


    if ((cmd_id == 0) ||
        (cmd_id != resp_id) ||
        ((cmd_host_id & MORSE_CMD_IID_SEQ_MASK) != (resp_host_id & MORSE_CMD_IID_SEQ_MASK)))
    {
        MMLOG_WRN("Late response for timed out cmd 0x%04x:%04x have 0x%04x:%04x 0x%04x\n",
                  resp_id,
                  resp_host_id,
                  cmd_id,
                  cmd_host_id,
                  driverd->cmd.seq);
        MMLOG_WRN("MM_CMD RX late_or_mismatch resp=0x%04x(%s):0x%04x pending=0x%04x:0x%04x seq=0x%04x\n",
                  resp_id,
                  morse_cmd_id_name(resp_id),
                  resp_host_id,
                  cmd_id,
                  cmd_host_id,
                  driverd->cmd.seq);
        goto exit;
    }
    if ((cmd_host_id & MORSE_CMD_IID_RETRY_MASK) != (resp_host_id & MORSE_CMD_IID_RETRY_MASK))
    {
        MMLOG_INF("Command retry mismatch 0x%04x:%04x 0x%04x:%04x\n",
                  cmd_id,
                  cmd_host_id,
                  resp_id,
                  resp_host_id);
    }

    MMOSAL_DEV_ASSERT(driverd->cmd.rspview == NULL);
    if (driverd->cmd.rspview != NULL)
    {

        struct mmpkt *old = mmpkt_from_view(driverd->cmd.rspview);
        mmpkt_close(&driverd->cmd.rspview);
        mmpkt_release(old);
    }
    driverd->cmd.rspview = view;
    view = NULL;
    mmpkt = NULL;

    driverd->cmd.pending_cmd_id = 0;
    driverd->cmd.pending_cmd_host_id = 0;
    notify = true;

exit:
    mmpkt_close(&view);
    mmpkt_release(mmpkt);

    MMOSAL_MUTEX_RELEASE(driverd->cmd.lock);
    if (notify)
    {
        mmosal_semb_give(driverd->cmd.semb);
    }

    return ret;
}

int morse_cmd_init(struct driver_data *driverd)
{
    DRVCMD_TRACE_INIT();

    driverd->cmd.lock = mmosal_mutex_create("cmd.lock");
    if (driverd->cmd.lock == NULL)
    {
        goto failure;
    }

    driverd->cmd.wait = mmosal_mutex_create("cmd.wait");
    if (driverd->cmd.wait == NULL)
    {
        goto failure;
    }

    driverd->cmd.semb = mmosal_semb_create("cmdrsp");
    if (driverd->cmd.semb == NULL)
    {
        goto failure;
    }

    return MORSE_SUCCESS;

failure:
    MMLOG_ERR("Mutex/semb creation failed\n");
    mmosal_mutex_delete(driverd->cmd.lock);
    driverd->cmd.lock = NULL;
    mmosal_mutex_delete(driverd->cmd.wait);
    driverd->cmd.wait = NULL;

    return -ENOMEM;
}

void morse_cmd_deinit(struct driver_data *driverd)
{
    if (driverd->cmd.lock == NULL)
    {
        return;
    }


    MMOSAL_MUTEX_GET_INF(driverd->cmd.lock);
    if (driverd->cmd.pending_cmd_id != 0)
    {
        driverd->cmd.pending_cmd_id = 0;
        driverd->cmd.pending_cmd_host_id = 0;
        mmosal_semb_give(driverd->cmd.semb);
    }
    MMOSAL_MUTEX_RELEASE(driverd->cmd.lock);


    MMOSAL_MUTEX_GET_INF(driverd->cmd.wait);
    MMOSAL_MUTEX_RELEASE(driverd->cmd.wait);

    if (driverd->cmd.rspview != NULL)
    {
        struct mmpkt *rsppkt = mmpkt_from_view(driverd->cmd.rspview);
        driverd->cmd.rspview = NULL;
        mmpkt_release(rsppkt);
    }

    mmosal_mutex_delete(driverd->cmd.wait);
    driverd->cmd.wait = NULL;
    mmosal_mutex_delete(driverd->cmd.lock);
    driverd->cmd.lock = NULL;
    if (driverd->cmd.semb != NULL)
    {
        mmosal_semb_delete(driverd->cmd.semb);
    }
}

int morse_cmd_health_check(struct driver_data *driverd)
{
    int ret;
    struct morse_cmd_req_health_check cmd =
        MORSE_COMMAND_INIT(cmd, MORSE_CMD_ID_HEALTH_CHECK, UNKNOWN_VIF_ID);

    ret = morse_cmd_tx(driverd, NULL, (struct morse_cmd_req *)&cmd, 0, MM_CMD_TIMEOUT_HEALTH_CHECK);

    return ret;
}
