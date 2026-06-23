/*
 * Copyright 2025 Morse Micro
 * SPDX-License-Identifier: GPL-3.0-or-later OR LicenseRef-MorseMicroCommercial
 */

#include "beacon.h"
#include "driver/driver.h"
#include "driver/morse_driver/hw.h"

void morse_beacon_irq_handle(struct driver_data *driverd, uint32_t status1_reg)
{
    uint8_t beacon_irq_num = MORSE_INT_BEACON_BASE_NUM + driverd->beacon.vif_id;

    if (status1_reg & 1ul << beacon_irq_num)
    {
        driver_task_notify_event_from_isr(driverd, DRV_EVT_BEACON_REQ_PEND);
    }
}

static int morse_beacon_set_irq_enabled(struct driver_data *driverd, bool enabled)
{
    uint8_t beacon_irq_num = MORSE_INT_BEACON_BASE_NUM + driverd->beacon.vif_id;

    int ret = morse_hw_irq_enable(driverd, beacon_irq_num, enabled);
    if (ret == 0)
    {
        MMLOG_DBG("Beacon IRQ %s (mask=0x%08lx)\n",
                  enabled ? "enabled" : "disabled",
                  1ul << beacon_irq_num);
    }
    else
    {
        MMLOG_ERR("Failed to %s beacon IRQ (%d)\n", enabled ? "enable" : "disable", ret);
    }
    return ret;
}

static int morse_beacon_work_(struct driver_data *driverd)
{
    if (driver_task_notification_check_and_clear(driverd, DRV_EVT_BEACON_REQ_PEND))
    {
        printf("[MM_BCN] work event enabled=%u vif=%u count=%lu\n",
               driverd->beacon.enabled ? 1U : 0U,
               (unsigned)driverd->beacon.vif_id,
               (unsigned long)driverd->beacon.count);
        if (!driverd->beacon.enabled)
        {
            return 0;
        }

        struct mmpkt *beacon = mmdrv_host_get_beacon();
        if (beacon == NULL)
        {
            printf("[MM_BCN] get_beacon failed NULL vif=%u; disabling beaconing to avoid repeated firmware requests\n",
                   (unsigned)driverd->beacon.vif_id);
            (void)morse_beacon_set_irq_enabled(driverd, false);
            driverd->beacon.enabled = false;
            driverd->beacon.vif_id = UINT16_MAX;
            MMLOG_WRN("Failed to get beacon\n");
            return 0;
        }

        struct morse_skbq *mq = driverd->cfg->ops->skbq_bcn_tc_q(driverd);
        if (!mq)
        {
            static bool error_message_displayed = false;
            printf("[MM_BCN] beacon_queue missing vif=%u\n",
                   (unsigned)driverd->beacon.vif_id);
            (void)morse_beacon_set_irq_enabled(driverd, false);
            driverd->beacon.enabled = false;
            driverd->beacon.vif_id = UINT16_MAX;
            if (!error_message_displayed)
            {
                MMLOG_ERR("Failed to find beacon mq\n");
                error_message_displayed = true;
            }

            return 0;
        }

        int ret = morse_skbq_mmpkt_tx(mq, beacon, MORSE_SKB_CHAN_BEACON);
        printf("[MM_BCN] enqueue ret=%d vif=%u\n",
               ret, (unsigned)driverd->beacon.vif_id);
        if (ret == 0)
        {
            driverd->beacon.count++;
        }
        return ret;
    }

    return 0;
}

int morse_beacon_start(struct driver_data *driverd, uint16_t vif_id)
{
    MMLOG_INF("Start beaconing\n");
    printf("[MM_BCN] start vif=%u old_enabled=%u old_vif=%u\n",
           (unsigned)vif_id,
           driverd->beacon.enabled ? 1U : 0U,
           (unsigned)driverd->beacon.vif_id);
    driverd->beacon.count = 0;
    driverd->beacon.enabled = true;
    driverd->beacon.vif_id = vif_id;
    driverd->beacon.beacon_work_fn = morse_beacon_work_;
    driver_task_notify_event(driverd, DRV_EVT_BEACON_REQ_PEND);

    int ret = morse_beacon_set_irq_enabled(driverd, true);
    printf("[MM_BCN] irq_enable ret=%d vif=%u\n", ret, (unsigned)vif_id);
    if (ret != 0)
    {
        MMLOG_WRN("Failed to start beaconing\n");
    }

    return ret;
}

int morse_beacon_stop(struct driver_data *driverd)
{
    int ret = 0;
    MMLOG_INF("Stop beaconing\n");
    if (driverd->beacon.enabled && driverd->beacon.vif_id != UINT16_MAX)
    {
        ret = morse_beacon_set_irq_enabled(driverd, false);
    }
    driverd->beacon.enabled = false;
    driverd->beacon.vif_id = UINT16_MAX;

    if (ret != 0)
    {
        MMLOG_WRN("Failed to stop beaconing\n");
    }

    return ret;
}

int morse_beacon_work(struct driver_data *driverd)
{

    if (driverd->beacon.beacon_work_fn != NULL)
    {
        return driverd->beacon.beacon_work_fn(driverd);
    }
    return -MM_EINVAL;
}
