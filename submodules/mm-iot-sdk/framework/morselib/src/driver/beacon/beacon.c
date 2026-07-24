/*
 * Copyright 2025 Morse Micro
 * SPDX-License-Identifier: GPL-3.0-or-later OR LicenseRef-MorseMicroCommercial
 */

#include "beacon.h"
#include "driver/driver.h"
#include "driver/morse_driver/hw.h"
#ifdef STRINGIFY
#undef STRINGIFY
#endif
#include <zephyr/sys/printk.h>

/* Firmware normally requests the next beacon through its beacon IRQ. Keep a
 * slightly-late software request armed as a watchdog so beaconing continues
 * when that IRQ is absent or intermittently lost. A real IRQ cancels the
 * scheduled request before it expires. */
#define BEACON_DEFAULT_INTERVAL_TU           (100U)
#define BEACON_REQUEST_WATCHDOG_MARGIN_MS    (10U)

static uint32_t morse_beacon_watchdog_ms(const struct driver_data *driverd)
{
    uint32_t interval_tu = driverd->beacon.interval_tu;

    if (interval_tu == 0U)
    {
        interval_tu = BEACON_DEFAULT_INTERVAL_TU;
    }

    /* One TU is 1024 us. Round up to milliseconds, then stay slightly behind
     * the firmware TBTT request so a real IRQ wins and cancels the watchdog. */
    return ((interval_tu * 1024U) + 999U) / 1000U + BEACON_REQUEST_WATCHDOG_MARGIN_MS;
}

void morse_beacon_irq_handle(struct driver_data *driverd, uint32_t status1_reg)
{
    static uint32_t irq_count;
    uint8_t beacon_irq_num = MORSE_INT_BEACON_BASE_NUM + driverd->beacon.vif_id;

    if (status1_reg & 1ul << beacon_irq_num)
    {
        irq_count++;
        printk("[MM_BCN] irq count=%lu status1=0x%08lx irq=%u vif=%u enabled=%u\n",
               (unsigned long)irq_count,
               (unsigned long)status1_reg,
               (unsigned)beacon_irq_num,
               (unsigned)driverd->beacon.vif_id,
               driverd->beacon.enabled ? 1U : 0U);
        driver_task_notify_event_from_isr(driverd, DRV_EVT_BEACON_REQ_PEND);
    }
}

static int morse_beacon_set_irq_enabled(struct driver_data *driverd, bool enabled)
{
    uint8_t beacon_irq_num = MORSE_INT_BEACON_BASE_NUM + driverd->beacon.vif_id;

    int ret = morse_hw_irq_enable(driverd, beacon_irq_num, enabled);
    printk("[MM_BCN] irq_config enabled=%u irq=%u mask=0x%08lx ret=%d\n",
           enabled ? 1U : 0U,
           (unsigned)beacon_irq_num,
           (unsigned long)(1ul << beacon_irq_num),
           ret);
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
        bool log_sample = (driverd->beacon.count == 0U) ||
                          ((driverd->beacon.count % 600U) == 0U);
        if (log_sample)
        {
            printk("[MM_BCN] work event enabled=%u vif=%u count=%lu pending=0x%08lx\n",
                   driverd->beacon.enabled ? 1U : 0U,
                   (unsigned)driverd->beacon.vif_id,
                   (unsigned long)driverd->beacon.count,
                   (unsigned long)driverd->driver_task.pending_evts);
        }
        if (!driverd->beacon.enabled)
        {
            return 0;
        }

        struct mmpkt *beacon = mmdrv_host_get_beacon();
        if (beacon == NULL)
        {
            printk("[MM_BCN] get_beacon failed NULL vif=%u interval_tu=%u; disabling\n",
                   (unsigned)driverd->beacon.vif_id,
                   (unsigned)driverd->beacon.interval_tu);
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
            printk("[MM_BCN] beacon_queue missing vif=%u cfg=%p ops=%p\n",
                   (unsigned)driverd->beacon.vif_id,
                   driverd->cfg,
                   driverd->cfg ? driverd->cfg->ops : NULL);
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
        if (ret != 0 || log_sample)
        {
            printk("[MM_BCN] enqueue ret=%d vif=%u beacon=%p len=%lu queue=%p\n",
                   ret,
                   (unsigned)driverd->beacon.vif_id,
                   beacon,
                   (unsigned long)mmpkt_peek_data_length(beacon),
                   mq);
        }
        if (ret == 0)
        {
            driverd->beacon.count++;
        }
        /* Retry after transient queue pressure as well as successful TX. */
        driver_task_schedule_notification(driverd, DRV_EVT_BEACON_REQ_PEND,
                                          morse_beacon_watchdog_ms(driverd));
        return ret;
    }

    return 0;
}

int morse_beacon_start(struct driver_data *driverd, uint16_t vif_id)
{
    MMLOG_INF("Start beaconing\n");
    printk("[MM_BCN] start vif=%u old_enabled=%u old_vif=%u interval_tu=%u "
           "task_running=%u task=%p pending=0x%08lx\n",
           (unsigned)vif_id,
           driverd->beacon.enabled ? 1U : 0U,
           (unsigned)driverd->beacon.vif_id,
           (unsigned)driverd->beacon.interval_tu,
           driverd->driver_task.task_running ? 1U : 0U,
           driverd->driver_task.task,
           (unsigned long)driverd->driver_task.pending_evts);
    driverd->beacon.count = 0;
    driverd->beacon.enabled = true;
    driverd->beacon.vif_id = vif_id;
    driverd->beacon.beacon_work_fn = morse_beacon_work_;
    driver_task_notify_event(driverd, DRV_EVT_BEACON_REQ_PEND);
    /* Arm the initial watchdog as well as the immediate first request. */
    driver_task_schedule_notification(driverd, DRV_EVT_BEACON_REQ_PEND,
                                      morse_beacon_watchdog_ms(driverd));
    printk("[MM_BCN] request_watchdog period_ms=%lu interval_tu=%u vif=%u "
           "pending=0x%08lx\n",
           (unsigned long)morse_beacon_watchdog_ms(driverd),
           (unsigned)driverd->beacon.interval_tu,
           (unsigned)vif_id,
           (unsigned long)driverd->driver_task.pending_evts);

    int ret = morse_beacon_set_irq_enabled(driverd, true);
    printk("[MM_BCN] start_complete irq_enable_ret=%d vif=%u\n",
           ret, (unsigned)vif_id);
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
