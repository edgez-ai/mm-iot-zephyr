/*
 * Copyright 2024 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "mmhal.h"
#include "mmosal.h"

#include "morse.h"

#include "morse_log.h"
LOG_MODULE_DECLARE(LOG_MODULE_NAME);

/** 10x8bit training seq */
#define BYTE_TRAIN 16

static mmhal_irq_handler_t spi_irq_handler = NULL;
static mmhal_irq_handler_t busy_irq_handler = NULL;
static volatile uint32_t spi_irq_callback_count;
static uint32_t spi_irq_enable_count;
static uint32_t spi_irq_pending_recovery_count;
static const uint8_t spi_ones[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
					   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

void mmhal_wlan_hard_reset(void)
{
	const struct morse_config *cfg = morse_config0;
	const struct gpio_dt_spec *gpio_dt = &cfg->resetn;
	int ret = 0;

	if ((ret = gpio_pin_set_dt(gpio_dt, 1)) < 0) {
		LOG_ERR("Unhandled exception %d in %s\n", ret, __func__);
	}
	mmosal_task_sleep(5);
	if ((ret = gpio_pin_set_dt(gpio_dt, 0)) < 0) {
		LOG_ERR("Unhandled exception %d in %s\n", ret, __func__);
	}
	mmosal_task_sleep(20);
}

#if defined(CONFIG_WIFI_MORSE_EXT_XTAL_INIT) && CONFIG_WIFI_MORSE_EXT_XTAL_INIT
bool mmhal_wlan_ext_xtal_init_is_required(void)
{
	return true;
}
#endif

void mmhal_wlan_spi_cs_assert(void)
{
	/* Zephyr asserts CS on the first transfer. SPI_HOLD_ON_CS keeps it
	 * asserted across all transfers in the Morse SDIO transaction.
	 */
}

void mmhal_wlan_spi_cs_deassert(void)
{
	const struct morse_config *cfg = morse_config0;
	int ret;

	/* End the transaction and release both CS and the SPI bus lock. */
	ret = spi_release(cfg->spi.bus, &cfg->spi.config);
	if (ret < 0) {
		LOG_ERR("Unhandled error %d in spi_release()\n", ret);
	}
}

uint8_t mmhal_wlan_spi_rw(uint8_t data)
{
	const struct morse_config *cfg = morse_config0;
	const struct device *spi = cfg->spi.bus;
	const struct spi_config *spi_cfg = &cfg->spi.config;
	int ret = 0;
	uint8_t read_val = 0;

	struct spi_buf tx_bufs[] = {{.buf = &data, .len = 1}};

	const struct spi_buf_set tx = {
		.buffers = tx_bufs,
		.count = 1,
	};

	struct spi_buf rx_bufs[] = {{.buf = &read_val, .len = 1}};

	const struct spi_buf_set rx = {
		.buffers = rx_bufs,
		.count = 1,
	};
	if ((ret = spi_transceive(spi, spi_cfg, &tx, &rx)) < 0) {
		LOG_ERR("Unhandled error %d in spi_tranceive\n", ret);
	}
	return read_val;
}

void mmhal_wlan_spi_read_buf(uint8_t *buf, unsigned len)
{
	const struct morse_config *cfg = morse_config0;
	const struct device *spi = cfg->spi.bus;
	const struct spi_config *spi_cfg = &cfg->spi.config;
	int ret = 0;

	struct spi_buf rx_bufs[] = {{.buf = buf, .len = len}};

	const struct spi_buf_set rx = {
		.buffers = rx_bufs,
		.count = 1,
	};
	if ((ret = spi_read(spi, spi_cfg, &rx)) < 0) {
		LOG_ERR("Unhandled error %d in spi_read()\n", ret);
	}
}

void mmhal_wlan_spi_write_buf(const uint8_t *buf, unsigned len)
{
	const struct morse_config *cfg = morse_config0;
	const struct device *spi = cfg->spi.bus;
	const struct spi_config *spi_cfg = &cfg->spi.config;
	int ret = 0;
	uint8_t *tx_buf_cast = (uint8_t *)buf;

	struct spi_buf tx_bufs[] = {{.buf = tx_buf_cast, .len = len}};

	const struct spi_buf_set tx = {
		.buffers = tx_bufs,
		.count = 1,
	};
	if ((ret = spi_write(spi, spi_cfg, &tx)) < 0) {
		LOG_ERR("Unhandled error %d in spi_write()\n", ret);
	}
}

void mmhal_wlan_send_training_seq(void)
{
	const struct morse_config *cfg = morse_config0;
	const struct device *spi = cfg->spi.bus;
	struct gpio_dt_spec cs_gpio = cfg->spi.config.cs.gpio;
	struct spi_config spi_cfg = cfg->spi.config;
	int ret = 0;

	struct spi_buf tx_bufs = {.buf = (uint8_t *)spi_ones, .len = sizeof(spi_ones)};

	const struct spi_buf_set tx = {
		.buffers = &tx_bufs,
		.count = 1,
	};

	/* The training clocks must be sent with CS physically inactive. Disable
	 * automatic CS for this transfer and drive the active-low CS high.
	 */
	spi_cfg.operation &= ~(SPI_LOCK_ON | SPI_HOLD_ON_CS);
	spi_cfg.cs.gpio.port = NULL;
	ret = gpio_pin_configure_dt(&cs_gpio, GPIO_OUTPUT_INACTIVE);
	if (ret != 0) {
		LOG_ERR("Unhandled error %d configuring inactive CS\n", ret);
		return;
	}

	ret = spi_transceive(spi, &spi_cfg, &tx, NULL);
	if (ret != 0) {
		LOG_ERR("Unhandled error %d in spi_transceive()\n", ret);
		return;
	}
}

void mmhal_wlan_register_spi_irq_handler(mmhal_irq_handler_t handler)
{
	spi_irq_handler = handler;
	LOG_INF("RF_RX IRQ handler=%p pin=%s.%u active_low=%u",
		(void *)handler, morse_config0->spi_irq.port->name, morse_config0->spi_irq.pin,
		(morse_config0->spi_irq.dt_flags & GPIO_ACTIVE_LOW) != 0U);
}

bool mmhal_wlan_spi_irq_is_asserted(void)
{
	const struct morse_config *cfg = morse_config0;
	const struct gpio_dt_spec *gpio_dt = &cfg->spi_irq;
	int ret = 0;
	if ((ret = gpio_pin_get_dt(gpio_dt)) < 0) {
		LOG_ERR("Unhandled exception %d in %s\n", ret, __func__);
		return false;
	}
	return !!ret;
}

void mmhal_wlan_set_spi_irq_enabled(bool enabled)
{
	const struct morse_config *cfg = morse_config0;
	int ret;

	if (enabled) {
		/* The transceiver holds IRQ low until all pending information is retrieved.
		 * Use the same active-low level-triggered behavior as the ESP32 HAL.
		 *
		 * Arm the interrupt before sampling the line. Sampling first leaves a race in
		 * which the MM6108 can assert IRQ while the GPIO interrupt is disabled;
		 * the sample also provides a fallback for GPIO drivers that defer delivery.
		 */
		ret = gpio_pin_interrupt_configure_dt(&cfg->spi_irq, GPIO_INT_LEVEL_ACTIVE);
		if (ret < 0) {
			LOG_ERR("RF_RX IRQ enable failed ret=%d", ret);
			return;
		}

		spi_irq_enable_count++;
		if (mmhal_wlan_spi_irq_is_asserted()) {
			spi_irq_pending_recovery_count++;
			if (spi_irq_pending_recovery_count <= 16U ||
			    (spi_irq_pending_recovery_count % 64U) == 0U) {
				LOG_INF("RF_RX IRQ pending-after-enable recovery=%lu gpio_callbacks=%lu enables=%lu raw_level=%d",
					(unsigned long)spi_irq_pending_recovery_count,
					(unsigned long)spi_irq_callback_count,
					(unsigned long)spi_irq_enable_count,
					gpio_pin_get(cfg->spi_irq.port, cfg->spi_irq.pin));
			}
			if (spi_irq_handler != NULL) {
				spi_irq_handler();
			}
		} else if ((spi_irq_enable_count % 64U) == 0U) {
			LOG_INF("RF_RX IRQ idle enables=%lu gpio_callbacks=%lu recoveries=%lu raw_level=%d",
				(unsigned long)spi_irq_enable_count,
				(unsigned long)spi_irq_callback_count,
				(unsigned long)spi_irq_pending_recovery_count,
				gpio_pin_get(cfg->spi_irq.port, cfg->spi_irq.pin));
		}
	} else {
		ret = gpio_pin_interrupt_configure_dt(&cfg->spi_irq, GPIO_INT_DISABLE);
		if (ret < 0) {
			LOG_ERR("RF_RX IRQ disable failed ret=%d", ret);
		}
	}
}

void mmhal_wlan_init(void)
{
	const struct morse_config *cfg = morse_config0;
	const struct gpio_dt_spec *gpio_dt = &cfg->resetn;
	int ret = 0;
	if ((ret = gpio_pin_set_dt(gpio_dt, 1)) < 0) {
		LOG_ERR("Unhandled exception %d in %s\n", ret, __func__);
	}
}

void mmhal_wlan_deinit(void)
{
	const struct morse_config *cfg = morse_config0;
	const struct gpio_dt_spec *gpio_dt = &cfg->resetn;
	int ret = 0;
	if ((ret = gpio_pin_set_dt(gpio_dt, 0)) < 0) {
		LOG_ERR("Unhandled exception %d in %s\n", ret, __func__);
	}
}

void mmhal_wlan_wake_assert(void)
{
	const struct morse_config *cfg = morse_config0;
	const struct gpio_dt_spec *gpio_dt = &cfg->wakeup;
	int ret = 0;
	if ((ret = gpio_pin_set_dt(gpio_dt, 1)) < 0) {
		LOG_ERR("Unhandled exception %d in %s\n", ret, __func__);
	}
}

void mmhal_wlan_wake_deassert(void)
{
	const struct morse_config *cfg = morse_config0;
	const struct gpio_dt_spec *gpio_dt = &cfg->wakeup;
	int ret = 0;
	if ((ret = gpio_pin_set_dt(gpio_dt, 0)) < 0) {
		LOG_ERR("Unhandled exception %d in %s\n", ret, __func__);
	}
}

bool mmhal_wlan_busy_is_asserted(void)
{
	const struct morse_config *cfg = morse_config0;
	const struct gpio_dt_spec *gpio_dt = &cfg->busy;
	int ret = 0;
	if ((ret = gpio_pin_get_dt(gpio_dt)) < 0) {
		LOG_ERR("Unhandled exception %d in %s\n", ret, __func__);
		return false;
	}
	return !!ret;
}

void mmhal_wlan_register_busy_irq_handler(mmhal_irq_handler_t handler)
{
	busy_irq_handler = handler;
}

void mmhal_wlan_set_busy_irq_enabled(bool enabled)
{
	const struct morse_config *cfg = morse_config0;

	if (enabled) {
		gpio_pin_interrupt_configure_dt(&cfg->busy, GPIO_INT_EDGE_TO_ACTIVE);
	} else {
		gpio_pin_interrupt_configure_dt(&cfg->busy, GPIO_INT_DISABLE);
	}
}

/**
 * @brief This function handles BUSY interrupt.
 */
void morse_busy_cb(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
	if (busy_irq_handler != NULL) {
		busy_irq_handler();
	}
}

/**
 * @brief This function handles SPI IRQ interrupts.
 */
void morse_spi_irq_cb(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
	spi_irq_callback_count++;
	if (spi_irq_handler != NULL) {
		spi_irq_handler();
	}
}
