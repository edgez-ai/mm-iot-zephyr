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
#define MORSE_SPI_TRACE_MAX 96
#define MORSE_USER_NODE DT_PATH(zephyr_user)

#if DT_NODE_HAS_PROP(MORSE_USER_NODE, halow_power_en_gpios)
static const struct gpio_dt_spec morse_power_diag =
	GPIO_DT_SPEC_GET(MORSE_USER_NODE, halow_power_en_gpios);
#endif

static mmhal_irq_handler_t spi_irq_handler = NULL;
static mmhal_irq_handler_t busy_irq_handler = NULL;
static uint8_t spi_trace_tx[MORSE_SPI_TRACE_MAX];
static uint8_t spi_trace_rx[MORSE_SPI_TRACE_MAX];
static size_t spi_trace_len;
static uint32_t spi_rw_count;
static uint32_t spi_read_bytes;
static uint32_t spi_write_bytes;
static uint32_t spi_error_count;
static int spi_training_rc;
static int spi_release_rc;
static const uint8_t spi_ones[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
					   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

static void morse_log_gpio_state(const char *stage)
{
	const struct morse_config *cfg = morse_config0;
#if DT_NODE_HAS_PROP(MORSE_USER_NODE, halow_power_en_gpios)
	int power_logical = gpio_pin_get_dt(&morse_power_diag);
	int power_raw = gpio_pin_get_raw(morse_power_diag.port, morse_power_diag.pin);
#else
	int power_logical = -ENODEV;
	int power_raw = -ENODEV;
#endif

	LOG_INF("MM8108 GPIO stage=%s power_logical=%d power_raw=%d reset_logical=%d reset_raw=%d wake_logical=%d wake_raw=%d busy_logical=%d busy_raw=%d irq_logical=%d irq_raw=%d",
		stage, power_logical, power_raw,
		gpio_pin_get_dt(&cfg->resetn),
		gpio_pin_get_raw(cfg->resetn.port, cfg->resetn.pin),
		gpio_pin_get_dt(&cfg->wakeup),
		gpio_pin_get_raw(cfg->wakeup.port, cfg->wakeup.pin),
		gpio_pin_get_dt(&cfg->busy),
		gpio_pin_get_raw(cfg->busy.port, cfg->busy.pin),
		gpio_pin_get_dt(&cfg->spi_irq),
		gpio_pin_get_raw(cfg->spi_irq.port, cfg->spi_irq.pin));
}

void mmhal_wlan_diag_dump(void)
{
	morse_log_gpio_state("boot_failed");
	LOG_ERR("MM8108 SPI diag training_rc=%d release_rc=%d rw_calls=%u read_bytes=%u write_bytes=%u errors=%u trace_len=%u",
		spi_training_rc, spi_release_rc, spi_rw_count, spi_read_bytes,
		spi_write_bytes, spi_error_count,
		(unsigned)spi_trace_len);
	if (spi_trace_len > 0U) {
		LOG_HEXDUMP_ERR(spi_trace_tx, spi_trace_len, "MM8108 SPI first TX bytes");
		LOG_HEXDUMP_ERR(spi_trace_rx, spi_trace_len, "MM8108 SPI first RX bytes");
	}
}

void mmhal_wlan_hard_reset(void)
{
	const struct morse_config *cfg = morse_config0;
	const struct gpio_dt_spec *gpio_dt = &cfg->resetn;
	int ret = 0;

	spi_trace_len = 0;
	spi_rw_count = 0;
	spi_read_bytes = 0;
	spi_write_bytes = 0;
	spi_error_count = 0;
	spi_training_rc = -EINPROGRESS;
	spi_release_rc = -EINPROGRESS;
	morse_log_gpio_state("before_hard_reset");

	if ((ret = gpio_pin_set_dt(gpio_dt, 1)) < 0) {
		LOG_ERR("Unhandled exception %d in %s\n", ret, __func__);
	}
	morse_log_gpio_state("reset_asserted");
	mmosal_task_sleep(5);
	if ((ret = gpio_pin_set_dt(gpio_dt, 0)) < 0) {
		LOG_ERR("Unhandled exception %d in %s\n", ret, __func__);
	}
	morse_log_gpio_state("reset_released");
	mmosal_task_sleep(20);
	morse_log_gpio_state("reset_settled_20ms");
}

#if defined(CONFIG_WIFI_MORSE_EXT_XTAL_INIT) && CONFIG_WIFI_MORSE_EXT_XTAL_INIT
bool mmhal_wlan_ext_xtal_init_is_required(void)
{
	return true;
}
#endif

void mmhal_wlan_spi_cs_assert(void)
{
}

void mmhal_wlan_spi_cs_deassert(void)
{
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
		spi_error_count++;
	}
	spi_rw_count++;
	if (spi_trace_len < MORSE_SPI_TRACE_MAX) {
		spi_trace_tx[spi_trace_len] = data;
		spi_trace_rx[spi_trace_len] = read_val;
		spi_trace_len++;
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
		spi_error_count++;
	}
	spi_read_bytes += len;
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
		spi_error_count++;
	}
	spi_write_bytes += len;
}

void mmhal_wlan_send_training_seq(void)
{
	const struct morse_config *cfg = morse_config0;
	const struct device *spi = cfg->spi.bus;
	struct gpio_dt_spec cs_gpio = cfg->spi.config.cs.gpio;
	struct spi_config spi_cfg = cfg->spi.config;
	gpio_flags_t flags = GPIO_OUTPUT_INACTIVE;
	int ret = 0;

	struct spi_buf tx_bufs = {.buf = (uint8_t *)spi_ones, .len = sizeof(spi_ones)};

	const struct spi_buf_set tx = {
		.buffers = &tx_bufs,
		.count = 1,
	};

	ret = gpio_pin_get_config_dt(&cs_gpio, &flags);
	if (ret == -ENOSYS) {
		LOG_DBG("Platform does not implement gpio_pin_get_config(), using default flags\n");
	} else if (ret < 0) {
		LOG_ERR("Unhandled error %d in gpio_pin_get_config_dt()\n", ret);
		return;
	}

	ret = gpio_pin_configure(cs_gpio.port, cs_gpio.pin, flags & ~(GPIO_ACTIVE_LOW));
	if (ret != 0) {
		LOG_ERR("Unhandled error %d in gpio_pin_configure()\n", ret);
		return;
	}

	ret = spi_transceive(spi, &spi_cfg, &tx, NULL);
	spi_training_rc = ret;
	if (ret != 0) {
		LOG_ERR("Unhandled error %d in spi_transceive()\n", ret);
		spi_error_count++;
		return;
	}
	/* Release lock on SPI bus */
	ret = spi_release(spi, &spi_cfg);
	spi_release_rc = ret;
	if (ret != 0) {
		LOG_ERR("MM8108 SPI training release failed rc=%d", ret);
		spi_error_count++;
	}

	ret = gpio_pin_configure(cs_gpio.port, cs_gpio.pin, flags | GPIO_ACTIVE_LOW);
	if (ret != 0) {
		LOG_ERR("Unhandled error %d in gpio_pin_configure()\n", ret);
		return;
	}
	LOG_INF("MM8108 SPI training completed transaction_rc=%d release_rc=%d bytes=%u frequency=%u",
		spi_training_rc, spi_release_rc, (unsigned)sizeof(spi_ones),
		spi_cfg.frequency);
}

void mmhal_wlan_register_spi_irq_handler(mmhal_irq_handler_t handler)
{
	spi_irq_handler = handler;
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

	if (enabled) {
		/* The transiver will hold the IRQ line low if there is additional information
		 * to be retrived. Ideally the interrupt pin would be configured as a low level
		 * interrupt.
		 */
		if (mmhal_wlan_spi_irq_is_asserted()) {
			if (spi_irq_handler != NULL) {
				spi_irq_handler();
			}
		}
		gpio_pin_interrupt_configure_dt(&cfg->spi_irq, GPIO_INT_EDGE_TO_ACTIVE);
	} else {
		gpio_pin_interrupt_configure_dt(&cfg->spi_irq, GPIO_INT_DISABLE);
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
	if (spi_irq_handler != NULL) {
		spi_irq_handler();
	}
}
