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
#define MORSE_SPI_EVENT_MAX 48
#define MORSE_SPI_EVENTS_PER_TRANSACTION 12
#define MORSE_USER_NODE DT_PATH(zephyr_user)

#if CONFIG_DT_HAS_MORSE_MM8108_ENABLED
#define MORSE_DT_NODE DT_COMPAT_GET_ANY_STATUS_OKAY(morse_mm8108)
#else
#define MORSE_DT_NODE DT_COMPAT_GET_ANY_STATUS_OKAY(morse_mm6108)
#endif

#define MORSE_SPI_BUS_NODE DT_BUS(MORSE_DT_NODE)
#define MORSE_SPI_PINCTRL_NODE DT_PHANDLE(MORSE_SPI_BUS_NODE, pinctrl_0)
#define MORSE_SPI_PIN_GROUP DT_CHILD(MORSE_SPI_PINCTRL_NODE, group1)

#if DT_NODE_HAS_COMPAT(MORSE_SPI_BUS_NODE, nordic_nrf_spim) && \
	DT_NODE_EXISTS(MORSE_SPI_PIN_GROUP)
#include <hal/nrf_gpio.h>
#include <zephyr/dt-bindings/pinctrl/nrf-pinctrl.h>
#define MORSE_NRF_SPI_DIAG 1
#else
#define MORSE_NRF_SPI_DIAG 0
#endif

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
static uint32_t spi_transaction_count;
static uint32_t spi_release_count;
static uint16_t spi_transaction_event_count;
static int spi_training_rc;
static int spi_release_rc;
static const uint8_t spi_ones[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
					   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

enum morse_spi_event_op {
	MORSE_SPI_EVENT_RW,
	MORSE_SPI_EVENT_READ,
	MORSE_SPI_EVENT_WRITE,
	MORSE_SPI_EVENT_RELEASE,
	MORSE_SPI_EVENT_TRAIN,
};

struct morse_spi_event {
	uint32_t cycle;
	uint16_t transaction;
	uint16_t len;
	int16_t rc;
	uint8_t op;
	uint8_t tx_first;
	uint8_t rx_first;
	int8_t cs_raw;
	int8_t busy_raw;
	int8_t irq_raw;
	int8_t sck_raw;
};

static struct morse_spi_event spi_events[MORSE_SPI_EVENT_MAX];
static size_t spi_event_count;

#if MORSE_NRF_SPI_DIAG
static const uint32_t morse_spi_psels[] = DT_PROP(MORSE_SPI_PIN_GROUP, psels);

static int morse_spi_sck_raw(void)
{
	for (size_t i = 0; i < ARRAY_SIZE(morse_spi_psels); i++) {
		uint32_t psel = morse_spi_psels[i];
		uint32_t function = (psel >> NRF_FUN_POS) & NRF_FUN_MSK;

		if (function == NRF_FUN_SPIM_SCK) {
			return nrf_gpio_pin_read((psel >> NRF_PIN_POS) & NRF_PIN_MSK);
		}
	}

	return -ENOENT;
}

static void morse_log_spi_pin_state(const char *stage)
{
	for (size_t i = 0; i < ARRAY_SIZE(morse_spi_psels); i++) {
		uint32_t psel = morse_spi_psels[i];
		uint32_t function = (psel >> NRF_FUN_POS) & NRF_FUN_MSK;
		uint32_t pin_number = (psel >> NRF_PIN_POS) & NRF_PIN_MSK;
		const char *name = function == NRF_FUN_SPIM_SCK ? "SCK" :
			function == NRF_FUN_SPIM_MOSI ? "MOSI" :
			function == NRF_FUN_SPIM_MISO ? "MISO" : "unknown";

		LOG_INF("MM8108 SPI pin stage=%s signal=%s psel=0x%08x P%u.%02u raw=%u out=%u dir=%u input=%u pull=%u drive=%u",
			stage, name, psel, pin_number / 32U, pin_number % 32U,
			nrf_gpio_pin_read(pin_number), nrf_gpio_pin_out_read(pin_number),
			nrf_gpio_pin_dir_get(pin_number), nrf_gpio_pin_input_get(pin_number),
			nrf_gpio_pin_pull_get(pin_number), nrf_gpio_pin_drive_get(pin_number));
	}
}
#else
static int morse_spi_sck_raw(void)
{
	return -ENOTSUP;
}

static void morse_log_spi_pin_state(const char *stage)
{
	ARG_UNUSED(stage);
}
#endif

static void morse_trace_spi_event(enum morse_spi_event_op op, unsigned len, int rc,
				  uint8_t tx_first, uint8_t rx_first)
{
	const struct morse_config *cfg = morse_config0;
	struct morse_spi_event *event;

	/* A missing MM8108 can cause hundreds of identical 0xff polling bytes.
	 * Keep the start and release of several transactions instead of filling the
	 * entire diagnostic buffer with the first poll loop.
	 */
	if (op != MORSE_SPI_EVENT_RELEASE && op != MORSE_SPI_EVENT_TRAIN &&
	    spi_transaction_event_count >= MORSE_SPI_EVENTS_PER_TRANSACTION) {
		return;
	}

	if (spi_event_count >= ARRAY_SIZE(spi_events)) {
		return;
	}

	event = &spi_events[spi_event_count++];
	event->cycle = k_cycle_get_32();
	event->transaction = spi_transaction_count;
	event->len = MIN(len, UINT16_MAX);
	event->rc = CLAMP(rc, INT16_MIN, INT16_MAX);
	event->op = op;
	event->tx_first = tx_first;
	event->rx_first = rx_first;
	event->cs_raw = gpio_pin_get_raw(cfg->spi.config.cs.gpio.port,
					 cfg->spi.config.cs.gpio.pin);
	event->busy_raw = gpio_pin_get_raw(cfg->busy.port, cfg->busy.pin);
	event->irq_raw = gpio_pin_get_raw(cfg->spi_irq.port, cfg->spi_irq.pin);
	event->sck_raw = morse_spi_sck_raw();
	if (op != MORSE_SPI_EVENT_RELEASE && op != MORSE_SPI_EVENT_TRAIN) {
		spi_transaction_event_count++;
	}
}

static const char *morse_spi_event_name(uint8_t op)
{
	switch (op) {
	case MORSE_SPI_EVENT_RW:
		return "rw";
	case MORSE_SPI_EVENT_READ:
		return "read";
	case MORSE_SPI_EVENT_WRITE:
		return "write";
	case MORSE_SPI_EVENT_RELEASE:
		return "release";
	case MORSE_SPI_EVENT_TRAIN:
		return "training";
	default:
		return "unknown";
	}
}

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
	morse_log_spi_pin_state("boot_failed");
	LOG_ERR("MM8108 SPI diag ready=%d training_rc=%d last_release_rc=%d transactions=%u releases=%u rw_bytes=%u read_buf_bytes=%u write_buf_bytes=%u errors=%u byte_trace_len=%u event_trace_len=%u",
		spi_is_ready_dt(&morse_config0->spi),
		spi_training_rc, spi_release_rc, spi_transaction_count, spi_release_count,
		spi_rw_count,
		spi_read_bytes, spi_write_bytes, spi_error_count,
		(unsigned)spi_trace_len, (unsigned)spi_event_count);
	if (spi_trace_len > 0U) {
		LOG_HEXDUMP_ERR(spi_trace_tx, spi_trace_len, "MM8108 SPI first TX bytes");
		LOG_HEXDUMP_ERR(spi_trace_rx, spi_trace_len, "MM8108 SPI first RX bytes");
	}
	for (size_t i = 0; i < spi_event_count; i++) {
		const struct morse_spi_event *event = &spi_events[i];

		LOG_ERR("MM8108 SPI event=%u cycle=%u transaction=%u op=%s len=%u rc=%d tx0=0x%02x rx0=0x%02x cs_raw=%d sck_raw=%d busy_raw=%d irq_raw=%d",
			(unsigned)i, event->cycle, event->transaction,
			morse_spi_event_name(event->op), event->len, event->rc,
			event->tx_first, event->rx_first, event->cs_raw, event->sck_raw,
			event->busy_raw, event->irq_raw);
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
	spi_transaction_count = 0;
	spi_release_count = 0;
	spi_transaction_event_count = 0;
	spi_event_count = 0;
	spi_training_rc = -EINPROGRESS;
	spi_release_rc = -EINPROGRESS;
	morse_log_gpio_state("before_hard_reset");
	morse_log_spi_pin_state("before_hard_reset");

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
	/*
	 * SPI_HOLD_ON_CS causes the first transfer in this Morse transaction to
	 * assert CS and keep it asserted across the following byte/buffer calls.
	 */
	spi_transaction_count++;
	spi_transaction_event_count = 0;
}

void mmhal_wlan_spi_cs_deassert(void)
{
	const struct morse_config *cfg = morse_config0;
	int ret = spi_release(cfg->spi.bus, &cfg->spi.config);
	spi_release_rc = ret;
	spi_release_count++;
	morse_trace_spi_event(MORSE_SPI_EVENT_RELEASE, 0, ret, 0, 0);

	if (ret != 0) {
		LOG_ERR("Failed to deassert Morse SPI CS/release bus: %d", ret);
		spi_error_count++;
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
		spi_error_count++;
	}
	morse_trace_spi_event(MORSE_SPI_EVENT_RW, 1, ret, data, read_val);
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
	morse_trace_spi_event(MORSE_SPI_EVENT_READ, len, ret, 0, len > 0U ? buf[0] : 0);
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
	morse_trace_spi_event(MORSE_SPI_EVENT_WRITE, len, ret, len > 0U ? buf[0] : 0, 0);
	spi_write_bytes += len;
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

	/* Training requires clocks with CS deasserted. Disable automatic CS for
	 * this transfer and explicitly hold the active-low CS GPIO high.
	 */
	ret = gpio_pin_set_dt(&cs_gpio, 0);
	if (ret != 0) {
		LOG_ERR("Failed to deassert Morse CS for SPI training: %d", ret);
		return;
	}
	spi_cfg.operation &= ~(SPI_LOCK_ON | SPI_HOLD_ON_CS);
	spi_cfg.cs.gpio.port = NULL;

	ret = spi_transceive(spi, &spi_cfg, &tx, NULL);
	spi_training_rc = ret;
	spi_release_rc = 0;
	morse_trace_spi_event(MORSE_SPI_EVENT_TRAIN, sizeof(spi_ones), ret, spi_ones[0], 0);
	if (ret != 0) {
		LOG_ERR("Unhandled error %d in spi_transceive()\n", ret);
		spi_error_count++;
		return;
	}
	LOG_INF("MM8108 SPI training completed with CS high transaction_rc=%d release_rc=%d bytes=%u frequency=%u cs_raw=%d",
		spi_training_rc, spi_release_rc, (unsigned)sizeof(spi_ones),
		spi_cfg.frequency, gpio_pin_get_raw(cs_gpio.port, cs_gpio.pin));
	morse_log_spi_pin_state("after_training");
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
