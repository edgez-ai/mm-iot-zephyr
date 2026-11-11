/*
 * Copyright 2024-2026 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "morsemicro_log.h"
LOG_MODULE_DECLARE(LOG_MODULE_NAME);

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/spi.h>
#include <errno.h>

#include "mmhal.h"

#include "morsemicro_common.h"

static struct gpio_callback spi_irq_gpio_cb;
static mmhal_irq_handler_t spi_irq_handler = NULL;

static union morsemicro_bus_config bus_config;

#if defined(CONFIG_OFFGRID_NRF54_SENSOR_SPI_SLEEP_PINS)
#include <zephyr/pm/device.h>
#include <hal/nrf_gpio.h>

/* Passive evidence: successful suspends, resumes, errors, suspended state.
 * All transitions run in the SDK thread, serialized by its transport lock. */
volatile uint32_t sensor_spi_sleep_state[4];
/* Last errors per stage, plus already-released context count. */
volatile int32_t sensor_spi_sleep_diagnostics[6];

int morsemicro_sensor_spi_resume(void)
{
	if (!sensor_spi_sleep_state[3]) {
		return 0;
	}
	int rc = pm_device_action_run(bus_config.spi.bus, PM_DEVICE_ACTION_RESUME);
	if (rc != 0 && rc != -EALREADY) {
		sensor_spi_sleep_diagnostics[0] = rc;
		++sensor_spi_sleep_state[2];
		LOG_ERR("Sensor SPI resume failed: %d", rc);
		return rc;
	}
	/* The SPIM PM callback restores the default SCK/MOSI/MISO pinctrl state. */
	rc = gpio_pin_configure_dt(&bus_config.spi.config.cs.gpio, GPIO_OUTPUT_INACTIVE);
	if (rc != 0) {
		sensor_spi_sleep_diagnostics[1] = rc;
		++sensor_spi_sleep_state[2];
		return rc;
	}
	sensor_spi_sleep_state[3] = 0;
	++sensor_spi_sleep_state[1];
	return 0;
}

static void morsemicro_sensor_spi_suspend(void)
{
	if (sensor_spi_sleep_state[3]) {
		return;
	}
	/* SPI_LOCK_ON retains the controller context after a transfer. Release it
	 * while the SDK transport lock is held, before asking PM to suspend. */
	int rc = spi_release(bus_config.spi.bus, &bus_config.spi.config);
	if (rc == -EALREADY) {
		/* Zephyr's async SPI API reports this when no matching context is
		 * owned, including initial startup and after training releases it. */
		++sensor_spi_sleep_diagnostics[5];
	}
	if (rc != 0 && rc != -EINVAL && rc != -EALREADY) {
		sensor_spi_sleep_diagnostics[2] = rc;
		++sensor_spi_sleep_state[2];
		return;
	}
	rc = gpio_pin_configure_dt(&bus_config.spi.config.cs.gpio, GPIO_OUTPUT_INACTIVE);
	if (rc != 0) {
		sensor_spi_sleep_diagnostics[3] = rc;
	}
	if (rc == 0) {
		rc = pm_device_action_run(bus_config.spi.bus, PM_DEVICE_ACTION_SUSPEND);
	}
	if (rc != 0 && rc != -EALREADY) {
		sensor_spi_sleep_diagnostics[4] = rc;
		++sensor_spi_sleep_state[2];
		LOG_ERR("Sensor SPI suspend failed: %d", rc);
		return;
	}
	/* Match the carrier's all-off benchmark. The radio stays powered, CS
	 * remains inactive, and BUSY retains its existing wake interrupt. */
	nrf_gpio_cfg_default(NRF_GPIO_PIN_MAP(2, 1));
	nrf_gpio_cfg_default(NRF_GPIO_PIN_MAP(2, 2));
	nrf_gpio_cfg_default(NRF_GPIO_PIN_MAP(2, 4));
	sensor_spi_sleep_state[3] = 1;
	++sensor_spi_sleep_state[0];
}
#endif

static uint8_t training_sequence[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

/**
 * @brief This function handles SPI IRQ interrupts.
 */
static void morsemicro_spi_irq_cb(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
	if (spi_irq_handler != NULL) {
		spi_irq_handler();
	}
}

void mmhal_wlan_spi_cs_assert(void)
{
}

void mmhal_wlan_spi_cs_deassert(void)
{
}

uint8_t mmhal_wlan_spi_rw(uint8_t data)
{
#if defined(CONFIG_OFFGRID_NRF54_SENSOR_SPI_SLEEP_PINS)
	if (morsemicro_sensor_spi_resume() != 0) { return 0xff; }
#endif
	const struct device *spi = bus_config.spi.bus;
	const struct spi_config *spi_cfg = &bus_config.spi.config;
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
#if defined(CONFIG_OFFGRID_NRF54_SENSOR_SPI_SLEEP_PINS)
	if (morsemicro_sensor_spi_resume() != 0) { memset(buf, 0xff, len); return; }
#endif
	const struct device *spi = bus_config.spi.bus;
	const struct spi_config *spi_cfg = &bus_config.spi.config;
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
#if defined(CONFIG_OFFGRID_NRF54_SENSOR_SPI_SLEEP_PINS)
	if (morsemicro_sensor_spi_resume() != 0) { return; }
#endif
	const struct device *spi = bus_config.spi.bus;
	const struct spi_config *spi_cfg = &bus_config.spi.config;
	int ret = 0;

	struct spi_buf tx_bufs[] = {{.buf = (void *)buf, .len = len}};

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
#if defined(CONFIG_OFFGRID_NRF54_SENSOR_SPI_SLEEP_PINS)
	if (morsemicro_sensor_spi_resume() != 0) { return; }
#endif
	const struct device *spi = bus_config.spi.bus;
	struct gpio_dt_spec *cs_gpio = &bus_config.spi.config.cs.gpio;
	struct spi_config spi_cfg = bus_config.spi.config;
	gpio_flags_t flags = GPIO_OUTPUT_INACTIVE;
	int ret = 0;

	struct spi_buf tx_bufs = {.buf = (uint8_t *)training_sequence,
				  .len = sizeof(training_sequence)};

	const struct spi_buf_set tx = {
		.buffers = &tx_bufs,
		.count = 1,
	};

	ret = gpio_pin_get_config_dt(cs_gpio, &flags);
	if (ret == -ENOSYS) {
		LOG_DBG("Platform does not implement gpio_pin_get_config(), using default flags\n");
	} else if (ret < 0) {
		LOG_ERR("Unhandled error %d in gpio_pin_get_config_dt()\n", ret);
		return;
	}

	ret = gpio_pin_configure(cs_gpio->port, cs_gpio->pin, flags & ~(GPIO_ACTIVE_LOW));
	if (ret != 0) {
		LOG_ERR("Unhandled error %d in gpio_pin_configure()\n", ret);
		return;
	}

	ret = spi_transceive(spi, &spi_cfg, &tx, NULL);
	if (ret != 0) {
		LOG_ERR("Unhandled error %d in spi_transceive()\n", ret);
		return;
	}
	/* Release lock on SPI bus */
	ret = spi_release(spi, &spi_cfg);

	ret = gpio_pin_configure(cs_gpio->port, cs_gpio->pin, flags | GPIO_ACTIVE_LOW);
	if (ret != 0) {
		LOG_ERR("Unhandled error %d in gpio_pin_configure()\n", ret);
		return;
	}
}

void mmhal_wlan_register_spi_irq_handler(mmhal_irq_handler_t handler)
{
	spi_irq_handler = handler;
}

bool mmhal_wlan_spi_irq_is_asserted(void)
{
	int ret = 0;
	if ((ret = gpio_pin_get_dt(&bus_config.spi_irq)) < 0) {
		LOG_ERR("Unhandled exception %d in %s\n", ret, __func__);
		return false;
	}
	return !!ret;
}

void mmhal_wlan_set_spi_irq_enabled(bool enabled)
{
	if (enabled) {
#if defined(CONFIG_OFFGRID_NRF54_SENSOR_SPI_SLEEP_PINS)
		if (morsemicro_sensor_spi_resume() != 0) return;
#endif
#if defined(CONFIG_OFFGRID_NRF54_SENSOR_SPI_IRQ_SLEEP_NOPULL)
		/* Restore open-drain bias before reading/unmasking IRQ. */
		gpio_pin_configure_dt(&bus_config.spi_irq, GPIO_INPUT | GPIO_PULL_UP);
#endif
		/* The transiver will hold the IRQ line low if there is additional information
		 * to be retrived. Ideally the interrupt pin would be configured as a low level
		 * interrupt.
		 */
		if (mmhal_wlan_spi_irq_is_asserted()) {
			if (spi_irq_handler != NULL) {
				spi_irq_handler();
			}
		}
		gpio_pin_interrupt_configure_dt(&bus_config.spi_irq, GPIO_INT_EDGE_TO_ACTIVE);
	} else {
		gpio_pin_interrupt_configure_dt(&bus_config.spi_irq, GPIO_INT_DISABLE);
#if defined(CONFIG_OFFGRID_NRF54_SENSOR_SPI_IRQ_SLEEP_NOPULL)
		/* IRQ is masked before retained sleep; BUSY remains the wake source. */
		gpio_pin_configure_dt(&bus_config.spi_irq, GPIO_INPUT);
#endif
#if defined(CONFIG_OFFGRID_NRF54_SENSOR_SPI_SLEEP_PINS)
		morsemicro_sensor_spi_suspend();
#endif
	}
}

static int morsemicro_bus_init(const struct device *dev)
{
	bus_config = ((const struct morsemicro_config *)dev->config)->bus_config;

	if (!spi_is_ready_dt(&bus_config.spi)) {
		LOG_ERR("SPI bus %s not ready", bus_config.spi.bus->name);
		return -ENODEV;
	}

	if (!gpio_is_ready_dt(&bus_config.spi_irq)) {
		LOG_ERR("%s: device %s is not ready", dev->name, bus_config.spi_irq.port->name);
		return -ENODEV;
	}
	gpio_pin_configure_dt(&bus_config.spi_irq, GPIO_INPUT | GPIO_PULL_UP);
	gpio_pin_interrupt_configure_dt(&bus_config.spi_irq, GPIO_INT_DISABLE);

	gpio_init_callback(&spi_irq_gpio_cb, morsemicro_spi_irq_cb, BIT(bus_config.spi_irq.pin));
	gpio_add_callback(bus_config.spi_irq.port, &spi_irq_gpio_cb);

	return 0;
}

static int morsemicro_bus_release()
{
	int ret = spi_release(bus_config.spi.bus, &bus_config.spi.config);

	if (ret != 0) {
		LOG_ERR("Failed to release SPI bus: %d", ret);
	}

	return ret;
}

const struct morsemicro_bus_ops morsemicro_bus_ops_spi = {
	.init = morsemicro_bus_init,
	.release = morsemicro_bus_release,
};
