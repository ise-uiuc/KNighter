## Patch Description

backlight: hx8357: Fix potential NULL pointer dereference

The "im" pins are optional. Add missing check in the hx8357_probe().

Reported-by: Dan Carpenter <dan.carpenter@linaro.org>
Closes: https://lore.kernel.org/r/642e1230-3358-4006-a17f-3f297897ae74@moroto.mountain
Fixes: 7d84a63a39b7 ("backlight: hx8357: Convert to agnostic GPIO API")
Signed-off-by: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
Reviewed-by: Daniel Thompson <daniel.thompson@linaro.org>
Link: https://lore.kernel.org/r/20240114143921.550736-1-andriy.shevchenko@linux.intel.com
Signed-off-by: Lee Jones <lee@kernel.org>

## Buggy Code

```c
// Function: hx8357_probe in drivers/video/backlight/hx8357.c
static int hx8357_probe(struct spi_device *spi)
{
	struct device *dev = &spi->dev;
	struct lcd_device *lcdev;
	struct hx8357_data *lcd;
	const struct of_device_id *match;
	int i, ret;

	lcd = devm_kzalloc(&spi->dev, sizeof(*lcd), GFP_KERNEL);
	if (!lcd)
		return -ENOMEM;

	ret = spi_setup(spi);
	if (ret < 0) {
		dev_err(&spi->dev, "SPI setup failed.\n");
		return ret;
	}

	lcd->spi = spi;

	match = of_match_device(hx8357_dt_ids, &spi->dev);
	if (!match || !match->data)
		return -EINVAL;

	lcd->reset = devm_gpiod_get(dev, "reset", GPIOD_OUT_LOW);
	if (IS_ERR(lcd->reset))
		return dev_err_probe(dev, PTR_ERR(lcd->reset), "failed to request reset GPIO\n");
	gpiod_set_consumer_name(lcd->reset, "hx8357-reset");

	lcd->im_pins = devm_gpiod_get_array_optional(dev, "im", GPIOD_OUT_LOW);
	if (IS_ERR(lcd->im_pins))
		return dev_err_probe(dev, PTR_ERR(lcd->im_pins), "failed to request im GPIOs\n");
	if (lcd->im_pins->ndescs < HX8357_NUM_IM_PINS)
		return dev_err_probe(dev, -EINVAL, "not enough im GPIOs\n");

	for (i = 0; i < HX8357_NUM_IM_PINS; i++)
		gpiod_set_consumer_name(lcd->im_pins->desc[i], "im_pins");

	lcdev = devm_lcd_device_register(&spi->dev, "mxsfb", &spi->dev, lcd,
					&hx8357_ops);
	if (IS_ERR(lcdev)) {
		ret = PTR_ERR(lcdev);
		return ret;
	}
	spi_set_drvdata(spi, lcdev);

	hx8357_lcd_reset(lcdev);

	ret = ((int (*)(struct lcd_device *))match->data)(lcdev);
	if (ret) {
		dev_err(&spi->dev, "Couldn't initialize panel\n");
		return ret;
	}

	dev_info(&spi->dev, "Panel probed\n");

	return 0;
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/video/backlight/hx8357.c b/drivers/video/backlight/hx8357.c
index d7298376cf74..bf18337ff0c2 100644
--- a/drivers/video/backlight/hx8357.c
+++ b/drivers/video/backlight/hx8357.c
@@ -609,11 +609,13 @@ static int hx8357_probe(struct spi_device *spi)
 	lcd->im_pins = devm_gpiod_get_array_optional(dev, "im", GPIOD_OUT_LOW);
 	if (IS_ERR(lcd->im_pins))
 		return dev_err_probe(dev, PTR_ERR(lcd->im_pins), "failed to request im GPIOs\n");
-	if (lcd->im_pins->ndescs < HX8357_NUM_IM_PINS)
-		return dev_err_probe(dev, -EINVAL, "not enough im GPIOs\n");
+	if (lcd->im_pins) {
+		if (lcd->im_pins->ndescs < HX8357_NUM_IM_PINS)
+			return dev_err_probe(dev, -EINVAL, "not enough im GPIOs\n");

-	for (i = 0; i < HX8357_NUM_IM_PINS; i++)
-		gpiod_set_consumer_name(lcd->im_pins->desc[i], "im_pins");
+		for (i = 0; i < HX8357_NUM_IM_PINS; i++)
+			gpiod_set_consumer_name(lcd->im_pins->desc[i], "im_pins");
+	}

 	lcdev = devm_lcd_device_register(&spi->dev, "mxsfb", &spi->dev, lcd,
 					&hx8357_ops);
```
