## Patch Description

iio: adc: palmas: fix off by one bugs

Valid values for "adc_chan" are zero to (PALMAS_ADC_CH_MAX - 1).
Smatch detects some buffer overflows caused by this:
drivers/iio/adc/palmas_gpadc.c:721 palmas_gpadc_read_event_value() error: buffer overflow 'adc->thresholds' 16 <= 16
drivers/iio/adc/palmas_gpadc.c:758 palmas_gpadc_write_event_value() error: buffer overflow 'adc->thresholds' 16 <= 16

The effect of this bug in other functions is more complicated but
obviously we should fix all of them.

Fixes: a99544c6c883 ("iio: adc: palmas: add support for iio threshold events")
Signed-off-by: Dan Carpenter <dan.carpenter@linaro.org>
Link: https://lore.kernel.org/r/14fee94a-7db7-4371-b7d6-e94d86b9561e@kili.mountain
Signed-off-by: Jonathan Cameron <Jonathan.Cameron@huawei.com>

## Buggy Code

```c
// drivers/iio/adc/palmas_gpadc.c
static int palmas_gpadc_read_raw(struct iio_dev *indio_dev,
	struct iio_chan_spec const *chan, int *val, int *val2, long mask)
{
	struct  palmas_gpadc *adc = iio_priv(indio_dev);
	int adc_chan = chan->channel;
	int ret = 0;

	if (adc_chan > PALMAS_ADC_CH_MAX)
		return -EINVAL;

	mutex_lock(&adc->lock);

	switch (mask) {
	case IIO_CHAN_INFO_RAW:
	case IIO_CHAN_INFO_PROCESSED:
		ret = palmas_gpadc_read_prepare(adc, adc_chan);
		if (ret < 0)
			goto out;

		ret = palmas_gpadc_start_conversion(adc, adc_chan);
		if (ret < 0) {
			dev_err(adc->dev,
			"ADC start conversion failed\n");
			goto out;
		}

		if (mask == IIO_CHAN_INFO_PROCESSED)
			ret = palmas_gpadc_get_calibrated_code(
							adc, adc_chan, ret);

		*val = ret;

		ret = IIO_VAL_INT;
		goto out;
	}

	mutex_unlock(&adc->lock);
	return ret;

out:
	palmas_gpadc_read_done(adc, adc_chan);
	mutex_unlock(&adc->lock);

	return ret;
}
```
```c
// drivers/iio/adc/palmas_gpadc.c
static int palmas_gpadc_write_event_config(struct iio_dev *indio_dev,
					   const struct iio_chan_spec *chan,
					   enum iio_event_type type,
					   enum iio_event_direction dir,
					   int state)
{
	struct palmas_gpadc *adc = iio_priv(indio_dev);
	int adc_chan = chan->channel;
	int ret;

	if (adc_chan > PALMAS_ADC_CH_MAX || type != IIO_EV_TYPE_THRESH)
		return -EINVAL;

	mutex_lock(&adc->lock);

	if (state)
		ret = palmas_gpadc_enable_event_config(adc, chan, dir);
	else
		ret = palmas_gpadc_disable_event_config(adc, chan, dir);

	mutex_unlock(&adc->lock);

	return ret;
}
```
```c
// drivers/iio/adc/palmas_gpadc.c
static int palmas_gpadc_read_event_value(struct iio_dev *indio_dev,
					 const struct iio_chan_spec *chan,
					 enum iio_event_type type,
					 enum iio_event_direction dir,
					 enum iio_event_info info,
					 int *val, int *val2)
{
	struct palmas_gpadc *adc = iio_priv(indio_dev);
	int adc_chan = chan->channel;
	int ret;

	if (adc_chan > PALMAS_ADC_CH_MAX || type != IIO_EV_TYPE_THRESH)
		return -EINVAL;

	mutex_lock(&adc->lock);

	switch (info) {
	case IIO_EV_INFO_VALUE:
		*val = (dir == IIO_EV_DIR_RISING) ?
			adc->thresholds[adc_chan].high :
			adc->thresholds[adc_chan].low;
		ret = IIO_VAL_INT;
		break;
	default:
		ret = -EINVAL;
		break;
	}

	mutex_unlock(&adc->lock);

	return ret;
}
```
```c
// drivers/iio/adc/palmas_gpadc.c
static int palmas_gpadc_read_event_config(struct iio_dev *indio_dev,
					  const struct iio_chan_spec *chan,
					  enum iio_event_type type,
					  enum iio_event_direction dir)
{
	struct palmas_gpadc *adc = iio_priv(indio_dev);
	int adc_chan = chan->channel;
	int ret = 0;

	if (adc_chan > PALMAS_ADC_CH_MAX || type != IIO_EV_TYPE_THRESH)
		return -EINVAL;

	mutex_lock(&adc->lock);

	if (palmas_gpadc_get_event(adc, adc_chan, dir))
		ret = 1;

	mutex_unlock(&adc->lock);

	return ret;
}
```
```c
// drivers/iio/adc/palmas_gpadc.c
static int palmas_gpadc_write_event_value(struct iio_dev *indio_dev,
					  const struct iio_chan_spec *chan,
					  enum iio_event_type type,
					  enum iio_event_direction dir,
					  enum iio_event_info info,
					  int val, int val2)
{
	struct palmas_gpadc *adc = iio_priv(indio_dev);
	int adc_chan = chan->channel;
	int old;
	int ret;

	if (adc_chan > PALMAS_ADC_CH_MAX || type != IIO_EV_TYPE_THRESH)
		return -EINVAL;

	mutex_lock(&adc->lock);
	switch (info) {
	case IIO_EV_INFO_VALUE:
		if (val < 0 || val > 0xFFF) {
			ret = -EINVAL;
			goto out_unlock;
		}
		if (dir == IIO_EV_DIR_RISING) {
			old = adc->thresholds[adc_chan].high;
			adc->thresholds[adc_chan].high = val;
		} else {
			old = adc->thresholds[adc_chan].low;
			adc->thresholds[adc_chan].low = val;
		}
		ret = 0;
		break;
	default:
		ret = -EINVAL;
		goto out_unlock;
	}

	if (val != old && palmas_gpadc_get_event(adc, adc_chan, dir))
		ret = palmas_gpadc_reconfigure_event_channels(adc);

out_unlock:
	mutex_unlock(&adc->lock);

	return ret;
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/iio/adc/palmas_gpadc.c b/drivers/iio/adc/palmas_gpadc.c
index c1c439215aeb..7dfc9c927a23 100644
--- a/drivers/iio/adc/palmas_gpadc.c
+++ b/drivers/iio/adc/palmas_gpadc.c
@@ -547,7 +547,7 @@ static int palmas_gpadc_read_raw(struct iio_dev *indio_dev,
 	int adc_chan = chan->channel;
 	int ret = 0;
 
-	if (adc_chan > PALMAS_ADC_CH_MAX)
+	if (adc_chan >= PALMAS_ADC_CH_MAX)
 		return -EINVAL;
 
 	mutex_lock(&adc->lock);
@@ -595,7 +595,7 @@ static int palmas_gpadc_read_event_config(struct iio_dev *indio_dev,
 	int adc_chan = chan->channel;
 	int ret = 0;
 
-	if (adc_chan > PALMAS_ADC_CH_MAX || type != IIO_EV_TYPE_THRESH)
+	if (adc_chan >= PALMAS_ADC_CH_MAX || type != IIO_EV_TYPE_THRESH)
 		return -EINVAL;
 
 	mutex_lock(&adc->lock);
@@ -684,7 +684,7 @@ static int palmas_gpadc_write_event_config(struct iio_dev *indio_dev,
 	int adc_chan = chan->channel;
 	int ret;
 
-	if (adc_chan > PALMAS_ADC_CH_MAX || type != IIO_EV_TYPE_THRESH)
+	if (adc_chan >= PALMAS_ADC_CH_MAX || type != IIO_EV_TYPE_THRESH)
 		return -EINVAL;
 
 	mutex_lock(&adc->lock);
@@ -710,7 +710,7 @@ static int palmas_gpadc_read_event_value(struct iio_dev *indio_dev,
 	int adc_chan = chan->channel;
 	int ret;
 
-	if (adc_chan > PALMAS_ADC_CH_MAX || type != IIO_EV_TYPE_THRESH)
+	if (adc_chan >= PALMAS_ADC_CH_MAX || type != IIO_EV_TYPE_THRESH)
 		return -EINVAL;
 
 	mutex_lock(&adc->lock);
@@ -744,7 +744,7 @@ static int palmas_gpadc_write_event_value(struct iio_dev *indio_dev,
 	int old;
 	int ret;
 
-	if (adc_chan > PALMAS_ADC_CH_MAX || type != IIO_EV_TYPE_THRESH)
+	if (adc_chan >= PALMAS_ADC_CH_MAX || type != IIO_EV_TYPE_THRESH)
 		return -EINVAL;
 
 	mutex_lock(&adc->lock);
```

