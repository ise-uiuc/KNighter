## Patch Description

ASoC: sma1307: fix uninitialized variable refence

When firmware loading is disabled, gcc warns that the local
'fw' variable fails to get initialized:

sound/soc/codecs/sma1307.c: In function 'sma1307_setting_loaded.isra':
sound/soc/codecs/sma1307.c:1717:12: error: 'fw' is used uninitialized [-Werror=uninitialized]
 1717 |         if (!fw) {
      |            ^
sound/soc/codecs/sma1307.c:1712:32: note: 'fw' was declared here
 1712 |         const struct firmware *fw;

Check the return code from request_firmware() to ensure that the
firmware is correctly set, and drop the incorrect release_firmware()
on that uninitialized data.

Fixes: 576c57e6b4c1 ("ASoC: sma1307: Add driver for Iron Device SMA1307")
Signed-off-by: Arnd Bergmann <arnd@arndb.de>
Link: https://patch.msgid.link/20241113175734.2443315-1-arnd@kernel.org
Signed-off-by: Mark Brown <broonie@kernel.org>

## Buggy Code

```c
// Function: sma1307_setting_loaded in sound/soc/codecs/sma1307.c
static void sma1307_setting_loaded(struct sma1307_priv *sma1307, const char *file)
{
	const struct firmware *fw;
	int *data, size, offset, num_mode;

	request_firmware(&fw, file, sma1307->dev);

	if (!fw) {
		dev_err(sma1307->dev, "%s: failed to read \"%s\"\n",
			__func__, setting_file);
		release_firmware(fw);
		sma1307->set.status = false;
		return;
	} else if ((fw->size) < SMA1307_SETTING_HEADER_SIZE) {
		dev_err(sma1307->dev, "%s: Invalid file\n", __func__);
		release_firmware(fw);
		sma1307->set.status = false;
		return;
	}

	data = kzalloc(fw->size, GFP_KERNEL);
	size = fw->size >> 2;
	memcpy(data, fw->data, fw->size);

	release_firmware(fw);

	/* HEADER */
	sma1307->set.header_size = SMA1307_SETTING_HEADER_SIZE;
	sma1307->set.checksum = data[sma1307->set.header_size - 2];
	sma1307->set.num_mode = data[sma1307->set.header_size - 1];
	num_mode = sma1307->set.num_mode;
	sma1307->set.header = devm_kzalloc(sma1307->dev,
					   sma1307->set.header_size,
					   GFP_KERNEL);
	memcpy(sma1307->set.header, data,
	       sma1307->set.header_size * sizeof(int));

	if ((sma1307->set.checksum >> 8) != SMA1307_SETTING_CHECKSUM) {
		dev_err(sma1307->dev, "%s: failed by dismatch \"%s\"\n",
			__func__, setting_file);
		sma1307->set.status = false;
		return;
	}

	/* DEFAULT */
	sma1307->set.def_size = SMA1307_SETTING_DEFAULT_SIZE;
	sma1307->set.def
	    = devm_kzalloc(sma1307->dev,
			   sma1307->set.def_size * sizeof(int), GFP_KERNEL);
	memcpy(sma1307->set.def,
	       &data[sma1307->set.header_size],
	       sma1307->set.def_size * sizeof(int));

	/* MODE */
	offset = sma1307->set.header_size + sma1307->set.def_size;
	sma1307->set.mode_size = DIV_ROUND_CLOSEST(size - offset, num_mode + 1);
	for (int i = 0; i < num_mode; i++) {
		sma1307->set.mode_set[i]
		    = devm_kzalloc(sma1307->dev,
				   sma1307->set.mode_size * 2 * sizeof(int),
				   GFP_KERNEL);
		for (int j = 0; j < sma1307->set.mode_size; j++) {
			sma1307->set.mode_set[i][2 * j]
			    = data[offset + ((num_mode + 1) * j)];
			sma1307->set.mode_set[i][2 * j + 1]
			    = data[offset + ((num_mode + 1) * j + i + 1)];
		}
	}

	kfree(data);
	sma1307->set.status = true;

}
```

## Bug Fix Patch

```diff
diff --git a/sound/soc/codecs/sma1307.c b/sound/soc/codecs/sma1307.c
index 81638768ac12..f2cea6186d98 100644
--- a/sound/soc/codecs/sma1307.c
+++ b/sound/soc/codecs/sma1307.c
@@ -1711,13 +1711,13 @@ static void sma1307_setting_loaded(struct sma1307_priv *sma1307, const char *fil
 {
 	const struct firmware *fw;
 	int *data, size, offset, num_mode;
+	int ret;

-	request_firmware(&fw, file, sma1307->dev);
+	ret = request_firmware(&fw, file, sma1307->dev);

-	if (!fw) {
-		dev_err(sma1307->dev, "%s: failed to read \"%s\"\n",
-			__func__, setting_file);
-		release_firmware(fw);
+	if (ret) {
+		dev_err(sma1307->dev, "%s: failed to read \"%s\": %pe\n",
+			__func__, setting_file, ERR_PTR(ret));
 		sma1307->set.status = false;
 		return;
 	} else if ((fw->size) < SMA1307_SETTING_HEADER_SIZE) {
```
