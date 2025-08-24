## Patch Description

platform/chrome: cros_ec_uart: properly fix race condition

The cros_ec_uart_probe() function calls devm_serdev_device_open() before
it calls serdev_device_set_client_ops(). This can trigger a NULL pointer
dereference:

    BUG: kernel NULL pointer dereference, address: 0000000000000000
    ...
    Call Trace:
     <TASK>
     ...
     ? ttyport_receive_buf

A simplified version of crashing code is as follows:

    static inline size_t serdev_controller_receive_buf(struct serdev_controller *ctrl,
                                                      const u8 *data,
                                                      size_t count)
    {
            struct serdev_device *serdev = ctrl->serdev;

            if (!serdev || !serdev->ops->receive_buf) // CRASH!
                return 0;

            return serdev->ops->receive_buf(serdev, data, count);
    }

It assumes that if SERPORT_ACTIVE is set and serdev exists, serdev->ops
will also exist. This conflicts with the existing cros_ec_uart_probe()
logic, as it first calls devm_serdev_device_open() (which sets
SERPORT_ACTIVE), and only later sets serdev->ops via
serdev_device_set_client_ops().

Commit 01f95d42b8f4 ("platform/chrome: cros_ec_uart: fix race
condition") attempted to fix a similar race condition, but while doing
so, made the window of error for this race condition to happen much
wider.

Attempt to fix the race condition again, making sure we fully setup
before calling devm_serdev_device_open().

Fixes: 01f95d42b8f4 ("platform/chrome: cros_ec_uart: fix race condition")
Cc: stable@vger.kernel.org
Signed-off-by: Noah Loomans <noah@noahloomans.com>
Reviewed-by: Guenter Roeck <groeck@chromium.org>
Link: https://lore.kernel.org/r/20240410182618.169042-2-noah@noahloomans.com
Signed-off-by: Tzung-Bi Shih <tzungbi@kernel.org>

## Buggy Code

```c
// Function: cros_ec_uart_probe in drivers/platform/chrome/cros_ec_uart.c
static int cros_ec_uart_probe(struct serdev_device *serdev)
{
	struct device *dev = &serdev->dev;
	struct cros_ec_device *ec_dev;
	struct cros_ec_uart *ec_uart;
	int ret;

	ec_uart = devm_kzalloc(dev, sizeof(*ec_uart), GFP_KERNEL);
	if (!ec_uart)
		return -ENOMEM;

	ec_dev = devm_kzalloc(dev, sizeof(*ec_dev), GFP_KERNEL);
	if (!ec_dev)
		return -ENOMEM;

	ret = devm_serdev_device_open(dev, serdev);
	if (ret) {
		dev_err(dev, "Unable to open UART device");
		return ret;
	}

	serdev_device_set_drvdata(serdev, ec_dev);
	init_waitqueue_head(&ec_uart->response.wait_queue);

	ec_uart->serdev = serdev;

	ret = cros_ec_uart_acpi_probe(ec_uart);
	if (ret < 0) {
		dev_err(dev, "Failed to get ACPI info (%d)", ret);
		return ret;
	}

	ret = serdev_device_set_baudrate(serdev, ec_uart->baudrate);
	if (ret < 0) {
		dev_err(dev, "Failed to set up host baud rate (%d)", ret);
		return ret;
	}

	serdev_device_set_flow_control(serdev, ec_uart->flowcontrol);

	/* Initialize ec_dev for cros_ec  */
	ec_dev->phys_name = dev_name(dev);
	ec_dev->dev = dev;
	ec_dev->priv = ec_uart;
	ec_dev->irq = ec_uart->irq;
	ec_dev->cmd_xfer = NULL;
	ec_dev->pkt_xfer = cros_ec_uart_pkt_xfer;
	ec_dev->din_size = sizeof(struct ec_host_response) +
			   sizeof(struct ec_response_get_protocol_info);
	ec_dev->dout_size = sizeof(struct ec_host_request);

	serdev_device_set_client_ops(serdev, &cros_ec_uart_client_ops);

	return cros_ec_register(ec_dev);
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/platform/chrome/cros_ec_uart.c b/drivers/platform/chrome/cros_ec_uart.c
index 68d80559fddc..eb5eddeb73f7 100644
--- a/drivers/platform/chrome/cros_ec_uart.c
+++ b/drivers/platform/chrome/cros_ec_uart.c
@@ -263,12 +263,6 @@ static int cros_ec_uart_probe(struct serdev_device *serdev)
 	if (!ec_dev)
 		return -ENOMEM;

-	ret = devm_serdev_device_open(dev, serdev);
-	if (ret) {
-		dev_err(dev, "Unable to open UART device");
-		return ret;
-	}
-
 	serdev_device_set_drvdata(serdev, ec_dev);
 	init_waitqueue_head(&ec_uart->response.wait_queue);

@@ -280,14 +274,6 @@ static int cros_ec_uart_probe(struct serdev_device *serdev)
 		return ret;
 	}

-	ret = serdev_device_set_baudrate(serdev, ec_uart->baudrate);
-	if (ret < 0) {
-		dev_err(dev, "Failed to set up host baud rate (%d)", ret);
-		return ret;
-	}
-
-	serdev_device_set_flow_control(serdev, ec_uart->flowcontrol);
-
 	/* Initialize ec_dev for cros_ec  */
 	ec_dev->phys_name = dev_name(dev);
 	ec_dev->dev = dev;
@@ -301,6 +287,20 @@ static int cros_ec_uart_probe(struct serdev_device *serdev)

 	serdev_device_set_client_ops(serdev, &cros_ec_uart_client_ops);

+	ret = devm_serdev_device_open(dev, serdev);
+	if (ret) {
+		dev_err(dev, "Unable to open UART device");
+		return ret;
+	}
+
+	ret = serdev_device_set_baudrate(serdev, ec_uart->baudrate);
+	if (ret < 0) {
+		dev_err(dev, "Failed to set up host baud rate (%d)", ret);
+		return ret;
+	}
+
+	serdev_device_set_flow_control(serdev, ec_uart->flowcontrol);
+
 	return cros_ec_register(ec_dev);
 }

```
