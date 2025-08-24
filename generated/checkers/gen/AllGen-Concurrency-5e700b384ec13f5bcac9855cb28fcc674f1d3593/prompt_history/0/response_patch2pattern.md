## Bug Pattern

Activating a serdev port before registering its client ops, i.e., calling devm_serdev_device_open() (which can trigger asynchronous receive callbacks) before serdev_device_set_client_ops(). This enables the port and may invoke receive_buf while serdev->ops is still NULL, leading to a NULL pointer dereference.

Example of the faulty ordering:
- devm_serdev_device_open(dev, serdev);  // Port becomes active; callbacks may fire
- serdev_device_set_client_ops(serdev, &ops);  // Ops set too late

Correct pattern: set client ops (and complete necessary initialization) before opening/activating the device.
