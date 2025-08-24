## Bug Pattern

Allocating a per-instance structure with devm_kzalloc() and then immediately dereferencing it (directly or via an alias) without checking for NULL. For example:

spi_bus->spi_int[i] = devm_kzalloc(dev, sizeof(*spi_bus->spi_int[i]), GFP_KERNEL);
/* Missing NULL check here */
spi_sub_ptr = spi_bus->spi_int[i];
spi_sub_ptr->spi_host = devm_spi_alloc_host(dev, sizeof(struct spi_controller));

This pattern risks a NULL pointer dereference if devm_kzalloc() fails.
