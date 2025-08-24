## Patch Description

spi: mchp-pci1xxx: Fix a possible null pointer dereference in pci1xxx_spi_probe

In function pci1xxxx_spi_probe, there is a potential null pointer that
may be caused by a failed memory allocation by the function devm_kzalloc.
Hence, a null pointer check needs to be added to prevent null pointer
dereferencing later in the code.

To fix this issue, spi_bus->spi_int[iter] should be checked. The memory
allocated by devm_kzalloc will be automatically released, so just directly
return -ENOMEM without worrying about memory leaks.

Fixes: 1cc0cbea7167 ("spi: microchip: pci1xxxx: Add driver for SPI controller of PCI1XXXX PCIe switch")
Signed-off-by: Huai-Yuan Liu <qq810974084@gmail.com>
Link: https://msgid.link/r/20240403014221.969801-1-qq810974084@gmail.com
Signed-off-by: Mark Brown <broonie@kernel.org>

## Buggy Code

```c
// Function: pci1xxxx_spi_probe in drivers/spi/spi-pci1xxxx.c
static int pci1xxxx_spi_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	u8 hw_inst_cnt, iter, start, only_sec_inst;
	struct pci1xxxx_spi_internal *spi_sub_ptr;
	struct device *dev = &pdev->dev;
	struct pci1xxxx_spi *spi_bus;
	struct spi_controller *spi_host;
	u32 regval;
	int ret;

	hw_inst_cnt = ent->driver_data & 0x0f;
	start = (ent->driver_data & 0xf0) >> 4;
	if (start == 1)
		only_sec_inst = 1;
	else
		only_sec_inst = 0;

	spi_bus = devm_kzalloc(&pdev->dev,
			       struct_size(spi_bus, spi_int, hw_inst_cnt),
			       GFP_KERNEL);
	if (!spi_bus)
		return -ENOMEM;

	spi_bus->dev = pdev;
	spi_bus->total_hw_instances = hw_inst_cnt;
	pci_set_master(pdev);

	for (iter = 0; iter < hw_inst_cnt; iter++) {
		spi_bus->spi_int[iter] = devm_kzalloc(&pdev->dev,
						      sizeof(struct pci1xxxx_spi_internal),
						      GFP_KERNEL);
		spi_sub_ptr = spi_bus->spi_int[iter];
		spi_sub_ptr->spi_host = devm_spi_alloc_host(dev, sizeof(struct spi_controller));
		if (!spi_sub_ptr->spi_host)
			return -ENOMEM;

		spi_sub_ptr->parent = spi_bus;
		spi_sub_ptr->spi_xfer_in_progress = false;

		if (!iter) {
			ret = pcim_enable_device(pdev);
			if (ret)
				return -ENOMEM;

			ret = pci_request_regions(pdev, DRV_NAME);
			if (ret)
				return -ENOMEM;

			spi_bus->reg_base = pcim_iomap(pdev, 0, pci_resource_len(pdev, 0));
			if (!spi_bus->reg_base) {
				ret = -EINVAL;
				goto error;
			}

			ret = pci_alloc_irq_vectors(pdev, hw_inst_cnt, hw_inst_cnt,
						    PCI_IRQ_ALL_TYPES);
			if (ret < 0) {
				dev_err(&pdev->dev, "Error allocating MSI vectors\n");
				goto error;
			}

			init_completion(&spi_sub_ptr->spi_xfer_done);
			/* Initialize Interrupts - SPI_INT */
			regval = readl(spi_bus->reg_base +
				       SPI_MST_EVENT_MASK_REG_OFFSET(spi_sub_ptr->hw_inst));
			regval &= ~SPI_INTR;
			writel(regval, spi_bus->reg_base +
			       SPI_MST_EVENT_MASK_REG_OFFSET(spi_sub_ptr->hw_inst));
			spi_sub_ptr->irq = pci_irq_vector(pdev, 0);

			ret = devm_request_irq(&pdev->dev, spi_sub_ptr->irq,
					       pci1xxxx_spi_isr, PCI1XXXX_IRQ_FLAGS,
					       pci_name(pdev), spi_sub_ptr);
			if (ret < 0) {
				dev_err(&pdev->dev, "Unable to request irq : %d",
					spi_sub_ptr->irq);
				ret = -ENODEV;
				goto error;
			}

			ret = pci1xxxx_spi_dma_init(spi_bus, spi_sub_ptr->irq);
			if (ret && ret != -EOPNOTSUPP)
				goto error;

			/* This register is only applicable for 1st instance */
			regval = readl(spi_bus->reg_base + SPI_PCI_CTRL_REG_OFFSET(0));
			if (!only_sec_inst)
				regval |= (BIT(4));
			else
				regval &= ~(BIT(4));

			writel(regval, spi_bus->reg_base + SPI_PCI_CTRL_REG_OFFSET(0));
		}

		spi_sub_ptr->hw_inst = start++;

		if (iter == 1) {
			init_completion(&spi_sub_ptr->spi_xfer_done);
			/* Initialize Interrupts - SPI_INT */
			regval = readl(spi_bus->reg_base +
			       SPI_MST_EVENT_MASK_REG_OFFSET(spi_sub_ptr->hw_inst));
			regval &= ~SPI_INTR;
			writel(regval, spi_bus->reg_base +
			       SPI_MST_EVENT_MASK_REG_OFFSET(spi_sub_ptr->hw_inst));
			spi_sub_ptr->irq = pci_irq_vector(pdev, iter);
			ret = devm_request_irq(&pdev->dev, spi_sub_ptr->irq,
					       pci1xxxx_spi_isr, PCI1XXXX_IRQ_FLAGS,
					       pci_name(pdev), spi_sub_ptr);
			if (ret < 0) {
				dev_err(&pdev->dev, "Unable to request irq : %d",
					spi_sub_ptr->irq);
				ret = -ENODEV;
				goto error;
			}
		}

		spi_host = spi_sub_ptr->spi_host;
		spi_host->num_chipselect = SPI_CHIP_SEL_COUNT;
		spi_host->mode_bits = SPI_MODE_0 | SPI_MODE_3 | SPI_RX_DUAL |
				      SPI_TX_DUAL | SPI_LOOP;
		spi_host->can_dma = pci1xxxx_spi_can_dma;
		spi_host->transfer_one = pci1xxxx_spi_transfer_one;

		spi_host->set_cs = pci1xxxx_spi_set_cs;
		spi_host->bits_per_word_mask = SPI_BPW_MASK(8);
		spi_host->max_speed_hz = PCI1XXXX_SPI_MAX_CLOCK_HZ;
		spi_host->min_speed_hz = PCI1XXXX_SPI_MIN_CLOCK_HZ;
		spi_host->flags = SPI_CONTROLLER_MUST_TX;
		spi_controller_set_devdata(spi_host, spi_sub_ptr);
		ret = devm_spi_register_controller(dev, spi_host);
		if (ret)
			goto error;
	}
	pci_set_drvdata(pdev, spi_bus);

	return 0;

error:
	pci_release_regions(pdev);
	return ret;
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/spi/spi-pci1xxxx.c b/drivers/spi/spi-pci1xxxx.c
index 969965d7bc98..cc18d320370f 100644
--- a/drivers/spi/spi-pci1xxxx.c
+++ b/drivers/spi/spi-pci1xxxx.c
@@ -725,6 +725,8 @@ static int pci1xxxx_spi_probe(struct pci_dev *pdev, const struct pci_device_id *
 		spi_bus->spi_int[iter] = devm_kzalloc(&pdev->dev,
 						      sizeof(struct pci1xxxx_spi_internal),
 						      GFP_KERNEL);
+		if (!spi_bus->spi_int[iter])
+			return -ENOMEM;
 		spi_sub_ptr = spi_bus->spi_int[iter];
 		spi_sub_ptr->spi_host = devm_spi_alloc_host(dev, sizeof(struct spi_controller));
 		if (!spi_sub_ptr->spi_host)
```
