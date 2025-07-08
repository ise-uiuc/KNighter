## Patch Description

usb: dwc2: fix possible NULL pointer dereference caused by driver concurrency

In _dwc2_hcd_urb_enqueue(), "urb->hcpriv = NULL" is executed without
holding the lock "hsotg->lock". In _dwc2_hcd_urb_dequeue():

    spin_lock_irqsave(&hsotg->lock, flags);
    ...
	if (!urb->hcpriv) {
		dev_dbg(hsotg->dev, "## urb->hcpriv is NULL ##\n");
		goto out;
	}
    rc = dwc2_hcd_urb_dequeue(hsotg, urb->hcpriv); // Use urb->hcpriv
    ...
out:
    spin_unlock_irqrestore(&hsotg->lock, flags);

When _dwc2_hcd_urb_enqueue() and _dwc2_hcd_urb_dequeue() are
concurrently executed, the NULL check of "urb->hcpriv" can be executed
before "urb->hcpriv = NULL". After urb->hcpriv is NULL, it can be used
in the function call to dwc2_hcd_urb_dequeue(), which can cause a NULL
pointer dereference.

This possible bug is found by an experimental static analysis tool
developed by myself. This tool analyzes the locking APIs to extract
function pairs that can be concurrently executed, and then analyzes the
instructions in the paired functions to identify possible concurrency
bugs including data races and atomicity violations. The above possible
bug is reported, when my tool analyzes the source code of Linux 6.5.

To fix this possible bug, "urb->hcpriv = NULL" should be executed with
holding the lock "hsotg->lock". After using this patch, my tool never
reports the possible bug, with the kernelconfiguration allyesconfig for
x86_64. Because I have no associated hardware, I cannot test the patch
in runtime testing, and just verify it according to the code logic.

Fixes: 33ad261aa62b ("usb: dwc2: host: spinlock urb_enqueue")
Signed-off-by: Jia-Ju Bai <baijiaju@buaa.edu.cn>
Link: https://lore.kernel.org/r/20230926024404.832096-1-baijiaju@buaa.edu.cn
Signed-off-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>

## Buggy Code

```c
// drivers/usb/dwc2/hcd.c
static int _dwc2_hcd_urb_enqueue(struct usb_hcd *hcd, struct urb *urb,
				 gfp_t mem_flags)
{
	struct dwc2_hsotg *hsotg = dwc2_hcd_to_hsotg(hcd);
	struct usb_host_endpoint *ep = urb->ep;
	struct dwc2_hcd_urb *dwc2_urb;
	int i;
	int retval;
	int alloc_bandwidth = 0;
	u8 ep_type = 0;
	u32 tflags = 0;
	void *buf;
	unsigned long flags;
	struct dwc2_qh *qh;
	bool qh_allocated = false;
	struct dwc2_qtd *qtd;
	struct dwc2_gregs_backup *gr;

	gr = &hsotg->gr_backup;

	if (dbg_urb(urb)) {
		dev_vdbg(hsotg->dev, "DWC OTG HCD URB Enqueue\n");
		dwc2_dump_urb_info(hcd, urb, "urb_enqueue");
	}

	if (hsotg->hibernated) {
		if (gr->gotgctl & GOTGCTL_CURMODE_HOST)
			retval = dwc2_exit_hibernation(hsotg, 0, 0, 1);
		else
			retval = dwc2_exit_hibernation(hsotg, 0, 0, 0);

		if (retval)
			dev_err(hsotg->dev,
				"exit hibernation failed.\n");
	}

	if (hsotg->in_ppd) {
		retval = dwc2_exit_partial_power_down(hsotg, 0, true);
		if (retval)
			dev_err(hsotg->dev,
				"exit partial_power_down failed\n");
	}

	if (hsotg->params.power_down == DWC2_POWER_DOWN_PARAM_NONE &&
	    hsotg->bus_suspended) {
		if (dwc2_is_device_mode(hsotg))
			dwc2_gadget_exit_clock_gating(hsotg, 0);
		else
			dwc2_host_exit_clock_gating(hsotg, 0);
	}

	if (!ep)
		return -EINVAL;

	if (usb_pipetype(urb->pipe) == PIPE_ISOCHRONOUS ||
	    usb_pipetype(urb->pipe) == PIPE_INTERRUPT) {
		spin_lock_irqsave(&hsotg->lock, flags);
		if (!dwc2_hcd_is_bandwidth_allocated(hsotg, ep))
			alloc_bandwidth = 1;
		spin_unlock_irqrestore(&hsotg->lock, flags);
	}

	switch (usb_pipetype(urb->pipe)) {
	case PIPE_CONTROL:
		ep_type = USB_ENDPOINT_XFER_CONTROL;
		break;
	case PIPE_ISOCHRONOUS:
		ep_type = USB_ENDPOINT_XFER_ISOC;
		break;
	case PIPE_BULK:
		ep_type = USB_ENDPOINT_XFER_BULK;
		break;
	case PIPE_INTERRUPT:
		ep_type = USB_ENDPOINT_XFER_INT;
		break;
	}

	dwc2_urb = dwc2_hcd_urb_alloc(hsotg, urb->number_of_packets,
				      mem_flags);
	if (!dwc2_urb)
		return -ENOMEM;

	dwc2_hcd_urb_set_pipeinfo(hsotg, dwc2_urb, usb_pipedevice(urb->pipe),
				  usb_pipeendpoint(urb->pipe), ep_type,
				  usb_pipein(urb->pipe),
				  usb_endpoint_maxp(&ep->desc),
				  usb_endpoint_maxp_mult(&ep->desc));

	buf = urb->transfer_buffer;

	if (hcd_uses_dma(hcd)) {
		if (!buf && (urb->transfer_dma & 3)) {
			dev_err(hsotg->dev,
				"%s: unaligned transfer with no transfer_buffer",
				__func__);
			retval = -EINVAL;
			goto fail0;
		}
	}

	if (!(urb->transfer_flags & URB_NO_INTERRUPT))
		tflags |= URB_GIVEBACK_ASAP;
	if (urb->transfer_flags & URB_ZERO_PACKET)
		tflags |= URB_SEND_ZERO_PACKET;

	dwc2_urb->priv = urb;
	dwc2_urb->buf = buf;
	dwc2_urb->dma = urb->transfer_dma;
	dwc2_urb->length = urb->transfer_buffer_length;
	dwc2_urb->setup_packet = urb->setup_packet;
	dwc2_urb->setup_dma = urb->setup_dma;
	dwc2_urb->flags = tflags;
	dwc2_urb->interval = urb->interval;
	dwc2_urb->status = -EINPROGRESS;

	for (i = 0; i < urb->number_of_packets; ++i)
		dwc2_hcd_urb_set_iso_desc_params(dwc2_urb, i,
						 urb->iso_frame_desc[i].offset,
						 urb->iso_frame_desc[i].length);

	urb->hcpriv = dwc2_urb;
	qh = (struct dwc2_qh *)ep->hcpriv;
	/* Create QH for the endpoint if it doesn't exist */
	if (!qh) {
		qh = dwc2_hcd_qh_create(hsotg, dwc2_urb, mem_flags);
		if (!qh) {
			retval = -ENOMEM;
			goto fail0;
		}
		ep->hcpriv = qh;
		qh_allocated = true;
	}

	qtd = kzalloc(sizeof(*qtd), mem_flags);
	if (!qtd) {
		retval = -ENOMEM;
		goto fail1;
	}

	spin_lock_irqsave(&hsotg->lock, flags);
	retval = usb_hcd_link_urb_to_ep(hcd, urb);
	if (retval)
		goto fail2;

	retval = dwc2_hcd_urb_enqueue(hsotg, dwc2_urb, qh, qtd);
	if (retval)
		goto fail3;

	if (alloc_bandwidth) {
		dwc2_allocate_bus_bandwidth(hcd,
				dwc2_hcd_get_ep_bandwidth(hsotg, ep),
				urb);
	}

	spin_unlock_irqrestore(&hsotg->lock, flags);

	return 0;

fail3:
	dwc2_urb->priv = NULL;
	usb_hcd_unlink_urb_from_ep(hcd, urb);
	if (qh_allocated && qh->channel && qh->channel->qh == qh)
		qh->channel->qh = NULL;
fail2:
	spin_unlock_irqrestore(&hsotg->lock, flags);
	urb->hcpriv = NULL;
	kfree(qtd);
fail1:
	if (qh_allocated) {
		struct dwc2_qtd *qtd2, *qtd2_tmp;

		ep->hcpriv = NULL;
		dwc2_hcd_qh_unlink(hsotg, qh);
		/* Free each QTD in the QH's QTD list */
		list_for_each_entry_safe(qtd2, qtd2_tmp, &qh->qtd_list,
					 qtd_list_entry)
			dwc2_hcd_qtd_unlink_and_free(hsotg, qtd2, qh);
		dwc2_hcd_qh_free(hsotg, qh);
	}
fail0:
	kfree(dwc2_urb);

	return retval;
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/usb/dwc2/hcd.c b/drivers/usb/dwc2/hcd.c
index 657f1f659ffa..35c7a4df8e71 100644
--- a/drivers/usb/dwc2/hcd.c
+++ b/drivers/usb/dwc2/hcd.c
@@ -4769,8 +4769,8 @@ static int _dwc2_hcd_urb_enqueue(struct usb_hcd *hcd, struct urb *urb,
 	if (qh_allocated && qh->channel && qh->channel->qh == qh)
 		qh->channel->qh = NULL;
 fail2:
-	spin_unlock_irqrestore(&hsotg->lock, flags);
 	urb->hcpriv = NULL;
+	spin_unlock_irqrestore(&hsotg->lock, flags);
 	kfree(qtd);
 fail1:
 	if (qh_allocated) {
```

