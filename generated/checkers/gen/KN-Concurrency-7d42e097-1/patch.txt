## Patch Description

crypto: qat - resolve race condition during AER recovery

During the PCI AER system's error recovery process, the kernel driver
may encounter a race condition with freeing the reset_data structure's
memory. If the device restart will take more than 10 seconds the function
scheduling that restart will exit due to a timeout, and the reset_data
structure will be freed. However, this data structure is used for
completion notification after the restart is completed, which leads
to a UAF bug.

This results in a KFENCE bug notice.

  BUG: KFENCE: use-after-free read in adf_device_reset_worker+0x38/0xa0 [intel_qat]
  Use-after-free read at 0x00000000bc56fddf (in kfence-#142):
  adf_device_reset_worker+0x38/0xa0 [intel_qat]
  process_one_work+0x173/0x340

To resolve this race condition, the memory associated to the container
of the work_struct is freed on the worker if the timeout expired,
otherwise on the function that schedules the worker.
The timeout detection can be done by checking if the caller is
still waiting for completion or not by using completion_done() function.

Fixes: d8cba25d2c68 ("crypto: qat - Intel(R) QAT driver framework")
Cc: <stable@vger.kernel.org>
Signed-off-by: Damian Muszynski <damian.muszynski@intel.com>
Reviewed-by: Giovanni Cabiddu <giovanni.cabiddu@intel.com>
Signed-off-by: Herbert Xu <herbert@gondor.apana.org.au>

## Buggy Code

```c
// Function: adf_device_reset_worker in drivers/crypto/intel/qat/qat_common/adf_aer.c
static void adf_device_reset_worker(struct work_struct *work)
{
	struct adf_reset_dev_data *reset_data =
		  container_of(work, struct adf_reset_dev_data, reset_work);
	struct adf_accel_dev *accel_dev = reset_data->accel_dev;
	unsigned long wait_jiffies = msecs_to_jiffies(10000);
	struct adf_sriov_dev_data sriov_data;

	adf_dev_restarting_notify(accel_dev);
	if (adf_dev_restart(accel_dev)) {
		/* The device hanged and we can't restart it so stop here */
		dev_err(&GET_DEV(accel_dev), "Restart device failed\n");
		if (reset_data->mode == ADF_DEV_RESET_ASYNC)
			kfree(reset_data);
		WARN(1, "QAT: device restart failed. Device is unusable\n");
		return;
	}

	sriov_data.accel_dev = accel_dev;
	init_completion(&sriov_data.compl);
	INIT_WORK(&sriov_data.sriov_work, adf_device_sriov_worker);
	queue_work(device_sriov_wq, &sriov_data.sriov_work);
	if (wait_for_completion_timeout(&sriov_data.compl, wait_jiffies))
		adf_pf2vf_notify_restarted(accel_dev);

	adf_dev_restarted_notify(accel_dev);
	clear_bit(ADF_STATUS_RESTARTING, &accel_dev->status);

	/* The dev is back alive. Notify the caller if in sync mode */
	if (reset_data->mode == ADF_DEV_RESET_SYNC)
		complete(&reset_data->compl);
	else
		kfree(reset_data);
}
```

```c
// Function: adf_slot_reset in drivers/crypto/intel/qat/qat_common/adf_aer.c
static pci_ers_result_t adf_slot_reset(struct pci_dev *pdev)
{
	struct adf_accel_dev *accel_dev = adf_devmgr_pci_to_accel_dev(pdev);
	int res = 0;

	if (!accel_dev) {
		pr_err("QAT: Can't find acceleration device\n");
		return PCI_ERS_RESULT_DISCONNECT;
	}

	if (!pdev->is_busmaster)
		pci_set_master(pdev);
	pci_restore_state(pdev);
	pci_save_state(pdev);
	res = adf_dev_up(accel_dev, false);
	if (res && res != -EALREADY)
		return PCI_ERS_RESULT_DISCONNECT;

	adf_reenable_sriov(accel_dev);
	adf_pf2vf_notify_restarted(accel_dev);
	adf_dev_restarted_notify(accel_dev);
	clear_bit(ADF_STATUS_RESTARTING, &accel_dev->status);
	return PCI_ERS_RESULT_RECOVERED;
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/crypto/intel/qat/qat_common/adf_aer.c b/drivers/crypto/intel/qat/qat_common/adf_aer.c
index 3597e7605a14..9da2278bd5b7 100644
--- a/drivers/crypto/intel/qat/qat_common/adf_aer.c
+++ b/drivers/crypto/intel/qat/qat_common/adf_aer.c
@@ -130,7 +130,8 @@ static void adf_device_reset_worker(struct work_struct *work)
 	if (adf_dev_restart(accel_dev)) {
 		/* The device hanged and we can't restart it so stop here */
 		dev_err(&GET_DEV(accel_dev), "Restart device failed\n");
-		if (reset_data->mode == ADF_DEV_RESET_ASYNC)
+		if (reset_data->mode == ADF_DEV_RESET_ASYNC ||
+		    completion_done(&reset_data->compl))
 			kfree(reset_data);
 		WARN(1, "QAT: device restart failed. Device is unusable\n");
 		return;
@@ -146,11 +147,19 @@ static void adf_device_reset_worker(struct work_struct *work)
 	adf_dev_restarted_notify(accel_dev);
 	clear_bit(ADF_STATUS_RESTARTING, &accel_dev->status);

-	/* The dev is back alive. Notify the caller if in sync mode */
-	if (reset_data->mode == ADF_DEV_RESET_SYNC)
-		complete(&reset_data->compl);
-	else
+	/*
+	 * The dev is back alive. Notify the caller if in sync mode
+	 *
+	 * If device restart will take a more time than expected,
+	 * the schedule_reset() function can timeout and exit. This can be
+	 * detected by calling the completion_done() function. In this case
+	 * the reset_data structure needs to be freed here.
+	 */
+	if (reset_data->mode == ADF_DEV_RESET_ASYNC ||
+	    completion_done(&reset_data->compl))
 		kfree(reset_data);
+	else
+		complete(&reset_data->compl);
 }

 static int adf_dev_aer_schedule_reset(struct adf_accel_dev *accel_dev,
@@ -183,8 +192,9 @@ static int adf_dev_aer_schedule_reset(struct adf_accel_dev *accel_dev,
 			dev_err(&GET_DEV(accel_dev),
 				"Reset device timeout expired\n");
 			ret = -EFAULT;
+		} else {
+			kfree(reset_data);
 		}
-		kfree(reset_data);
 		return ret;
 	}
 	return 0;
```
