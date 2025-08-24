## Patch Description

arm64/sme: Fix NULL check after kzalloc

Fix following coccicheck error:
./arch/arm64/kernel/process.c:322:2-23: alloc with no test, possible model on line 326

Here should be dst->thread.sve_state.

Fixes: 8bd7f91c03d8 ("arm64/sme: Implement traps and syscall handling for SME")
Signed-off-by: Wan Jiabing <wanjiabing@vivo.com>
Reviwed-by: Mark Brown <broonie@kernel.org>
Link: https://lore.kernel.org/r/20220426113054.630983-1-wanjiabing@vivo.com
Signed-off-by: Catalin Marinas <catalin.marinas@arm.com>

## Buggy Code

```c
// Function: arch_dup_task_struct in arch/arm64/kernel/process.c
int arch_dup_task_struct(struct task_struct *dst, struct task_struct *src)
{
	if (current->mm)
		fpsimd_preserve_current_state();
	*dst = *src;

	/* We rely on the above assignment to initialize dst's thread_flags: */
	BUILD_BUG_ON(!IS_ENABLED(CONFIG_THREAD_INFO_IN_TASK));

	/*
	 * Detach src's sve_state (if any) from dst so that it does not
	 * get erroneously used or freed prematurely.  dst's copies
	 * will be allocated on demand later on if dst uses SVE.
	 * For consistency, also clear TIF_SVE here: this could be done
	 * later in copy_process(), but to avoid tripping up future
	 * maintainers it is best not to leave TIF flags and buffers in
	 * an inconsistent state, even temporarily.
	 */
	dst->thread.sve_state = NULL;
	clear_tsk_thread_flag(dst, TIF_SVE);

	/*
	 * In the unlikely event that we create a new thread with ZA
	 * enabled we should retain the ZA state so duplicate it here.
	 * This may be shortly freed if we exec() or if CLONE_SETTLS
	 * but it's simpler to do it here. To avoid confusing the rest
	 * of the code ensure that we have a sve_state allocated
	 * whenever za_state is allocated.
	 */
	if (thread_za_enabled(&src->thread)) {
		dst->thread.sve_state = kzalloc(sve_state_size(src),
						GFP_KERNEL);
		if (!dst->thread.za_state)
			return -ENOMEM;
		dst->thread.za_state = kmemdup(src->thread.za_state,
					       za_state_size(src),
					       GFP_KERNEL);
		if (!dst->thread.za_state) {
			kfree(dst->thread.sve_state);
			dst->thread.sve_state = NULL;
			return -ENOMEM;
		}
	} else {
		dst->thread.za_state = NULL;
		clear_tsk_thread_flag(dst, TIF_SME);
	}

	/* clear any pending asynchronous tag fault raised by the parent */
	clear_tsk_thread_flag(dst, TIF_MTE_ASYNC_FAULT);

	return 0;
}
```

## Bug Fix Patch

```diff
diff --git a/arch/arm64/kernel/process.c b/arch/arm64/kernel/process.c
index 99c293513817..9734c9fb1a32 100644
--- a/arch/arm64/kernel/process.c
+++ b/arch/arm64/kernel/process.c
@@ -321,7 +321,7 @@ int arch_dup_task_struct(struct task_struct *dst, struct task_struct *src)
 	if (thread_za_enabled(&src->thread)) {
 		dst->thread.sve_state = kzalloc(sve_state_size(src),
 						GFP_KERNEL);
-		if (!dst->thread.za_state)
+		if (!dst->thread.sve_state)
 			return -ENOMEM;
 		dst->thread.za_state = kmemdup(src->thread.za_state,
 					       za_state_size(src),
```
