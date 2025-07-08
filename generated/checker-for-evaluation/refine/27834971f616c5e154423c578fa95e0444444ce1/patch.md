## Patch Description

virt: tdx-guest: Just leak decrypted memory on unrecoverable errors

In CoCo VMs it is possible for the untrusted host to cause
set_memory_decrypted() to fail such that an error is returned
and the resulting memory is shared. Callers need to take care
to handle these errors to avoid returning decrypted (shared)
memory to the page allocator, which could lead to functional
or security issues.

Leak the decrypted memory when set_memory_decrypted() fails,
and don't need to print an error since set_memory_decrypted()
will call WARN_ONCE().

Fixes: f4738f56d1dc ("virt: tdx-guest: Add Quote generation support using TSM_REPORTS")
Signed-off-by: Li RongQing <lirongqing@baidu.com>
Signed-off-by: Dave Hansen <dave.hansen@linux.intel.com>
Signed-off-by: Ingo Molnar <mingo@kernel.org>
Reviewed-by: Rick Edgecombe <rick.p.edgecombe@intel.com>
Reviewed-by: Kirill A. Shutemov <kirill.shutemov@linux.intel.com>
Cc: stable@vger.kernel.org
Link: https://lore.kernel.org/all/20240619111801.25630-1-lirongqing%40baidu.com

## Buggy Code

```c
// drivers/virt/coco/tdx-guest/tdx-guest.c
static void *alloc_quote_buf(void)
{
	size_t len = PAGE_ALIGN(GET_QUOTE_BUF_SIZE);
	unsigned int count = len >> PAGE_SHIFT;
	void *addr;

	addr = alloc_pages_exact(len, GFP_KERNEL | __GFP_ZERO);
	if (!addr)
		return NULL;

	if (set_memory_decrypted((unsigned long)addr, count)) {
		free_pages_exact(addr, len);
		return NULL;
	}

	return addr;
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/virt/coco/tdx-guest/tdx-guest.c b/drivers/virt/coco/tdx-guest/tdx-guest.c
index d7db6c824e13..224e7dde9cde 100644
--- a/drivers/virt/coco/tdx-guest/tdx-guest.c
+++ b/drivers/virt/coco/tdx-guest/tdx-guest.c
@@ -124,10 +124,8 @@ static void *alloc_quote_buf(void)
 	if (!addr)
 		return NULL;
 
-	if (set_memory_decrypted((unsigned long)addr, count)) {
-		free_pages_exact(addr, len);
+	if (set_memory_decrypted((unsigned long)addr, count))
 		return NULL;
-	}
 
 	return addr;
 }
```

