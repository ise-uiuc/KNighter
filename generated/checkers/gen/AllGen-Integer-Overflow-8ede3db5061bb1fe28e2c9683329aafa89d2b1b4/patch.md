## Patch Description

io_uring/net: fix overflow check in io_recvmsg_mshot_prep()

The "controllen" variable is type size_t (unsigned long).  Casting it
to int could lead to an integer underflow.

The check_add_overflow() function considers the type of the destination
which is type int.  If we add two positive values and the result cannot
fit in an integer then that's counted as an overflow.

However, if we cast "controllen" to an int and it turns negative, then
negative values *can* fit into an int type so there is no overflow.

Good: 100 + (unsigned long)-4 = 96  <-- overflow
 Bad: 100 + (int)-4 = 96 <-- no overflow

I deleted the cast of the sizeof() as well.  That's not a bug but the
cast is unnecessary.

Fixes: 9b0fc3c054ff ("io_uring: fix types in io_recvmsg_multishot_overflow")
Signed-off-by: Dan Carpenter <dan.carpenter@linaro.org>
Link: https://lore.kernel.org/r/138bd2e2-ede8-4bcc-aa7b-f3d9de167a37@moroto.mountain
Signed-off-by: Jens Axboe <axboe@kernel.dk>

## Buggy Code

```c
// Function: io_recvmsg_mshot_prep in io_uring/net.c
static int io_recvmsg_mshot_prep(struct io_kiocb *req,
				 struct io_async_msghdr *iomsg,
				 int namelen, size_t controllen)
{
	if ((req->flags & (REQ_F_APOLL_MULTISHOT|REQ_F_BUFFER_SELECT)) ==
			  (REQ_F_APOLL_MULTISHOT|REQ_F_BUFFER_SELECT)) {
		int hdr;

		if (unlikely(namelen < 0))
			return -EOVERFLOW;
		if (check_add_overflow((int)sizeof(struct io_uring_recvmsg_out),
					namelen, &hdr))
			return -EOVERFLOW;
		if (check_add_overflow(hdr, (int)controllen, &hdr))
			return -EOVERFLOW;

		iomsg->namelen = namelen;
		iomsg->controllen = controllen;
		return 0;
	}

	return 0;
}
```

## Bug Fix Patch

```diff
diff --git a/io_uring/net.c b/io_uring/net.c
index 40d4542bfe2a..1640e985cd08 100644
--- a/io_uring/net.c
+++ b/io_uring/net.c
@@ -559,10 +559,10 @@ static int io_recvmsg_mshot_prep(struct io_kiocb *req,

 		if (unlikely(namelen < 0))
 			return -EOVERFLOW;
-		if (check_add_overflow((int)sizeof(struct io_uring_recvmsg_out),
+		if (check_add_overflow(sizeof(struct io_uring_recvmsg_out),
 					namelen, &hdr))
 			return -EOVERFLOW;
-		if (check_add_overflow(hdr, (int)controllen, &hdr))
+		if (check_add_overflow(hdr, controllen, &hdr))
 			return -EOVERFLOW;

 		iomsg->namelen = namelen;
```
