## Patch Description

bcachefs: fix iov_iter count underflow on sub-block dio read

bch2_direct_IO_read() checks the request offset and size for sector
alignment and then falls through to a couple calculations to shrink
the size of the request based on the inode size. The problem is that
these checks round up to the fs block size, which runs the risk of
underflowing iter->count if the block size happens to be large
enough. This is triggered by fstest generic/361 with a 4k block
size, which subsequently leads to a crash. To avoid this crash,
check that the shorten length doesn't exceed the overall length of
the iter.

Fixes:
Signed-off-by: Brian Foster <bfoster@redhat.com>
Reviewed-by: Su Yue <glass.su@suse.com>
Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>

## Buggy Code

```c
// fs/bcachefs/fs-io-direct.c
static int bch2_direct_IO_read(struct kiocb *req, struct iov_iter *iter)
{
	struct file *file = req->ki_filp;
	struct bch_inode_info *inode = file_bch_inode(file);
	struct bch_fs *c = inode->v.i_sb->s_fs_info;
	struct bch_io_opts opts;
	struct dio_read *dio;
	struct bio *bio;
	loff_t offset = req->ki_pos;
	bool sync = is_sync_kiocb(req);
	size_t shorten;
	ssize_t ret;

	bch2_inode_opts_get(&opts, c, &inode->ei_inode);

	/* bios must be 512 byte aligned: */
	if ((offset|iter->count) & (SECTOR_SIZE - 1))
		return -EINVAL;

	ret = min_t(loff_t, iter->count,
		    max_t(loff_t, 0, i_size_read(&inode->v) - offset));

	if (!ret)
		return ret;

	shorten = iov_iter_count(iter) - round_up(ret, block_bytes(c));
	iter->count -= shorten;

	bio = bio_alloc_bioset(NULL,
			       bio_iov_vecs_to_alloc(iter, BIO_MAX_VECS),
			       REQ_OP_READ,
			       GFP_KERNEL,
			       &c->dio_read_bioset);

	bio->bi_end_io = bch2_direct_IO_read_endio;

	dio = container_of(bio, struct dio_read, rbio.bio);
	closure_init(&dio->cl, NULL);

	/*
	 * this is a _really_ horrible hack just to avoid an atomic sub at the
	 * end:
	 */
	if (!sync) {
		set_closure_fn(&dio->cl, bch2_dio_read_complete, NULL);
		atomic_set(&dio->cl.remaining,
			   CLOSURE_REMAINING_INITIALIZER -
			   CLOSURE_RUNNING +
			   CLOSURE_DESTRUCTOR);
	} else {
		atomic_set(&dio->cl.remaining,
			   CLOSURE_REMAINING_INITIALIZER + 1);
		dio->cl.closure_get_happened = true;
	}

	dio->req	= req;
	dio->ret	= ret;
	/*
	 * This is one of the sketchier things I've encountered: we have to skip
	 * the dirtying of requests that are internal from the kernel (i.e. from
	 * loopback), because we'll deadlock on page_lock.
	 */
	dio->should_dirty = iter_is_iovec(iter);

	goto start;
	while (iter->count) {
		bio = bio_alloc_bioset(NULL,
				       bio_iov_vecs_to_alloc(iter, BIO_MAX_VECS),
				       REQ_OP_READ,
				       GFP_KERNEL,
				       &c->bio_read);
		bio->bi_end_io		= bch2_direct_IO_read_split_endio;
start:
		bio->bi_opf		= REQ_OP_READ|REQ_SYNC;
		bio->bi_iter.bi_sector	= offset >> 9;
		bio->bi_private		= dio;

		ret = bio_iov_iter_get_pages(bio, iter);
		if (ret < 0) {
			/* XXX: fault inject this path */
			bio->bi_status = BLK_STS_RESOURCE;
			bio_endio(bio);
			break;
		}

		offset += bio->bi_iter.bi_size;

		if (dio->should_dirty)
			bio_set_pages_dirty(bio);

		if (iter->count)
			closure_get(&dio->cl);

		bch2_read(c, rbio_init(bio, opts), inode_inum(inode));
	}

	iter->count += shorten;

	if (sync) {
		closure_sync(&dio->cl);
		closure_debug_destroy(&dio->cl);
		ret = dio->ret;
		bio_check_or_release(&dio->rbio.bio, dio->should_dirty);
		return ret;
	} else {
		return -EIOCBQUEUED;
	}
}
```

## Bug Fix Patch

```diff
diff --git a/fs/bcachefs/fs-io-direct.c b/fs/bcachefs/fs-io-direct.c
index e3b219e19e10..33cb6da3a5ad 100644
--- a/fs/bcachefs/fs-io-direct.c
+++ b/fs/bcachefs/fs-io-direct.c
@@ -88,6 +88,8 @@ static int bch2_direct_IO_read(struct kiocb *req, struct iov_iter *iter)
 		return ret;
 
 	shorten = iov_iter_count(iter) - round_up(ret, block_bytes(c));
+	if (shorten >= iter->count)
+		shorten = 0;
 	iter->count -= shorten;
 
 	bio = bio_alloc_bioset(NULL,
```

