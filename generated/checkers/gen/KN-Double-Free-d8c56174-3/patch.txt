## Patch Description

net/mlx5: HWS, fixed double-free in error flow of creating SQ

When SQ creation fails, call the appropriate mlx5_core destroy function.

This fixes the following smatch warnings:
  divers/net/ethernet/mellanox/mlx5/core/steering/hws/mlx5hws_send.c:739
    hws_send_ring_open_sq() warn: 'sq->dep_wqe' double freed
    hws_send_ring_open_sq() warn: 'sq->wq_ctrl.buf.frags' double freed
    hws_send_ring_open_sq() warn: 'sq->wr_priv' double freed

Fixes: 2ca62599aa0b ("net/mlx5: HWS, added send engine and context handling")
Reported-by: Dan Carpenter <dan.carpenter@linaro.org>
Closes: https://lore.kernel.org/all/e4ebc227-4b25-49bf-9e4c-14b7ea5c6a07@stanley.mountain/
Signed-off-by: Yevgeny Kliteynik <kliteyn@nvidia.com>
Signed-off-by: Saeed Mahameed <saeedm@nvidia.com>

## Buggy Code

```c
// Function: hws_send_ring_create_sq in drivers/net/ethernet/mellanox/mlx5/core/steering/hws/mlx5hws_send.c
static int hws_send_ring_create_sq(struct mlx5_core_dev *mdev, u32 pdn,
				   void *sqc_data,
				   struct mlx5hws_send_engine *queue,
				   struct mlx5hws_send_ring_sq *sq,
				   struct mlx5hws_send_ring_cq *cq)
{
	void *in, *sqc, *wq;
	int inlen, err;
	u8 ts_format;

	inlen = MLX5_ST_SZ_BYTES(create_sq_in) +
		sizeof(u64) * sq->wq_ctrl.buf.npages;
	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	sqc = MLX5_ADDR_OF(create_sq_in, in, ctx);
	wq = MLX5_ADDR_OF(sqc, sqc, wq);

	memcpy(sqc, sqc_data, MLX5_ST_SZ_BYTES(sqc));
	MLX5_SET(sqc, sqc, cqn, cq->mcq.cqn);

	MLX5_SET(sqc, sqc, state, MLX5_SQC_STATE_RST);
	MLX5_SET(sqc, sqc, flush_in_error_en, 1);

	ts_format = mlx5_is_real_time_sq(mdev) ? MLX5_TIMESTAMP_FORMAT_REAL_TIME :
						 MLX5_TIMESTAMP_FORMAT_FREE_RUNNING;
	MLX5_SET(sqc, sqc, ts_format, ts_format);

	MLX5_SET(wq, wq, wq_type, MLX5_WQ_TYPE_CYCLIC);
	MLX5_SET(wq, wq, uar_page, mdev->mlx5e_res.hw_objs.bfreg.index);
	MLX5_SET(wq, wq, log_wq_pg_sz, sq->wq_ctrl.buf.page_shift - MLX5_ADAPTER_PAGE_SHIFT);
	MLX5_SET64(wq, wq, dbr_addr, sq->wq_ctrl.db.dma);

	mlx5_fill_page_frag_array(&sq->wq_ctrl.buf,
				  (__be64 *)MLX5_ADDR_OF(wq, wq, pas));

	err = mlx5_core_create_sq(mdev, in, inlen, &sq->sqn);

	kvfree(in);

	return err;
}
```

## Bug Fix Patch

```diff
diff --git a/drivers/net/ethernet/mellanox/mlx5/core/steering/hws/mlx5hws_send.c b/drivers/net/ethernet/mellanox/mlx5/core/steering/hws/mlx5hws_send.c
index a1adbb48735c..0c7989184c30 100644
--- a/drivers/net/ethernet/mellanox/mlx5/core/steering/hws/mlx5hws_send.c
+++ b/drivers/net/ethernet/mellanox/mlx5/core/steering/hws/mlx5hws_send.c
@@ -653,6 +653,12 @@ static int hws_send_ring_create_sq(struct mlx5_core_dev *mdev, u32 pdn,
 	return err;
 }

+static void hws_send_ring_destroy_sq(struct mlx5_core_dev *mdev,
+				     struct mlx5hws_send_ring_sq *sq)
+{
+	mlx5_core_destroy_sq(mdev, sq->sqn);
+}
+
 static int hws_send_ring_set_sq_rdy(struct mlx5_core_dev *mdev, u32 sqn)
 {
 	void *in, *sqc;
@@ -696,7 +702,7 @@ static int hws_send_ring_create_sq_rdy(struct mlx5_core_dev *mdev, u32 pdn,

 	err = hws_send_ring_set_sq_rdy(mdev, sq->sqn);
 	if (err)
-		hws_send_ring_close_sq(sq);
+		hws_send_ring_destroy_sq(mdev, sq);

 	return err;
 }
```
