## Patch Description

smb: client: fix possible double free in smb2_set_ea()

Clang static checker(scan-build) warning：
fs/smb/client/smb2ops.c:1304:2: Attempt to free released memory.
 1304 |         kfree(ea);
      |         ^~~~~~~~~

There is a double free in such case:
'ea is initialized to NULL' -> 'first successful memory allocation for
ea' -> 'something failed, goto sea_exit' -> 'first memory release for ea'
-> 'goto replay_again' -> 'second goto sea_exit before allocate memory
for ea' -> 'second memory release for ea resulted in double free'.

Re-initialie 'ea' to NULL near to the replay_again label, it can fix this
double free problem.

Fixes: 4f1fffa23769 ("cifs: commands that are retried should have replay flag set")
Reviewed-by: Dan Carpenter <dan.carpenter@linaro.org>
Signed-off-by: Su Hui <suhui@nfschina.com>
Signed-off-by: Steve French <stfrench@microsoft.com>

## Buggy Code

```c
// Function: smb2_set_ea in fs/smb/client/smb2ops.c
static int
smb2_set_ea(const unsigned int xid, struct cifs_tcon *tcon,
	    const char *path, const char *ea_name, const void *ea_value,
	    const __u16 ea_value_len, const struct nls_table *nls_codepage,
	    struct cifs_sb_info *cifs_sb)
{
	struct smb2_compound_vars *vars;
	struct cifs_ses *ses = tcon->ses;
	struct TCP_Server_Info *server;
	struct smb_rqst *rqst;
	struct kvec *rsp_iov;
	__le16 *utf16_path = NULL;
	int ea_name_len = strlen(ea_name);
	int flags = CIFS_CP_CREATE_CLOSE_OP;
	int len;
	int resp_buftype[3];
	struct cifs_open_parms oparms;
	__u8 oplock = SMB2_OPLOCK_LEVEL_NONE;
	struct cifs_fid fid;
	unsigned int size[1];
	void *data[1];
	struct smb2_file_full_ea_info *ea = NULL;
	struct smb2_query_info_rsp *rsp;
	int rc, used_len = 0;
	int retries = 0, cur_sleep = 1;

replay_again:
	/* reinitialize for possible replay */
	flags = CIFS_CP_CREATE_CLOSE_OP;
	oplock = SMB2_OPLOCK_LEVEL_NONE;
	server = cifs_pick_channel(ses);

	if (smb3_encryption_required(tcon))
		flags |= CIFS_TRANSFORM_REQ;

	if (ea_name_len > 255)
		return -EINVAL;

	utf16_path = cifs_convert_path_to_utf16(path, cifs_sb);
	if (!utf16_path)
		return -ENOMEM;

	resp_buftype[0] = resp_buftype[1] = resp_buftype[2] = CIFS_NO_BUFFER;
	vars = kzalloc(sizeof(*vars), GFP_KERNEL);
	if (!vars) {
		rc = -ENOMEM;
		goto out_free_path;
	}
	rqst = vars->rqst;
	rsp_iov = vars->rsp_iov;

	if (ses->server->ops->query_all_EAs) {
		if (!ea_value) {
			rc = ses->server->ops->query_all_EAs(xid, tcon, path,
							     ea_name, NULL, 0,
							     cifs_sb);
			if (rc == -ENODATA)
				goto sea_exit;
		} else {
			/* If we are adding a attribute we should first check
			 * if there will be enough space available to store
			 * the new EA. If not we should not add it since we
			 * would not be able to even read the EAs back.
			 */
			rc = smb2_query_info_compound(xid, tcon, path,
				      FILE_READ_EA,
				      FILE_FULL_EA_INFORMATION,
				      SMB2_O_INFO_FILE,
				      CIFSMaxBufSize -
				      MAX_SMB2_CREATE_RESPONSE_SIZE -
				      MAX_SMB2_CLOSE_RESPONSE_SIZE,
				      &rsp_iov[1], &resp_buftype[1], cifs_sb);
			if (rc == 0) {
				rsp = (struct smb2_query_info_rsp *)rsp_iov[1].iov_base;
				used_len = le32_to_cpu(rsp->OutputBufferLength);
			}
			free_rsp_buf(resp_buftype[1], rsp_iov[1].iov_base);
			resp_buftype[1] = CIFS_NO_BUFFER;
			memset(&rsp_iov[1], 0, sizeof(rsp_iov[1]));
			rc = 0;

			/* Use a fudge factor of 256 bytes in case we collide
			 * with a different set_EAs command.
			 */
			if (CIFSMaxBufSize - MAX_SMB2_CREATE_RESPONSE_SIZE -
			   MAX_SMB2_CLOSE_RESPONSE_SIZE - 256 <
			   used_len + ea_name_len + ea_value_len + 1) {
				rc = -ENOSPC;
				goto sea_exit;
			}
		}
	}

	/* Open */
	rqst[0].rq_iov = vars->open_iov;
	rqst[0].rq_nvec = SMB2_CREATE_IOV_SIZE;

	oparms = (struct cifs_open_parms) {
		.tcon = tcon,
		.path = path,
		.desired_access = FILE_WRITE_EA,
		.disposition = FILE_OPEN,
		.create_options = cifs_create_options(cifs_sb, 0),
		.fid = &fid,
		.replay = !!(retries),
	};

	rc = SMB2_open_init(tcon, server,
			    &rqst[0], &oplock, &oparms, utf16_path);
	if (rc)
		goto sea_exit;
	smb2_set_next_command(tcon, &rqst[0]);


	/* Set Info */
	rqst[1].rq_iov = vars->si_iov;
	rqst[1].rq_nvec = 1;

	len = sizeof(*ea) + ea_name_len + ea_value_len + 1;
	ea = kzalloc(len, GFP_KERNEL);
	if (ea == NULL) {
		rc = -ENOMEM;
		goto sea_exit;
	}

	ea->ea_name_length = ea_name_len;
	ea->ea_value_length = cpu_to_le16(ea_value_len);
	memcpy(ea->ea_data, ea_name, ea_name_len + 1);
	memcpy(ea->ea_data + ea_name_len + 1, ea_value, ea_value_len);

	size[0] = len;
	data[0] = ea;

	rc = SMB2_set_info_init(tcon, server,
				&rqst[1], COMPOUND_FID,
				COMPOUND_FID, current->tgid,
				FILE_FULL_EA_INFORMATION,
				SMB2_O_INFO_FILE, 0, data, size);
	if (rc)
		goto sea_exit;
	smb2_set_next_command(tcon, &rqst[1]);
	smb2_set_related(&rqst[1]);

	/* Close */
	rqst[2].rq_iov = &vars->close_iov;
	rqst[2].rq_nvec = 1;
	rc = SMB2_close_init(tcon, server,
			     &rqst[2], COMPOUND_FID, COMPOUND_FID, false);
	if (rc)
		goto sea_exit;
	smb2_set_related(&rqst[2]);

	if (retries) {
		smb2_set_replay(server, &rqst[0]);
		smb2_set_replay(server, &rqst[1]);
		smb2_set_replay(server, &rqst[2]);
	}

	rc = compound_send_recv(xid, ses, server,
				flags, 3, rqst,
				resp_buftype, rsp_iov);
	/* no need to bump num_remote_opens because handle immediately closed */

 sea_exit:
	kfree(ea);
	SMB2_open_free(&rqst[0]);
	SMB2_set_info_free(&rqst[1]);
	SMB2_close_free(&rqst[2]);
	free_rsp_buf(resp_buftype[0], rsp_iov[0].iov_base);
	free_rsp_buf(resp_buftype[1], rsp_iov[1].iov_base);
	free_rsp_buf(resp_buftype[2], rsp_iov[2].iov_base);
	kfree(vars);
out_free_path:
	kfree(utf16_path);

	if (is_replayable_error(rc) &&
	    smb2_should_replay(tcon, &retries, &cur_sleep))
		goto replay_again;

	return rc;
}
```

## Bug Fix Patch

```diff
diff --git a/fs/smb/client/smb2ops.c b/fs/smb/client/smb2ops.c
index 6b385fce3f2a..24a2aa04a108 100644
--- a/fs/smb/client/smb2ops.c
+++ b/fs/smb/client/smb2ops.c
@@ -1158,7 +1158,7 @@ smb2_set_ea(const unsigned int xid, struct cifs_tcon *tcon,
 	struct cifs_fid fid;
 	unsigned int size[1];
 	void *data[1];
-	struct smb2_file_full_ea_info *ea = NULL;
+	struct smb2_file_full_ea_info *ea;
 	struct smb2_query_info_rsp *rsp;
 	int rc, used_len = 0;
 	int retries = 0, cur_sleep = 1;
@@ -1179,6 +1179,7 @@ smb2_set_ea(const unsigned int xid, struct cifs_tcon *tcon,
 	if (!utf16_path)
 		return -ENOMEM;

+	ea = NULL;
 	resp_buftype[0] = resp_buftype[1] = resp_buftype[2] = CIFS_NO_BUFFER;
 	vars = kzalloc(sizeof(*vars), GFP_KERNEL);
 	if (!vars) {
```
