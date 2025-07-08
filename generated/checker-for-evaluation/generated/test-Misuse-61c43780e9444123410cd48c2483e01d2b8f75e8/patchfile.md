## Patch Description

devlink: fix port dump cmd type

Unlike other commands, due to a c&p error, port dump fills-up cmd with
wrong value, different from port-get request cmd, port-get doit reply
and port notification.

Fix it by filling cmd with value DEVLINK_CMD_PORT_NEW.

Skimmed through devlink userspace implementations, none of them cares
about this cmd value. Only ynl, for which, this is actually a fix, as it
expects doit and dumpit ops rsp_value to be the same.

Omit the fixes tag, even thought this is fix, better to target this for
next release.

Fixes: bfcd3a466172 ("Introduce devlink infrastructure")
Signed-off-by: Jiri Pirko <jiri@nvidia.com>
Reviewed-by: Simon Horman <horms@kernel.org>
Reviewed-by: Jakub Kicinski <kuba@kernel.org>
Link: https://lore.kernel.org/r/20240220075245.75416-1-jiri@resnulli.us
Signed-off-by: Jakub Kicinski <kuba@kernel.org>

## Buggy Code

```c
// net/devlink/port.c
static int
devlink_nl_port_get_dump_one(struct sk_buff *msg, struct devlink *devlink,
			     struct netlink_callback *cb, int flags)
{
	struct devlink_nl_dump_state *state = devlink_dump_state(cb);
	struct devlink_port *devlink_port;
	unsigned long port_index;
	int err = 0;

	xa_for_each_start(&devlink->ports, port_index, devlink_port, state->idx) {
		err = devlink_nl_port_fill(msg, devlink_port,
					   DEVLINK_CMD_NEW,
					   NETLINK_CB(cb->skb).portid,
					   cb->nlh->nlmsg_seq, flags,
					   cb->extack);
		if (err) {
			state->idx = port_index;
			break;
		}
	}

	return err;
}
```

## Bug Fix Patch

```diff
diff --git a/net/devlink/port.c b/net/devlink/port.c
index 78592912f657..4b2d46ccfe48 100644
--- a/net/devlink/port.c
+++ b/net/devlink/port.c
@@ -583,7 +583,7 @@ devlink_nl_port_get_dump_one(struct sk_buff *msg, struct devlink *devlink,
 
 	xa_for_each_start(&devlink->ports, port_index, devlink_port, state->idx) {
 		err = devlink_nl_port_fill(msg, devlink_port,
-					   DEVLINK_CMD_NEW,
+					   DEVLINK_CMD_PORT_NEW,
 					   NETLINK_CB(cb->skb).portid,
 					   cb->nlh->nlmsg_seq, flags,
 					   cb->extack);
```

