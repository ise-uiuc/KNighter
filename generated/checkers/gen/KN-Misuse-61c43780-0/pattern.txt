## Bug Pattern

Passing the wrong Netlink command identifier to a message-fill function: using a generic DEVLINK_CMD_NEW instead of the object-specific DEVLINK_CMD_PORT_NEW in dump responses, causing the dump reply’s cmd to be inconsistent with the corresponding get/doit replies and notifications. This copy‑paste mismatch of cmd enums breaks userspace expectations that dump and doit use the same rsp_value.
