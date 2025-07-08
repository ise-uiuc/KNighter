## Bug Pattern

A copy-paste error caused the wrong hard-coded command constant to be used. This pattern occurs when a developer reuses code for a similar functionality but mistakenly leaves an incorrect constant value (here, DEVLINK_CMD_NEW instead of the correct DEVLINK_CMD_PORT_NEW), leading to inconsistent behavior between commands.