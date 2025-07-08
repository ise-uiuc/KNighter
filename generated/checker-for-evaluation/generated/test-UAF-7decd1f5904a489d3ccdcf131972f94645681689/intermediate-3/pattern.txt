## Bug Pattern

The pattern is a use-after-free caused by accessing a field from an object after it has been logically released. In this case, the code updates the variable “removed” by reading subflow->request_join after calling mptcp_close_ssk(), a function that ultimately frees or invalidates the subflow. The correct approach is to fetch any necessary data from the object before it is released.