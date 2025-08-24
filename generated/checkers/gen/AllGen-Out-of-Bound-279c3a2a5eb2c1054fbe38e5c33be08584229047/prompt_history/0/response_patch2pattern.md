## Bug Pattern

Off-by-one bounds check on an array index: using “> MAX” instead of “>= MAX” when MAX denotes the count/size (valid indices are 0..MAX-1). This allows index == MAX to pass validation and be used to index arrays (e.g., thresholds[MAX]), causing out-of-bounds access.

Wrong:
if (idx > MAX)
    return -EINVAL;

Right:
if (idx >= MAX)
    return -EINVAL;
