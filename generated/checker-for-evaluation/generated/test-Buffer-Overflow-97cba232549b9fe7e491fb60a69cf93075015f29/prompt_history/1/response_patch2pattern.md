## Bug Pattern

A loop iterates over an array and then uses an offset (i+1) without adjusting the loop bounds. This can cause an out-of-bounds access when the loop reaches the final element, leading to memory corruption (buffer overflow). The bug arises from not subtracting the necessary offset from the loop’s terminating condition.