```
## Bug Pattern

Using iterator arithmetic (increment, decrement, or random-access modifications) that results in an iterator pointing outside the valid range (either past-the-end or before the beginning of a container) and then dereferencing or otherwise using that invalid iterator. This bug pattern involves performing operations on STL iterators without ensuring that the resulting iterator remains within the correct container bounds, which can lead to undefined behavior.
```