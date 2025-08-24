## Bug Pattern

Using an unbounded string copy (strcpy) into a fixed-size buffer where the source string can exceed the destination’s capacity, e.g.:

char dst[8];
strcpy(dst, src);  // src may be longer than 7 chars + NUL -> overflow

In this case, copying hdev->name into di.name[8] without a length limit can overflow. The fix uses strscpy(dst, src, sizeof(dst)) to bound the copy.
