## Bug Pattern

Casting an integer to an enumeration type where the integer value does not match any of the enumeration’s defined constant values. This results in producing an out-of-range (or undefined) enum value, which may lead to undefined behavior.