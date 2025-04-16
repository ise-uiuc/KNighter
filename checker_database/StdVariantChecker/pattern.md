## Bug Pattern

Incorrectly retrieving a value from a std::variant using std::get with a type or index that does not match the variant’s active held type. This pattern occurs when the program assumes the variant holds one type (or is in one state) but in reality it holds another, leading to type mismatches that trigger runtime errors or unexpected behavior.