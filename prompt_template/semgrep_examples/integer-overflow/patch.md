## Patch Description

update version of lazy_bdecode from libtorrent

## Buggy Code

```c
// Complete file: lazy_entry.hpp (tree-sitter fallback)
/*

Copyright (c) 2003-2012, Arvid Norberg
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the distribution.
    * Neither the name of the author nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

*/

#ifndef TORRENT_LAZY_ENTRY_HPP_INCLUDED
#define TORRENT_LAZY_ENTRY_HPP_INCLUDED

#include <utility>
#include <vector>
#include <string>
#include <cstring>
#include <boost/system/error_code.hpp>

#define TORRENT_EXPORT
#define TORRENT_EXTRA_EXPORT
#define TORRENT_ASSERT(x) assert(x)

namespace libtorrent
{
	using boost::system::error_code;

	struct lazy_entry;

	// This function decodes bencoded_ data.
	// 
	// .. _bencoded: http://wiki.theory.org/index.php/BitTorrentSpecification
	// 
	// Whenever possible, ``lazy_bdecode()`` should be preferred over ``bdecode()``.
	// It is more efficient and more secure. It supports having constraints on the
	// amount of memory is consumed by the parser.
	// 
	// *lazy* refers to the fact that it doesn't copy any actual data out of the
	// bencoded buffer. It builds a tree of ``lazy_entry`` which has pointers into
	// the bencoded buffer. This makes it very fast and efficient. On top of that,
	// it is not recursive, which saves a lot of stack space when parsing deeply
	// nested trees. However, in order to protect against potential attacks, the
	// ``depth_limit`` and ``item_limit`` control how many levels deep the tree is
	// allowed to get. With recursive parser, a few thousand levels would be enough
	// to exhaust the threads stack and terminate the process. The ``item_limit``
	// protects against very large structures, not necessarily deep. Each bencoded
	// item in the structure causes the parser to allocate some amount of memory,
	// this memory is constant regardless of how much data actually is stored in
	// the item. One potential attack is to create a bencoded list of hundreds of
	// thousands empty strings, which would cause the parser to allocate a significant
	// amount of memory, perhaps more than is available on the machine, and effectively
	// provide a denial of service. The default item limit is set as a reasonable
	// upper limit for desktop computers. Very few torrents have more items in them.
	// The limit corresponds to about 25 MB, which might be a bit much for embedded
	// systems.
	// 
	// ``start`` and ``end`` defines the bencoded buffer to be decoded. ``ret`` is
	// the ``lazy_entry`` which is filled in with the whole decoded tree. ``ec``
	// is a reference to an ``error_code`` which is set to describe the error encountered
	// in case the function fails. ``error_pos`` is an optional pointer to an int,
	// which will be set to the byte offset into the buffer where an error occurred,
	// in case the function fails.
	TORRENT_EXPORT int lazy_bdecode(char const* start, char const* end
		, lazy_entry& ret, error_code& ec, int* error_pos = 0
		, int depth_limit = 1000, int item_limit = 1000000);

	// this is a string that is not NULL-terminated. Instead it
	// comes with a length, specified in bytes. This is particularly
	// useful when parsing bencoded structures, because strings are
	// not NULL-terminated internally, and requiring NULL termination
	// would require copying the string.
	//
	// see lazy_entry::string_pstr().
	struct TORRENT_EXPORT pascal_string
	{
		// construct a string pointing to the characters at ``p``
		// of length ``l`` characters. No NULL termination is required.
		pascal_string(char const* p, int l): len(l), ptr(p) {}
		
		// the number of characters in the string.
		int len;

		// the pointer to the first character in the string. This is
		// not NULL terminated, but instead consult the ``len`` field
		// to know how many characters follow.
		char const* ptr;

		// lexicographical comparison of strings. Order is consisten
		// with memcmp.
		bool operator<(pascal_string const& rhs) const
		{
			return std::memcmp(ptr, rhs.ptr, (std::min)(len, rhs.len)) < 0
				|| len < rhs.len;
		}
	};

	struct lazy_dict_entry;

	// this object represent a node in a bencoded structure. It is a variant
	// type whose concrete type is one of:
	//
	// 1. dictionary (maps strings -> lazy_entry)
	// 2. list (sequence of lazy_entry, i.e. heterogenous)
	// 3. integer
	// 4. string
	//
	// There is also a ``none`` type, which is used for uninitialized
	// lazy_entries.
	struct TORRENT_EXPORT lazy_entry
	{
		// The different types a lazy_entry can have
		enum entry_type_t
		{
			none_t, dict_t, list_t, string_t, int_t
		};

		lazy_entry() : m_begin(0), m_len(0), m_size(0), m_capacity(0), m_type(none_t)
		{ m_data.start = 0; }

		// tells you which specific type this lazy entry has.
		// See entry_type_t. The type determines which subset of
		// member functions are valid to use.
		entry_type_t type() const { return (entry_type_t)m_type; }

		// start points to the first decimal digit
		// length is the number of digits
		void construct_int(char const* start, int length)
		{
			TORRENT_ASSERT(m_type == none_t);
			m_type = int_t;
			m_data.start = start;
			m_size = length;
			m_begin = start - 1; // include 'i'
			m_len = length + 2; // include 'e'
		}

		// if this is an integer, return the integer value
		boost::int64_t int_value() const;

		// internal
		void construct_string(char const* start, int length);

		// the string is not null-terminated!
		// use string_length() to determine how many bytes
		// are part of the string.
		char const* string_ptr() const
		{
			TORRENT_ASSERT(m_type == string_t);
			return m_data.start;
		}

		// this will return a null terminated string
		// it will write to the source buffer!
		char const* string_cstr() const
		{
			TORRENT_ASSERT(m_type == string_t);
			const_cast<char*>(m_data.start)[m_size] = 0;
			return m_data.start;
		}

		// if this is a string, returns a pascal_string
		// representing the string value.
		pascal_string string_pstr() const
		{
			TORRENT_ASSERT(m_type == string_t);
			return pascal_string(m_data.start, m_size);
		}

		// if this is a string, returns the string as a std::string.
		// (which requires a copy)
		std::string string_value() const
		{
			TORRENT_ASSERT(m_type == string_t);
			return std::string(m_data.start, m_size);
		}

		// if the lazy_entry is a string, returns the
		// length of the string, in bytes.
		int string_length() const
		{ return m_size; }

		// internal
		void construct_dict(char const* begin)
		{
			TORRENT_ASSERT(m_type == none_t);
			m_type = dict_t;
			m_size = 0;
			m_capacity = 0;
			m_begin = begin;
		}

		// internal
		lazy_entry* dict_append(char const* name);
		// internal
		void pop();

		// if this is a dictionary, look for a key ``name``, and return
		// a pointer to its value, or NULL if there is none.
		lazy_entry* dict_find(char const* name);
		lazy_entry const* dict_find(char const* name) const
		{ return const_cast<lazy_entry*>(this)->dict_find(name); }
		lazy_entry const* dict_find_string(char const* name) const;

		// if this is a dictionary, look for a key ``name`` whose value
		// is a string. If such key exist, return a pointer to
		// its value, otherwise NULL.
		std::string dict_find_string_value(char const* name) const;
		pascal_string dict_find_pstr(char const* name) const;

		// if this is a dictionary, look for a key ``name`` whose value
		// is an int. If such key exist, return a pointer to its value,
		// otherwise NULL.
		boost::int64_t dict_find_int_value(char const* name, boost::int64_t default_val = 0) const;
		lazy_entry const* dict_find_int(char const* name) const;

		lazy_entry const* dict_find_dict(char const* name) const;
		lazy_entry const* dict_find_list(char const* name) const;

		// if this is a dictionary, return the key value pair at
		// position ``i`` from the dictionary.
		std::pair<std::string, lazy_entry const*> dict_at(int i) const;

		// if this is a dictionary, return the number of items in it
		int dict_size() const
		{
			TORRENT_ASSERT(m_type == dict_t);
			return m_size;
		}

		// internal
		void construct_list(char const* begin)
		{
			TORRENT_ASSERT(m_type == none_t);
			m_type = list_t;
			m_size = 0;
			m_capacity = 0;
			m_begin = begin;
		}

		// internal
		lazy_entry* list_append();

		// if this is a list, return the item at index ``i``.
		lazy_entry* list_at(int i)
		{
			TORRENT_ASSERT(m_type == list_t);
			TORRENT_ASSERT(i < int(m_size));
			return &m_data.list[i];
		}
		lazy_entry const* list_at(int i) const
		{ return const_cast<lazy_entry*>(this)->list_at(i); }

		std::string list_string_value_at(int i) const;
		pascal_string list_pstr_at(int i) const;
		boost::int64_t list_int_value_at(int i, boost::int64_t default_val = 0) const;

		// if this is a list, return the number of items in it.
		int list_size() const
		{
			TORRENT_ASSERT(m_type == list_t);
			return int(m_size);
		}

		// end points one byte passed last byte in the source
		// buffer backing the bencoded structure.
		void set_end(char const* end)
		{
			TORRENT_ASSERT(end > m_begin);
			m_len = end - m_begin;
		}
		
		// internal
		void clear();

		// releases ownership of any memory allocated
		void release()
		{
			m_data.start = 0;
			m_size = 0;
			m_capacity = 0;
			m_type = none_t;
		}

		// internal
		~lazy_entry()
		{ clear(); }

		// returns pointers into the source buffer where
		// this entry has its bencoded data
		std::pair<char const*, int> data_section() const;

		// swap values of ``this`` and ``e``.
		void swap(lazy_entry& e)
		{
			using std::swap;
			boost::uint32_t tmp = e.m_type;
			e.m_type = m_type;
			m_type = tmp;
			tmp = e.m_capacity;
			e.m_capacity = m_capacity;
			m_capacity = tmp;
			swap(m_data.start, e.m_data.start);
			swap(m_size, e.m_size);
			swap(m_begin, e.m_begin);
			swap(m_len, e.m_len);
		}

	private:

		union data_t
		{
			lazy_dict_entry* dict;
			lazy_entry* list;
			char const* start;
		} m_data;

		// used for dictionaries and lists to record the range
		// in the original buffer they are based on
		char const* m_begin;
		// the number of bytes this entry extends in the
		// bencoded byffer
		boost::uint32_t m_len;

		// if list or dictionary, the number of items
		boost::uint32_t m_size;
		// if list or dictionary, allocated number of items
		boost::uint32_t m_capacity:29;
		// element type (dict, list, int, string)
		boost::uint32_t m_type:3;

		// non-copyable
		lazy_entry(lazy_entry const&);
		lazy_entry const& operator=(lazy_entry const&);
	};

	struct lazy_dict_entry
	{
		char const* name;
		lazy_entry val;
	};

	TORRENT_EXTRA_EXPORT std::string print_entry(lazy_entry const& e
		, bool single_line = false, int indent = 0);

	TORRENT_EXPORT boost::system::error_category& get_bdecode_category();

	namespace bdecode_errors
	{
		// libtorrent uses boost.system's ``error_code`` class to represent errors. libtorrent has
		// its own error category get_bdecode_category() whith the error codes defined by error_code_enum.
		enum error_code_enum
		{
			// Not an error
			no_error = 0,
			// expected string in bencoded string
			expected_string,
			// expected colon in bencoded string
			expected_colon,
			// unexpected end of file in bencoded string
			unexpected_eof,
			// expected value (list, dict, int or string) in bencoded string
			expected_value,
			// bencoded recursion depth limit exceeded
			depth_exceeded,
			// bencoded item count limit exceeded
			limit_exceeded,

			// the number of error codes
			error_code_max
		};

		// hidden
		inline boost::system::error_code make_error_code(error_code_enum e)
		{
			return boost::system::error_code(e, get_bdecode_category());
		}
	}
}

#endif

```

```c
// Complete file: lazy_bdecode.cpp (tree-sitter fallback)
/*

Copyright (c) 2008-2012, Arvid Norberg
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the distribution.
    * Neither the name of the author nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

*/

#include "lazy_entry.hpp"
#include <cstring>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

namespace
{
	const int lazy_entry_grow_factor = 150; // percent
	const int lazy_entry_dict_init = 5;
	const int lazy_entry_list_init = 5;
}

namespace libtorrent
{

#define TORRENT_FAIL_BDECODE(code) \
	{ \
		ec = make_error_code(code); \
		while (!stack.empty()) { \
			top = stack.back(); \
			if (top->type() == lazy_entry::dict_t || top->type() == lazy_entry::list_t) top->pop(); \
			stack.pop_back(); \
		} \
		if (error_pos) *error_pos = start - orig_start; \
		return -1; \
	}

	bool is_digit(char c) { return c >= '0' && c <= '9'; }

	bool is_print(char c) { return c >= 32 && c < 127; }

	// fills in 'val' with what the string between start and the
	// first occurance of the delimiter is interpreted as an int.
	// return the pointer to the delimiter, or 0 if there is a
	// parse error. val should be initialized to zero
	char const* parse_int(char const* start, char const* end, char delimiter, boost::int64_t& val)
	{
		while (start < end && *start != delimiter)
		{
			if (!is_digit(*start)) { return 0; }
			val *= 10;
			val += *start - '0';
			++start;
		}
		return start;
	}

	char const* find_char(char const* start, char const* end, char delimiter)
	{
		while (start < end && *start != delimiter) ++start;
		return start;
	}

	// return 0 = success
	int lazy_bdecode(char const* start, char const* end, lazy_entry& ret
		, error_code& ec, int* error_pos, int depth_limit, int item_limit)
	{
		char const* const orig_start = start;
		ret.clear();
		if (start == end) return 0;

		std::vector<lazy_entry*> stack;

		stack.push_back(&ret);
		while (start < end)
		{
			if (stack.empty()) break; // done!

			lazy_entry* top = stack.back();

			if (int(stack.size()) > depth_limit) TORRENT_FAIL_BDECODE(bdecode_errors::depth_exceeded);
			if (start >= end) TORRENT_FAIL_BDECODE(bdecode_errors::unexpected_eof);
			char t = *start;
			++start;
			if (start >= end && t != 'e') TORRENT_FAIL_BDECODE(bdecode_errors::unexpected_eof);

			switch (top->type())
			{
				case lazy_entry::dict_t:
				{
					if (t == 'e')
					{
						top->set_end(start);
						stack.pop_back();
						continue;
					}
					if (!is_digit(t)) TORRENT_FAIL_BDECODE(bdecode_errors::expected_string);
					boost::int64_t len = t - '0';
					start = parse_int(start, end, ':', len);
					if (start == 0 || start + len + 3 > end || *start != ':')
						TORRENT_FAIL_BDECODE(bdecode_errors::expected_colon);
					++start;
					if (start == end) TORRENT_FAIL_BDECODE(bdecode_errors::unexpected_eof);
					lazy_entry* ent = top->dict_append(start);
					if (ent == 0) TORRENT_FAIL_BDECODE(boost::system::errc::not_enough_memory);
					start += len;
					if (start >= end) TORRENT_FAIL_BDECODE(bdecode_errors::unexpected_eof);
					stack.push_back(ent);
					t = *start;
					++start;
					break;
				}
				case lazy_entry::list_t:
				{
					if (t == 'e')
					{
						top->set_end(start);
						stack.pop_back();
						continue;
					}
					lazy_entry* ent = top->list_append();
					if (ent == 0) TORRENT_FAIL_BDECODE(boost::system::errc::not_enough_memory);
					stack.push_back(ent);
					break;
				}
				default: break;
			}

			--item_limit;
			if (item_limit <= 0) TORRENT_FAIL_BDECODE(bdecode_errors::limit_exceeded);

			top = stack.back();
			switch (t)
			{
				case 'd':
					top->construct_dict(start - 1);
					continue;
				case 'l':
					top->construct_list(start - 1);
					continue;
				case 'i':
				{
					char const* int_start = start;
					start = find_char(start, end, 'e');
					top->construct_int(int_start, start - int_start);
					if (start == end) TORRENT_FAIL_BDECODE(bdecode_errors::unexpected_eof);
					TORRENT_ASSERT(*start == 'e');
					++start;
					stack.pop_back();
					continue;
				}
				default:
				{
					if (!is_digit(t))
						TORRENT_FAIL_BDECODE(bdecode_errors::expected_value);

					boost::int64_t len = t - '0';
					start = parse_int(start, end, ':', len);
					if (start == 0 || start + len + 1 > end || *start != ':')
						TORRENT_FAIL_BDECODE(bdecode_errors::expected_colon);
					++start;
					top->construct_string(start, int(len));
					stack.pop_back();
					start += len;
					continue;
				}
			}
			return 0;
		}
		return 0;
	}

	boost::int64_t lazy_entry::int_value() const
	{
		TORRENT_ASSERT(m_type == int_t);
		boost::int64_t val = 0;
		bool negative = false;
		if (*m_data.start == '-') negative = true;
		parse_int(negative?m_data.start+1:m_data.start, m_data.start + m_size, 'e', val);
		if (negative) val = -val;
		return val;
	}

	lazy_entry* lazy_entry::dict_append(char const* name)
	{
		TORRENT_ASSERT(m_type == dict_t);
		TORRENT_ASSERT(m_size <= m_capacity);
		if (m_capacity == 0)
		{
			int capacity = lazy_entry_dict_init;
			m_data.dict = new (std::nothrow) lazy_dict_entry[capacity];
			if (m_data.dict == 0) return 0;
			m_capacity = capacity;
		}
		else if (m_size == m_capacity)
		{
			int capacity = m_capacity * lazy_entry_grow_factor / 100;
			lazy_dict_entry* tmp = new (std::nothrow) lazy_dict_entry[capacity];
			if (tmp == 0) return 0;
			std::memcpy(tmp, m_data.dict, sizeof(lazy_dict_entry) * m_size);
			for (int i = 0; i < int(m_size); ++i) m_data.dict[i].val.release();
			delete[] m_data.dict;
			m_data.dict = tmp;
			m_capacity = capacity;
		}

		TORRENT_ASSERT(m_size < m_capacity);
		lazy_dict_entry& ret = m_data.dict[m_size++];
		ret.name = name;
		return &ret.val;
	}

	void lazy_entry::pop()
	{
		if (m_size > 0) --m_size;
	}

	namespace
	{
		// the number of decimal digits needed
		// to represent the given value
		int num_digits(int val)
		{
			int ret = 1;
			while (val >= 10)
			{
				++ret;
				val /= 10;

// ... [TRUNCATED: 93 lines omitted] ...

		for (int i = 0; i < int(m_size); ++i)
		{
			lazy_dict_entry& e = m_data.dict[i];
			if (string_equal(name, e.name, e.val.m_begin - e.name))
				return &e.val;
		}
		return 0;
	}

	lazy_entry* lazy_entry::list_append()
	{
		TORRENT_ASSERT(m_type == list_t);
		TORRENT_ASSERT(m_size <= m_capacity);
		if (m_capacity == 0)
		{
			int capacity = lazy_entry_list_init;
			m_data.list = new (std::nothrow) lazy_entry[capacity];
			if (m_data.list == 0) return 0;
			m_capacity = capacity;
		}
		else if (m_size == m_capacity)
		{
			int capacity = m_capacity * lazy_entry_grow_factor / 100;
			lazy_entry* tmp = new (std::nothrow) lazy_entry[capacity];
			if (tmp == 0) return 0;
			std::memcpy(tmp, m_data.list, sizeof(lazy_entry) * m_size);
			for (int i = 0; i < int(m_size); ++i) m_data.list[i].release();
			delete[] m_data.list;
			m_data.list = tmp;
			m_capacity = capacity;
		}

		TORRENT_ASSERT(m_size < m_capacity);
		return m_data.list + (m_size++);
	}

	std::string lazy_entry::list_string_value_at(int i) const
	{
		lazy_entry const* e = list_at(i);
		if (e == 0 || e->type() != lazy_entry::string_t) return std::string();
		return e->string_value();
	}

	pascal_string lazy_entry::list_pstr_at(int i) const
	{
		lazy_entry const* e = list_at(i);
		if (e == 0 || e->type() != lazy_entry::string_t) return pascal_string(0, 0);
		return e->string_pstr();
	}

	boost::int64_t lazy_entry::list_int_value_at(int i, boost::int64_t default_val) const
	{
		lazy_entry const* e = list_at(i);
		if (e == 0 || e->type() != lazy_entry::int_t) return default_val;
		return e->int_value();
	}

	void lazy_entry::clear()
	{
		switch (m_type)
		{
			case list_t: delete[] m_data.list; break;
			case dict_t: delete[] m_data.dict; break;
			default: break;
		}
		m_data.start = 0;
		m_size = 0;
		m_capacity = 0;
		m_type = none_t;
	}

	std::pair<char const*, int> lazy_entry::data_section() const
	{
		typedef std::pair<char const*, int> return_t;
		return return_t(m_begin, m_len);
	}

	int line_longer_than(lazy_entry const& e, int limit)
	{
		int line_len = 0;
		switch (e.type())
		{
		case lazy_entry::list_t:
			line_len += 4;
			if (line_len > limit) return -1;
			for (int i = 0; i < e.list_size(); ++i)
			{
				int ret = line_longer_than(*e.list_at(i), limit - line_len);
				if (ret == -1) return -1;
				line_len += ret + 2;
			}
			break;
		case lazy_entry::dict_t:
			line_len += 4;
			if (line_len > limit) return -1;
			for (int i = 0; i < e.dict_size(); ++i)
			{
				line_len += 4 + e.dict_at(i).first.size();
				if (line_len > limit) return -1;
				int ret = line_longer_than(*e.dict_at(i).second, limit - line_len);
				if (ret == -1) return -1;
				line_len += ret + 1;
			}
			break;
		case lazy_entry::string_t:
			line_len += 3 + e.string_length();
			break;
		case lazy_entry::int_t:
		{
			boost::int64_t val = e.int_value();
			while (val > 0)
			{
				++line_len;
				val /= 10;
			}
			line_len += 2;
		}
		break;
		case lazy_entry::none_t:
			line_len += 4;
			break;
		}
	
		if (line_len > limit) return -1;
		return line_len;
	}

	std::string print_entry(lazy_entry const& e, bool single_line, int indent)
	{
		char indent_str[200];
		memset(indent_str, ' ', 200);
		indent_str[0] = ',';
		indent_str[1] = '\n';
		indent_str[199] = 0;
		if (indent < 197 && indent >= 0) indent_str[indent+2] = 0;
		std::string ret;
		switch (e.type())
		{
			case lazy_entry::none_t: return "none";
			case lazy_entry::int_t:
			{
				char str[100];
				snprintf(str, sizeof(str), "%" PRId64, e.int_value());
				return str;
			}
			case lazy_entry::string_t:
			{
				bool printable = true;
				char const* str = e.string_ptr();
				for (int i = 0; i < e.string_length(); ++i)
				{
					using namespace std;
					if (is_print((unsigned char)str[i])) continue;
					printable = false;
					break;
				}
				ret += "'";
				if (printable)
				{
					ret += e.string_value();
					ret += "'";
					return ret;
				}
				for (int i = 0; i < e.string_length(); ++i)
				{
					char tmp[5];
					snprintf(tmp, sizeof(tmp), "%02x", (unsigned char)str[i]);
					ret += tmp;
				}
				ret += "'";
				return ret;
			}
			case lazy_entry::list_t:
			{
				ret += '[';
				bool one_liner = line_longer_than(e, 200) != -1 || single_line;

				if (!one_liner) ret += indent_str + 1;
				for (int i = 0; i < e.list_size(); ++i)
				{
					if (i == 0 && one_liner) ret += " ";
					ret += print_entry(*e.list_at(i), single_line, indent + 2);
					if (i < e.list_size() - 1) ret += (one_liner?", ":indent_str);
					else ret += (one_liner?" ":indent_str+1);
				}
				ret += "]";
				return ret;
			}
			case lazy_entry::dict_t:
			{
				ret += "{";
				bool one_liner = line_longer_than(e, 200) != -1 || single_line;

				if (!one_liner) ret += indent_str+1;
				for (int i = 0; i < e.dict_size(); ++i)
				{
					if (i == 0 && one_liner) ret += " ";
					std::pair<std::string, lazy_entry const*> ent = e.dict_at(i);
					ret += "'";
					ret += ent.first;
					ret += "': ";
					ret += print_entry(*ent.second, single_line, indent + 2);
					if (i < e.dict_size() - 1) ret += (one_liner?", ":indent_str);
					else ret += (one_liner?" ":indent_str+1);
				}
				ret += "}";
				return ret;
			}
		}
		return ret;
	}

	struct bdecode_error_category : boost::system::error_category
	{
		virtual const char* name() const BOOST_SYSTEM_NOEXCEPT;
		virtual std::string message(int ev) const BOOST_SYSTEM_NOEXCEPT;
		virtual boost::system::error_condition default_error_condition(int ev) const BOOST_SYSTEM_NOEXCEPT
		{ return boost::system::error_condition(ev, *this); }
	};

	const char* bdecode_error_category::name() const BOOST_SYSTEM_NOEXCEPT
	{
		return "bdecode error";
	}

	std::string bdecode_error_category::message(int ev) const BOOST_SYSTEM_NOEXCEPT
	{
		static char const* msgs[] =
		{
			"no error",
			"expected string in bencoded string",
			"expected colon in bencoded string",
			"unexpected end of file in bencoded string",
			"expected value (list, dict, int or string) in bencoded string",
			"bencoded nesting depth exceeded",
			"bencoded item count limit exceeded",
		};
		if (ev < 0 || ev >= int(sizeof(msgs)/sizeof(msgs[0])))
			return "Unknown error";
		return msgs[ev];
	}

	boost::system::error_category& get_bdecode_category()
	{
		static bdecode_error_category bdecode_category;
		return bdecode_category;
	}

};

```

## Bug Fix Patch

```diff
diff --git a/lazy_bdecode.cpp b/lazy_bdecode.cpp
index 3bd4080..0f7b292 100644
--- a/lazy_bdecode.cpp
+++ b/lazy_bdecode.cpp
@@ -1,6 +1,6 @@
 /*
 
-Copyright (c) 2008-2012, Arvid Norberg
+Copyright (c) 2008-2014, Arvid Norberg
 All rights reserved.
 
 Redistribution and use in source and binary forms, with or without
@@ -45,35 +45,62 @@ namespace
 namespace libtorrent
 {
 
-#define TORRENT_FAIL_BDECODE(code) \
-	{ \
-		ec = make_error_code(code); \
-		while (!stack.empty()) { \
-			top = stack.back(); \
-			if (top->type() == lazy_entry::dict_t || top->type() == lazy_entry::list_t) top->pop(); \
-			stack.pop_back(); \
-		} \
-		if (error_pos) *error_pos = start - orig_start; \
-		return -1; \
+	namespace
+	{
+		int fail(int* error_pos
+			, std::vector<lazy_entry*>& stack
+			, char const* start
+			, char const* orig_start)
+		{
+			while (!stack.empty()) {
+				lazy_entry* top = stack.back();
+				if (top->type() == lazy_entry::dict_t || top->type() == lazy_entry::list_t)
+				{
+					top->pop();
+					break;
+				}
+				stack.pop_back();
+			}
+			if (error_pos) *error_pos = start - orig_start;
+			return -1;
+		}
 	}
 
-	bool is_digit(char c) { return c >= '0' && c <= '9'; }
+#define TORRENT_FAIL_BDECODE(code) do { ec = make_error_code(code); return fail(error_pos, stack, start, orig_start); } while (false)
 
-	bool is_print(char c) { return c >= 32 && c < 127; }
+	namespace { bool numeric(char c) { return c >= '0' && c <= '9'; } }
 
 	// fills in 'val' with what the string between start and the
 	// first occurance of the delimiter is interpreted as an int.
 	// return the pointer to the delimiter, or 0 if there is a
 	// parse error. val should be initialized to zero
-	char const* parse_int(char const* start, char const* end, char delimiter, boost::int64_t& val)
+	char const* parse_int(char const* start, char const* end, char delimiter
+		, boost::int64_t& val, bdecode_errors::error_code_enum& ec)
 	{
 		while (start < end && *start != delimiter)
 		{
-			if (!is_digit(*start)) { return 0; }
+			if (!numeric(*start))
+			{
+				ec = bdecode_errors::expected_string;
+				return start;
+			}
+			if (val > INT64_MAX / 10)
+			{
+				ec = bdecode_errors::overflow;
+				return start;
+			}
 			val *= 10;
-			val += *start - '0';
+			int digit = *start - '0';
+			if (val > INT64_MAX - digit)
+			{
+				ec = bdecode_errors::overflow;
+				return start;
+			}
+			val += digit;
 			++start;
 		}
+		if (*start != delimiter)
+			ec = bdecode_errors::expected_colon;
 		return start;
 	}
 
@@ -94,7 +121,7 @@ namespace libtorrent
 		std::vector<lazy_entry*> stack;
 
 		stack.push_back(&ret);
-		while (start < end)
+		while (start <= end)
 		{
 			if (stack.empty()) break; // done!
 
@@ -116,11 +143,19 @@ namespace libtorrent
 						stack.pop_back();
 						continue;
 					}
-					if (!is_digit(t)) TORRENT_FAIL_BDECODE(bdecode_errors::expected_string);
+					if (!numeric(t)) TORRENT_FAIL_BDECODE(bdecode_errors::expected_string);
 					boost::int64_t len = t - '0';
-					start = parse_int(start, end, ':', len);
-					if (start == 0 || start + len + 3 > end || *start != ':')
-						TORRENT_FAIL_BDECODE(bdecode_errors::expected_colon);
+					bdecode_errors::error_code_enum e = bdecode_errors::no_error;
+					start = parse_int(start, end, ':', len, e);
+					if (e)
+						TORRENT_FAIL_BDECODE(e);
+
+					if (start + len + 1 > end)
+						TORRENT_FAIL_BDECODE(bdecode_errors::unexpected_eof);
+
+					if (len < 0)
+						TORRENT_FAIL_BDECODE(bdecode_errors::overflow);
+
 					++start;
 					if (start == end) TORRENT_FAIL_BDECODE(bdecode_errors::unexpected_eof);
 					lazy_entry* ent = top->dict_append(start);
@@ -173,13 +208,19 @@ namespace libtorrent
 				}
 				default:
 				{
-					if (!is_digit(t))
+					if (!numeric(t))
 						TORRENT_FAIL_BDECODE(bdecode_errors::expected_value);
 
 					boost::int64_t len = t - '0';
-					start = parse_int(start, end, ':', len);
-					if (start == 0 || start + len + 1 > end || *start != ':')
-						TORRENT_FAIL_BDECODE(bdecode_errors::expected_colon);
+					bdecode_errors::error_code_enum e = bdecode_errors::no_error;
+					start = parse_int(start, end, ':', len, e);
+					if (e)
+						TORRENT_FAIL_BDECODE(e);
+					if (start + len + 1 > end)
+						TORRENT_FAIL_BDECODE(bdecode_errors::unexpected_eof);
+					if (len < 0)
+						TORRENT_FAIL_BDECODE(bdecode_errors::overflow);
+
 					++start;
 					top->construct_string(start, int(len));
 					stack.pop_back();
@@ -198,7 +239,10 @@ namespace libtorrent
 		boost::int64_t val = 0;
 		bool negative = false;
 		if (*m_data.start == '-') negative = true;
-		parse_int(negative?m_data.start+1:m_data.start, m_data.start + m_size, 'e', val);
+		bdecode_errors::error_code_enum ec = bdecode_errors::no_error;
+		parse_int(m_data.start + negative
+			, m_data.start + m_size, 'e', val, ec);
+		if (ec) return 0;
 		if (negative) val = -val;
 		return val;
 	}
@@ -331,6 +375,13 @@ namespace libtorrent
 		return e;
 	}
 
+	lazy_entry const* lazy_entry::dict_find_dict(std::string const& name) const
+	{
+		lazy_entry const* e = dict_find(name);
+		if (e == 0 || e->type() != lazy_entry::dict_t) return 0;
+		return e;
+	}
+
 	lazy_entry const* lazy_entry::dict_find_list(char const* name) const
 	{
 		lazy_entry const* e = dict_find(name);
@@ -350,6 +401,19 @@ namespace libtorrent
 		return 0;
 	}
 
+	lazy_entry* lazy_entry::dict_find(std::string const& name)
+	{
+		TORRENT_ASSERT(m_type == dict_t);
+		for (int i = 0; i < int(m_size); ++i)
+		{
+			lazy_dict_entry& e = m_data.dict[i];
+			if (name.size() != e.val.m_begin - e.name) continue;
+			if (std::equal(name.begin(), name.end(), e.name))
+				return &e.val;
+		}
+		return 0;
+	}
+
 	lazy_entry* lazy_entry::list_append()
 	{
 		TORRENT_ASSERT(m_type == list_t);
@@ -492,23 +556,50 @@ namespace libtorrent
 				char const* str = e.string_ptr();
 				for (int i = 0; i < e.string_length(); ++i)
 				{
-					using namespace std;
-					if (is_print((unsigned char)str[i])) continue;
+					char c = str[i];
+					if (c >= 32 && c < 127) continue;
 					printable = false;
 					break;
 				}
 				ret += "'";
 				if (printable)
 				{
-					ret += e.string_value();
+					if (single_line && e.string_length() > 30)
+					{
+						ret.append(e.string_ptr(), 14);
+						ret += "...";
+						ret.append(e.string_ptr() + e.string_length()-14, 14);
+					}
+					else
+						ret.append(e.string_ptr(), e.string_length());
 					ret += "'";
 					return ret;
 				}
-				for (int i = 0; i < e.string_length(); ++i)
+				if (single_line && e.string_length() > 20)
 				{
-					char tmp[5];
-					snprintf(tmp, sizeof(tmp), "%02x", (unsigned char)str[i]);
-					ret += tmp;
+					for (int i = 0; i < 9; ++i)
+					{
+						char tmp[5];
+						snprintf(tmp, sizeof(tmp), "%02x", (unsigned char)str[i]);
+						ret += tmp;
+					}
+					ret += "...";
+					for (int i = e.string_length() - 9
+						, len(e.string_length()); i < len; ++i)
+					{
+						char tmp[5];
+						snprintf(tmp, sizeof(tmp), "%02x", (unsigned char)str[i]);
+						ret += tmp;
+					}
+				}
+				else
+				{
+					for (int i = 0; i < e.string_length(); ++i)
+					{
+						char tmp[5];
+						snprintf(tmp, sizeof(tmp), "%02x", (unsigned char)str[i]);
+						ret += tmp;
+					}
 				}
 				ret += "'";
 				return ret;
@@ -577,6 +668,7 @@ namespace libtorrent
 			"expected value (list, dict, int or string) in bencoded string",
 			"bencoded nesting depth exceeded",
 			"bencoded item count limit exceeded",
+			"integer overflow",
 		};
 		if (ev < 0 || ev >= int(sizeof(msgs)/sizeof(msgs[0])))
 			return "Unknown error";
@@ -589,5 +681,12 @@ namespace libtorrent
 		return bdecode_category;
 	}
 
+	namespace bdecode_errors
+	{
+		boost::system::error_code make_error_code(error_code_enum e)
+		{
+			return boost::system::error_code(e, get_bdecode_category());
+		}
+	}
 };
 
diff --git a/lazy_entry.hpp b/lazy_entry.hpp
index 70cec90..0e1bfb6 100644
--- a/lazy_entry.hpp
+++ b/lazy_entry.hpp
@@ -1,6 +1,6 @@
 /*
 
-Copyright (c) 2003-2012, Arvid Norberg
+Copyright (c) 2003-2014, Arvid Norberg
 All rights reserved.
 
 Redistribution and use in source and binary forms, with or without
@@ -37,6 +37,7 @@ POSSIBILITY OF SUCH DAMAGE.
 #include <vector>
 #include <string>
 #include <cstring>
+#include <algorithm>
 #include <boost/system/error_code.hpp>
 
 #define TORRENT_EXPORT
@@ -136,6 +137,7 @@ namespace libtorrent
 			none_t, dict_t, list_t, string_t, int_t
 		};
 
+		// internal
 		lazy_entry() : m_begin(0), m_len(0), m_size(0), m_capacity(0), m_type(none_t)
 		{ m_data.start = 0; }
 
@@ -156,7 +158,7 @@ namespace libtorrent
 			m_len = length + 2; // include 'e'
 		}
 
-		// if this is an integer, return the integer value
+		// requires the type to be an integer. return the integer value
 		boost::int64_t int_value() const;
 
 		// internal
@@ -221,6 +223,9 @@ namespace libtorrent
 		lazy_entry* dict_find(char const* name);
 		lazy_entry const* dict_find(char const* name) const
 		{ return const_cast<lazy_entry*>(this)->dict_find(name); }
+		lazy_entry* dict_find(std::string const& name);
+		lazy_entry const* dict_find(std::string const& name) const
+		{ return const_cast<lazy_entry*>(this)->dict_find(name); }
 		lazy_entry const* dict_find_string(char const* name) const;
 
 		// if this is a dictionary, look for a key ``name`` whose value
@@ -235,14 +240,22 @@ namespace libtorrent
 		boost::int64_t dict_find_int_value(char const* name, boost::int64_t default_val = 0) const;
 		lazy_entry const* dict_find_int(char const* name) const;
 
+		// these functions require that ``this`` is a dictionary.
+		// (this->type() == dict_t). They look for an element with the
+		// specified name in the dictionary. ``dict_find_dict`` only
+		// finds dictionaries and ``dict_find_list`` only finds lists.
+		// if no key with the corresponding value of the right type is
+		// found, NULL is returned.
 		lazy_entry const* dict_find_dict(char const* name) const;
+		lazy_entry const* dict_find_dict(std::string const& name) const;
 		lazy_entry const* dict_find_list(char const* name) const;
 
 		// if this is a dictionary, return the key value pair at
 		// position ``i`` from the dictionary.
 		std::pair<std::string, lazy_entry const*> dict_at(int i) const;
 
-		// if this is a dictionary, return the number of items in it
+		// requires that ``this`` is a dictionary. return the
+		// number of items in it
 		int dict_size() const
 		{
 			TORRENT_ASSERT(m_type == dict_t);
@@ -262,7 +275,8 @@ namespace libtorrent
 		// internal
 		lazy_entry* list_append();
 
-		// if this is a list, return the item at index ``i``.
+		// requires that ``this`` is a list. return
+		// the item at index ``i``.
 		lazy_entry* list_at(int i)
 		{
 			TORRENT_ASSERT(m_type == list_t);
@@ -272,8 +286,19 @@ namespace libtorrent
 		lazy_entry const* list_at(int i) const
 		{ return const_cast<lazy_entry*>(this)->list_at(i); }
 
+		// these functions require ``this`` to have the type list.
+		// (this->type() == list_t). ``list_string_value_at`` returns
+		// the string at index ``i``. ``list_pstr_at``
+		// returns a pascal_string of the string value at index ``i``.
+		// if the element at ``i`` is not a string, an empty string
+		// is returned.
 		std::string list_string_value_at(int i) const;
 		pascal_string list_pstr_at(int i) const;
+
+		// this function require ``this`` to have the type list.
+		// (this->type() == list_t). returns the integer value at
+		// index ``i``. If the element at ``i`` is not an integer
+		// ``default_val`` is returned, which defaults to 0.
 		boost::int64_t list_int_value_at(int i, boost::int64_t default_val = 0) const;
 
 		// if this is a list, return the number of items in it.
@@ -283,7 +308,7 @@ namespace libtorrent
 			return int(m_size);
 		}
 
-		// end points one byte passed last byte in the source
+		// internal: end points one byte passed last byte in the source
 		// buffer backing the bencoded structure.
 		void set_end(char const* end)
 		{
@@ -294,7 +319,7 @@ namespace libtorrent
 		// internal
 		void clear();
 
-		// releases ownership of any memory allocated
+		// internal: releases ownership of any memory allocated
 		void release()
 		{
 			m_data.start = 0;
@@ -361,9 +386,12 @@ namespace libtorrent
 		lazy_entry val;
 	};
 
-	TORRENT_EXTRA_EXPORT std::string print_entry(lazy_entry const& e
+	// print the bencoded structure in a human-readable format to a stting
+	// that's returned.
+	TORRENT_EXPORT std::string print_entry(lazy_entry const& e
 		, bool single_line = false, int indent = 0);
 
+	// get the ``error_category`` for bdecode errors
 	TORRENT_EXPORT boost::system::error_category& get_bdecode_category();
 
 	namespace bdecode_errors
@@ -386,17 +414,21 @@ namespace libtorrent
 			depth_exceeded,
 			// bencoded item count limit exceeded
 			limit_exceeded,
+			// integer overflow
+			overflow,
 
 			// the number of error codes
 			error_code_max
 		};
 
 		// hidden
-		inline boost::system::error_code make_error_code(error_code_enum e)
-		{
-			return boost::system::error_code(e, get_bdecode_category());
-		}
+		TORRENT_EXPORT boost::system::error_code make_error_code(error_code_enum e);
 	}
+
+	TORRENT_EXTRA_EXPORT char const* parse_int(char const* start
+		, char const* end, char delimiter, boost::int64_t& val
+		, bdecode_errors::error_code_enum& ec);
+
 }
 
 #endif
```
