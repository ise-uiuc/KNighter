## Patch Description

Add Inflator::BadDistanceErr exception (Issue 414)
The improved validation and excpetion clears the Address Sanitizer and Undefined Behavior Sanitizer findings

## Buggy Code

```c
// Complete file: zinflate.cpp (tree-sitter fallback)
// zinflate.cpp - originally written and placed in the public domain by Wei Dai

// This is a complete reimplementation of the DEFLATE decompression algorithm.
// It should not be affected by any security vulnerabilities in the zlib
// compression library. In particular it is not affected by the double free bug
// (http://www.kb.cert.org/vuls/id/368819).

#include "pch.h"

#include "zinflate.h"
#include "secblock.h"
#include "smartptr.h"

NAMESPACE_BEGIN(CryptoPP)

struct CodeLessThan
{
	inline bool operator()(CryptoPP::HuffmanDecoder::code_t lhs, const CryptoPP::HuffmanDecoder::CodeInfo &rhs)
		{return lhs < rhs.code;}
	// needed for MSVC .NET 2005
	inline bool operator()(const CryptoPP::HuffmanDecoder::CodeInfo &lhs, const CryptoPP::HuffmanDecoder::CodeInfo &rhs)
		{return lhs.code < rhs.code;}
};

inline bool LowFirstBitReader::FillBuffer(unsigned int length)
{
	while (m_bitsBuffered < length)
	{
		byte b;
		if (!m_store.Get(b))
			return false;
		m_buffer |= (unsigned long)b << m_bitsBuffered;
		m_bitsBuffered += 8;
	}
	CRYPTOPP_ASSERT(m_bitsBuffered <= sizeof(unsigned long)*8);
	return true;
}

inline unsigned long LowFirstBitReader::PeekBits(unsigned int length)
{
	bool result = FillBuffer(length);
	CRYPTOPP_UNUSED(result); CRYPTOPP_ASSERT(result);
	return m_buffer & (((unsigned long)1 << length) - 1);
}

inline void LowFirstBitReader::SkipBits(unsigned int length)
{
	CRYPTOPP_ASSERT(m_bitsBuffered >= length);
	m_buffer >>= length;
	m_bitsBuffered -= length;
}

inline unsigned long LowFirstBitReader::GetBits(unsigned int length)
{
	unsigned long result = PeekBits(length);
	SkipBits(length);
	return result;
}

inline HuffmanDecoder::code_t HuffmanDecoder::NormalizeCode(HuffmanDecoder::code_t code, unsigned int codeBits)
{
	return code << (MAX_CODE_BITS - codeBits);
}

void HuffmanDecoder::Initialize(const unsigned int *codeBits, unsigned int nCodes)
{
	// the Huffman codes are represented in 3 ways in this code:
	//
	// 1. most significant code bit (i.e. top of code tree) in the least significant bit position
	// 2. most significant code bit (i.e. top of code tree) in the most significant bit position
	// 3. most significant code bit (i.e. top of code tree) in n-th least significant bit position,
	//    where n is the maximum code length for this code tree
	//
	// (1) is the way the codes come in from the deflate stream
	// (2) is used to sort codes so they can be binary searched
	// (3) is used in this function to compute codes from code lengths
	//
	// a code in representation (2) is called "normalized" here
	// The BitReverse() function is used to convert between (1) and (2)
	// The NormalizeCode() function is used to convert from (3) to (2)

	if (nCodes == 0)
		throw Err("null code");

	m_maxCodeBits = *std::max_element(codeBits, codeBits+nCodes);

	if (m_maxCodeBits > MAX_CODE_BITS)
		throw Err("code length exceeds maximum");

	if (m_maxCodeBits == 0)
		throw Err("null code");

	// count number of codes of each length
	SecBlockWithHint<unsigned int, 15+1> blCount(m_maxCodeBits+1);
	std::fill(blCount.begin(), blCount.end(), 0);
	unsigned int i;
	for (i=0; i<nCodes; i++)
		blCount[codeBits[i]]++;

	// compute the starting code of each length
	code_t code = 0;
	SecBlockWithHint<code_t, 15+1> nextCode(m_maxCodeBits+1);
	nextCode[1] = 0;
	for (i=2; i<=m_maxCodeBits; i++)
	{
		// compute this while checking for overflow: code = (code + blCount[i-1]) << 1
		if (code > code + blCount[i-1])
			throw Err("codes oversubscribed");
		code += blCount[i-1];
		if (code > (code << 1))
			throw Err("codes oversubscribed");
		code <<= 1;
		nextCode[i] = code;
	}

	// MAX_CODE_BITS is 32, m_maxCodeBits may be smaller.
	const word64 shiftedMaxCode = ((word64)1 << m_maxCodeBits);
	if (code > shiftedMaxCode - blCount[m_maxCodeBits])
		throw Err("codes oversubscribed");
	else if (m_maxCodeBits != 1 && code < shiftedMaxCode - blCount[m_maxCodeBits])
		throw Err("codes incomplete");

	// compute a vector of <code, length, value> triples sorted by code
	m_codeToValue.resize(nCodes - blCount[0]);
	unsigned int j=0;
	for (i=0; i<nCodes; i++)
	{
		unsigned int len = codeBits[i];
		if (len != 0)
		{
			code = NormalizeCode(nextCode[len]++, len);
			m_codeToValue[j].code = code;
			m_codeToValue[j].len = len;
			m_codeToValue[j].value = i;
			j++;
		}
	}
	std::sort(m_codeToValue.begin(), m_codeToValue.end());

	// initialize the decoding cache
	m_cacheBits = STDMIN(9U, m_maxCodeBits);
	m_cacheMask = (1 << m_cacheBits) - 1;
	m_normalizedCacheMask = NormalizeCode(m_cacheMask, m_cacheBits);
	CRYPTOPP_ASSERT(m_normalizedCacheMask == BitReverse(m_cacheMask));

	const word64 shiftedCache = ((word64)1 << m_cacheBits);
	CRYPTOPP_ASSERT(shiftedCache <= SIZE_MAX);
	if (m_cache.size() != shiftedCache)
		m_cache.resize((size_t)shiftedCache);

	for (i=0; i<m_cache.size(); i++)
		m_cache[i].type = 0;
}

void HuffmanDecoder::FillCacheEntry(LookupEntry &entry, code_t normalizedCode) const
{
	normalizedCode &= m_normalizedCacheMask;
	const CodeInfo &codeInfo = *(std::upper_bound(m_codeToValue.begin(), m_codeToValue.end(), normalizedCode, CodeLessThan())-1);
	if (codeInfo.len <= m_cacheBits)
	{
		entry.type = 1;
		entry.value = codeInfo.value;
		entry.len = codeInfo.len;
	}
	else
	{
		entry.begin = &codeInfo;
		const CodeInfo *last = & *(std::upper_bound(m_codeToValue.begin(), m_codeToValue.end(), normalizedCode + ~m_normalizedCacheMask, CodeLessThan())-1);
		if (codeInfo.len == last->len)
		{
			entry.type = 2;
			entry.len = codeInfo.len;
		}
		else
		{
			entry.type = 3;
			entry.end = last+1;
		}
	}
}

inline unsigned int HuffmanDecoder::Decode(code_t code, /* out */ value_t &value) const
{
	CRYPTOPP_ASSERT(m_codeToValue.size() > 0);
	LookupEntry &entry = m_cache[code & m_cacheMask];

	code_t normalizedCode = 0;
	if (entry.type != 1)
		normalizedCode = BitReverse(code);

	if (entry.type == 0)
		FillCacheEntry(entry, normalizedCode);

	if (entry.type == 1)
	{
		value = entry.value;
		return entry.len;
	}
	else
	{
		const CodeInfo &codeInfo = (entry.type == 2)
			? entry.begin[(normalizedCode << m_cacheBits) >> (MAX_CODE_BITS - (entry.len - m_cacheBits))]
			: *(std::upper_bound(entry.begin, entry.end, normalizedCode, CodeLessThan())-1);
		value = codeInfo.value;
		return codeInfo.len;
	}
}

bool HuffmanDecoder::Decode(LowFirstBitReader &reader, value_t &value) const
{
	bool result = reader.FillBuffer(m_maxCodeBits);
	CRYPTOPP_UNUSED(result); // CRYPTOPP_ASSERT(result);

	unsigned int codeBits = Decode(reader.PeekBuffer(), value);
	if (codeBits > reader.BitsBuffered())
		return false;
	reader.SkipBits(codeBits);
	return true;
}

// *************************************************************

Inflator::Inflator(BufferedTransformation *attachment, bool repeat, int propagation)
	: AutoSignaling<Filter>(propagation)
	, m_state(PRE_STREAM), m_repeat(repeat), m_eof(0), m_wrappedAround(0)
	, m_blockType(0xff), m_storedLen(0xffff), m_nextDecode(), m_literal(0)
	, m_distance(0), m_reader(m_inQueue), m_current(0), m_lastFlush(0)
{
	Detach(attachment);
}

void Inflator::IsolatedInitialize(const NameValuePairs &parameters)
{
	m_state = PRE_STREAM;
	parameters.GetValue("Repeat", m_repeat);
	m_inQueue.Clear();
	m_reader.SkipBits(m_reader.BitsBuffered());
}

void Inflator::OutputByte(byte b)
{
	m_window[m_current++] = b;
	if (m_current == m_window.size())
	{
		ProcessDecompressedData(m_window + m_lastFlush, m_window.size() - m_lastFlush);
		m_lastFlush = 0;
		m_current = 0;
		m_wrappedAround = true;
	}
}

// ... [TRUNCATED: 139 lines omitted] ...

		break;
		}
	case 1:	// fixed codes
		m_nextDecode = LITERAL;
		break;
	case 2:	// dynamic codes
		{
		if (!m_reader.FillBuffer(5+5+4))
			throw UnexpectedEndErr();
		unsigned int hlit = m_reader.GetBits(5);
		unsigned int hdist = m_reader.GetBits(5);
		unsigned int hclen = m_reader.GetBits(4);

		FixedSizeSecBlock<unsigned int, 286+32> codeLengths;
		unsigned int i;
		static const unsigned int border[] = {    // Order of the bit length code lengths
			16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};
		std::fill(codeLengths.begin(), codeLengths+19, 0);
		for (i=0; i<hclen+4; i++)
			codeLengths[border[i]] = m_reader.GetBits(3);

		try
		{
			HuffmanDecoder codeLengthDecoder(codeLengths, 19);
			for (i = 0; i < hlit+257+hdist+1; )
			{
				unsigned int k = 0, count = 0, repeater = 0;
				bool result = codeLengthDecoder.Decode(m_reader, k);
				if (!result)
					throw UnexpectedEndErr();
				if (k <= 15)
				{
					count = 1;
					repeater = k;
				}
				else switch (k)
				{
				case 16:
					if (!m_reader.FillBuffer(2))
						throw UnexpectedEndErr();
					count = 3 + m_reader.GetBits(2);
					if (i == 0)
						throw BadBlockErr();
					repeater = codeLengths[i-1];
					break;
				case 17:
					if (!m_reader.FillBuffer(3))
						throw UnexpectedEndErr();
					count = 3 + m_reader.GetBits(3);
					repeater = 0;
					break;
				case 18:
					if (!m_reader.FillBuffer(7))
						throw UnexpectedEndErr();
					count = 11 + m_reader.GetBits(7);
					repeater = 0;
					break;
				}
				if (i + count > hlit+257+hdist+1)
					throw BadBlockErr();
				std::fill(codeLengths + i, codeLengths + i + count, repeater);
				i += count;
			}
			m_dynamicLiteralDecoder.Initialize(codeLengths, hlit+257);
			if (hdist == 0 && codeLengths[hlit+257] == 0)
			{
				if (hlit != 0)	// a single zero distance code length means all literals
					throw BadBlockErr();
			}
			else
				m_dynamicDistanceDecoder.Initialize(codeLengths+hlit+257, hdist+1);
			m_nextDecode = LITERAL;
		}
		catch (HuffmanDecoder::Err &)
		{
			throw BadBlockErr();
		}
		break;
		}
	default:
		throw BadBlockErr();	// reserved block type
	}
	m_state = DECODING_BODY;
}

bool Inflator::DecodeBody()
{
	bool blockEnd = false;
	switch (m_blockType)
	{
	case 0:	// stored
		CRYPTOPP_ASSERT(m_reader.BitsBuffered() == 0);
		while (!m_inQueue.IsEmpty() && !blockEnd)
		{
			size_t size;
			const byte *block = m_inQueue.Spy(size);
			size = UnsignedMin(m_storedLen, size);
			CRYPTOPP_ASSERT(size <= 0xffff);

			OutputString(block, size);
			m_inQueue.Skip(size);
			m_storedLen = m_storedLen - (word16)size;
			if (m_storedLen == 0)
				blockEnd = true;
		}
		break;
	case 1:	// fixed codes
	case 2:	// dynamic codes
		static const unsigned int lengthStarts[] = {
			3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
			35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
		static const unsigned int lengthExtraBits[] = {
			0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
			3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
		static const unsigned int distanceStarts[] = {
			1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
			257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
			8193, 12289, 16385, 24577};
		static const unsigned int distanceExtraBits[] = {
			0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
			7, 7, 8, 8, 9, 9, 10, 10, 11, 11,
			12, 12, 13, 13};

		const HuffmanDecoder& literalDecoder = GetLiteralDecoder();
		const HuffmanDecoder& distanceDecoder = GetDistanceDecoder();

		switch (m_nextDecode)
		{
		case LITERAL:
			while (true)
			{
				if (!literalDecoder.Decode(m_reader, m_literal))
				{
					m_nextDecode = LITERAL;
					break;
				}
				if (m_literal < 256)
					OutputByte((byte)m_literal);
				else if (m_literal == 256)	// end of block
				{
					blockEnd = true;
					break;
				}
				else
				{
					if (m_literal > 285)
						throw BadBlockErr();
					unsigned int bits;
		case LENGTH_BITS:
					bits = lengthExtraBits[m_literal-257];
					if (!m_reader.FillBuffer(bits))
					{
						m_nextDecode = LENGTH_BITS;
						break;
					}
					m_literal = m_reader.GetBits(bits) + lengthStarts[m_literal-257];
		case DISTANCE:
					if (!distanceDecoder.Decode(m_reader, m_distance))
					{
						m_nextDecode = DISTANCE;
						break;
					}
		case DISTANCE_BITS:
					// TODO: this surfaced during fuzzing. What do we do???
					CRYPTOPP_ASSERT(m_distance < COUNTOF(distanceExtraBits));
					bits = (m_distance >= COUNTOF(distanceExtraBits)) ? distanceExtraBits[29] : distanceExtraBits[m_distance];
					if (!m_reader.FillBuffer(bits))
					{
						m_nextDecode = DISTANCE_BITS;
						break;
					}
					m_distance = m_reader.GetBits(bits) + distanceStarts[m_distance];
					OutputPast(m_literal, m_distance);
				}
			}
			break;
		default:
			CRYPTOPP_ASSERT(0);
		}
	}
	if (blockEnd)
	{
		if (m_eof)
		{
			FlushOutput();
			m_reader.SkipBits(m_reader.BitsBuffered()%8);
			if (m_reader.BitsBuffered())
			{
				// undo too much lookahead
				SecBlockWithHint<byte, 4> buffer(m_reader.BitsBuffered() / 8);
				for (unsigned int i=0; i<buffer.size(); i++)
					buffer[i] = (byte)m_reader.GetBits(8);
				m_inQueue.Unget(buffer, buffer.size());
			}
			m_state = POST_STREAM;
		}
		else
			m_state = WAIT_HEADER;
	}
	return blockEnd;
}

void Inflator::FlushOutput()
{
	if (m_state != PRE_STREAM)
	{
		CRYPTOPP_ASSERT(m_current >= m_lastFlush);
		ProcessDecompressedData(m_window + m_lastFlush, m_current - m_lastFlush);
		m_lastFlush = m_current;
	}
}

struct NewFixedLiteralDecoder
{
	HuffmanDecoder * operator()() const
	{
		unsigned int codeLengths[288];
		std::fill(codeLengths + 0, codeLengths + 144, 8);
		std::fill(codeLengths + 144, codeLengths + 256, 9);
		std::fill(codeLengths + 256, codeLengths + 280, 7);
		std::fill(codeLengths + 280, codeLengths + 288, 8);
		member_ptr<HuffmanDecoder> pDecoder(new HuffmanDecoder);
		pDecoder->Initialize(codeLengths, 288);
		return pDecoder.release();
	}
};

struct NewFixedDistanceDecoder
{
	HuffmanDecoder * operator()() const
	{
		unsigned int codeLengths[32];
		std::fill(codeLengths + 0, codeLengths + 32, 5);
		member_ptr<HuffmanDecoder> pDecoder(new HuffmanDecoder);
		pDecoder->Initialize(codeLengths, 32);
		return pDecoder.release();
	}
};

const HuffmanDecoder& Inflator::GetLiteralDecoder() const
{
	return m_blockType == 1 ? Singleton<HuffmanDecoder, NewFixedLiteralDecoder>().Ref() : m_dynamicLiteralDecoder;
}

const HuffmanDecoder& Inflator::GetDistanceDecoder() const
{
	return m_blockType == 1 ? Singleton<HuffmanDecoder, NewFixedDistanceDecoder>().Ref() : m_dynamicDistanceDecoder;
}

NAMESPACE_END
```

```c
// Complete file: zinflate.h (tree-sitter fallback)
#ifndef CRYPTOPP_ZINFLATE_H
#define CRYPTOPP_ZINFLATE_H

#include "cryptlib.h"
#include "secblock.h"
#include "filters.h"
#include "stdcpp.h"

NAMESPACE_BEGIN(CryptoPP)

//! \class LowFirstBitReader
//! \since Crypto++ 1.0
class LowFirstBitReader
{
public:
	LowFirstBitReader(BufferedTransformation &store)
		: m_store(store), m_buffer(0), m_bitsBuffered(0) {}
	unsigned int BitsBuffered() const {return m_bitsBuffered;}
	unsigned long PeekBuffer() const {return m_buffer;}
	bool FillBuffer(unsigned int length);
	unsigned long PeekBits(unsigned int length);
	void SkipBits(unsigned int length);
	unsigned long GetBits(unsigned int length);

private:
	BufferedTransformation &m_store;
	unsigned long m_buffer;
	unsigned int m_bitsBuffered;
};

struct CodeLessThan;

//! \class HuffmanDecoder
//! \brief Huffman Decoder
//! \since Crypto++ 1.0
class HuffmanDecoder
{
public:
	typedef unsigned int code_t;
	typedef unsigned int value_t;
	enum {MAX_CODE_BITS = sizeof(code_t)*8};

	class Err : public Exception {public: Err(const std::string &what) : Exception(INVALID_DATA_FORMAT, "HuffmanDecoder: " + what) {}};

	HuffmanDecoder() : m_maxCodeBits(0), m_cacheBits(0), m_cacheMask(0), m_normalizedCacheMask(0) {}
	HuffmanDecoder(const unsigned int *codeBitLengths, unsigned int nCodes)
		: m_maxCodeBits(0), m_cacheBits(0), m_cacheMask(0), m_normalizedCacheMask(0)
			{Initialize(codeBitLengths, nCodes);}

	void Initialize(const unsigned int *codeBitLengths, unsigned int nCodes);
	unsigned int Decode(code_t code, /* out */ value_t &value) const;
	bool Decode(LowFirstBitReader &reader, value_t &value) const;

private:
	friend struct CodeLessThan;

	struct CodeInfo
	{
		CodeInfo(code_t code=0, unsigned int len=0, value_t value=0) : code(code), len(len), value(value) {}
		inline bool operator<(const CodeInfo &rhs) const {return code < rhs.code;}
		code_t code;
		unsigned int len;
		value_t value;
	};

	struct LookupEntry
	{
		unsigned int type;
		union
		{
			value_t value;
			const CodeInfo *begin;
		};
		union
		{
			unsigned int len;
			const CodeInfo *end;
		};
	};

	static code_t NormalizeCode(code_t code, unsigned int codeBits);
	void FillCacheEntry(LookupEntry &entry, code_t normalizedCode) const;

	unsigned int m_maxCodeBits, m_cacheBits, m_cacheMask, m_normalizedCacheMask;
	std::vector<CodeInfo, AllocatorWithCleanup<CodeInfo> > m_codeToValue;
	mutable std::vector<LookupEntry, AllocatorWithCleanup<LookupEntry> > m_cache;
};

//! \class Inflator
//! \brief DEFLATE decompressor (RFC 1951)
//! \since Crypto++ 1.0
class Inflator : public AutoSignaling<Filter>
{
public:
	class Err : public Exception
	{
	public:
		Err(ErrorType e, const std::string &s)
			: Exception(e, s) {}
	};
	class UnexpectedEndErr : public Err {public: UnexpectedEndErr() : Err(INVALID_DATA_FORMAT, "Inflator: unexpected end of compressed block") {}};
	class BadBlockErr : public Err {public: BadBlockErr() : Err(INVALID_DATA_FORMAT, "Inflator: error in compressed block") {}};

	//! \brief RFC 1951 Decompressor
	//! \param attachment the filter's attached transformation
	//! \param repeat decompress multiple compressed streams in series
	//! \param autoSignalPropagation 0 to turn off MessageEnd signal
	Inflator(BufferedTransformation *attachment = NULLPTR, bool repeat = false, int autoSignalPropagation = -1);

	void IsolatedInitialize(const NameValuePairs &parameters);
	size_t Put2(const byte *inString, size_t length, int messageEnd, bool blocking);
	bool IsolatedFlush(bool hardFlush, bool blocking);

	virtual unsigned int GetLog2WindowSize() const {return 15;}

protected:
	ByteQueue m_inQueue;

private:
	virtual unsigned int MaxPrestreamHeaderSize() const {return 0;}
	virtual void ProcessPrestreamHeader() {}
	virtual void ProcessDecompressedData(const byte *string, size_t length)
		{AttachedTransformation()->Put(string, length);}
	virtual unsigned int MaxPoststreamTailSize() const {return 0;}
	virtual void ProcessPoststreamTail() {}

	void ProcessInput(bool flush);
	void DecodeHeader();
	bool DecodeBody();
	void FlushOutput();
	void OutputByte(byte b);
	void OutputString(const byte *string, size_t length);
	void OutputPast(unsigned int length, unsigned int distance);

	static const HuffmanDecoder *FixedLiteralDecoder();
	static const HuffmanDecoder *FixedDistanceDecoder();

	const HuffmanDecoder& GetLiteralDecoder() const;
	const HuffmanDecoder& GetDistanceDecoder() const;

	enum State {PRE_STREAM, WAIT_HEADER, DECODING_BODY, POST_STREAM, AFTER_END};
	State m_state;
	bool m_repeat, m_eof, m_wrappedAround;
	byte m_blockType;
	word16 m_storedLen;
	enum NextDecode {LITERAL, LENGTH_BITS, DISTANCE, DISTANCE_BITS};
	NextDecode m_nextDecode;
	unsigned int m_literal, m_distance;	// for LENGTH_BITS or DISTANCE_BITS
	HuffmanDecoder m_dynamicLiteralDecoder, m_dynamicDistanceDecoder;
	LowFirstBitReader m_reader;
	SecByteBlock m_window;
	size_t m_current, m_lastFlush;
};

NAMESPACE_END

#endif
```

## Bug Fix Patch

```diff
diff --git a/validat1.cpp b/validat1.cpp
index cd8655b4..e81a46c6 100644
--- a/validat1.cpp
+++ b/validat1.cpp
@@ -623,7 +623,7 @@ bool TestRandomPool()
 			std::cout << "FAILED:";
 		else
 			std::cout << "passed:";
-		std::cout << "  GenerateWord32 and Crop\n";	
+		std::cout << "  GenerateWord32 and Crop\n";
 	}
 
 #if !defined(NO_OS_DEPENDENCE)
@@ -711,7 +711,7 @@ bool TestRandomPool()
 			std::cout << "FAILED:";
 		else
 			std::cout << "passed:";
-		std::cout << "  GenerateWord32 and Crop\n";	
+		std::cout << "  GenerateWord32 and Crop\n";
 	}
 #endif
 
@@ -808,7 +808,7 @@ bool TestAutoSeededX917()
 		std::cout << "FAILED:";
 	else
 		std::cout << "passed:";
-	std::cout << "  GenerateWord32 and Crop\n";	
+	std::cout << "  GenerateWord32 and Crop\n";
 
 	std::cout.flush();
 	return pass;
diff --git a/zinflate.cpp b/zinflate.cpp
index 62431771..ee15c945 100644
--- a/zinflate.cpp
+++ b/zinflate.cpp
@@ -552,12 +552,18 @@ bool Inflator::DecodeBody()
 		case DISTANCE_BITS:
 					// TODO: this surfaced during fuzzing. What do we do???
 					CRYPTOPP_ASSERT(m_distance < COUNTOF(distanceExtraBits));
-					bits = (m_distance >= COUNTOF(distanceExtraBits)) ? distanceExtraBits[29] : distanceExtraBits[m_distance];
+					if (m_distance >= COUNTOF(distanceExtraBits))
+						throw BadDistanceErr();
+					bits = distanceExtraBits[m_distance];
 					if (!m_reader.FillBuffer(bits))
 					{
 						m_nextDecode = DISTANCE_BITS;
 						break;
 					}
+					// TODO: this surfaced during fuzzing. What do we do???
+					CRYPTOPP_ASSERT(m_distance < COUNTOF(distanceStarts));
+					if (m_distance >= COUNTOF(distanceStarts))
+						throw BadDistanceErr();
 					m_distance = m_reader.GetBits(bits) + distanceStarts[m_distance];
 					OutputPast(m_literal, m_distance);
 				}
diff --git a/zinflate.h b/zinflate.h
index b0879cef..0767d4f9 100644
--- a/zinflate.h
+++ b/zinflate.h
@@ -98,8 +98,12 @@ public:
 		Err(ErrorType e, const std::string &s)
 			: Exception(e, s) {}
 	};
+	//! \brief Exception thrown when a truncated stream is encountered
 	class UnexpectedEndErr : public Err {public: UnexpectedEndErr() : Err(INVALID_DATA_FORMAT, "Inflator: unexpected end of compressed block") {}};
+	//! \brief Exception thrown when a bad block is encountered
 	class BadBlockErr : public Err {public: BadBlockErr() : Err(INVALID_DATA_FORMAT, "Inflator: error in compressed block") {}};
+	//! \brief Exception thrown when an invalid distance is encountered
+	class BadDistanceErr : public Err {public: BadDistanceErr() : Err(INVALID_DATA_FORMAT, "Inflator: error in bit distance") {}};
 
 	//! \brief RFC 1951 Decompressor
 	//! \param attachment the filter's attached transformation
```