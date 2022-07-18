// Header files
#include "./common.h"
#include <iomanip>
#include <iostream>
#include <signal.h>
#include <sstream>
#include "./saturate_math.h"

// Check if macOS
#ifdef __APPLE__

	// Header files
	#include <libkern/OSByteOrder.h>
#endif

using namespace std;


// Definitions

// Always lock free
#define ALWAYS_LOCK_FREE 2


// Constants

// Milliseconds in a seconds
const int Common::MILLISECONDS_IN_A_SECOND = 1000;

// Seconds in a minute
const int Common::SECONDS_IN_A_MINUTE = 60;

// Minutes in an hour
const int Common::MINUTES_IN_A_HOUR = 60;

// Hours in a day
const int Common::HOURS_IN_A_DAY = 24;

// Days in a week
const int Common::DAYS_IN_A_WEEK = 7;

// Weeks in a year
const int Common::WEEKS_IN_A_YEAR = 52;

// Bits in a byte
const int Common::BITS_IN_A_BYTE = 8;

// Bytes in a kilobyte
const int Common::BYTES_IN_A_KILOBYTE = 1024;

// Tor proxy address
const char *Common::TOR_PROXY_ADDRESS = "localhost";

// Tor proxy port
const char *Common::TOR_PROXY_PORT = "9050";


// Global variables

// Set closing to false
atomic_bool Common::closing(false);

// Set signal occurred to false
atomic_bool Common::signalOccurred(false);

// Display lock
mutex Common::displayLock;


// Supporting function implementation

// Initialize
const bool Common::initialize() {

	// Check if setting signal handler failed
	if(signal(SIGINT, [](const int signal) {
	
		// Check signal
		switch(signal) {
		
			// Interrupt
			case SIGINT:
			
				// Check if atomic bool isn't always lock free
				#if ATOMIC_BOOL_LOCK_FREE != ALWAYS_LOCK_FREE
				
					// Throw error
					#error "Atomic bool isn't always lock free"
				#endif
			
				// Set closing to true
				closing.store(true);
				
				// Set signal occurred to true
				signalOccurred.store(true);
				
				// Break
				break;
		}
		
	}) == SIG_ERR) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Set closing
void Common::setClosing() {

	// Set closing to true
	closing.store(true);
}

// Is closing
const bool Common::isClosing() {

	// Return if closing
	return closing.load();
}

// Error occurred
const bool Common::errorOccurred() {

	// Return if closing and a signal didn't occur
	return closing.load() && !signalOccurred.load();
}

// Is UTF-8
const bool Common::isUtf8(const char *text, const size_t length) {

	// Go through all UTF-8 code points in the text
	for(size_t i = 0; i < length;) {
	
		// Check if UTF-8 code point is an ASCII character
		if(text[i] >= '\0' && text[i] <= '~') {
		
			// Go to next UTF-8 code point
			++i;
		}
		
		// Otherwise check if UTF-8 code point is a non-overlong two byte character
		else if(length >= 1 && i < length - 1 && text[i] >= 0xC2 && text[i] <= 0xDF && text[i + 1] <= 0x80 && text[i + 1] <= 0xBF) {
		
			// Go to next UTF-8 code point
			i += 2;
		}
		
		// Otherwise check if UTF-8 code point is an excluding overlongs character
		else if(length >= 2 && i < length - 2 && text[i] == 0xE0 && text[i + 1] >= 0xA0 && text[i + 1] <= 0xBF && text[i + 2] >= 0x80 && text[i + 2] <= 0xBF) {
		
			// Go to next UTF-8 code point
			i += 3;
		}
		
		// Otherwise check if UTF-8 code point is a straight three byte character
		else if(length >= 2 && i < length - 2 && ((text[i] >= 0xE1 && text[i] <= 0xEC) || text[i] == 0xEE || text[i] == 0xEF) && text[i + 1] >= 0x80 && text[i + 1] <= 0xBF && text[i + 2] >= 0x80 && text[i + 2] <= 0xBF) {
		
			// Go to next UTF-8 code point
			i += 3;
		}
		
		// Otherwise check if UTF-8 code point is an excluding surrogates character
		else if(length >= 2 && i < length - 2 && text[i] == 0xED && text[i + 1] >= 0x80 && text[i + 1] <= 0x9F && text[i + 2] >= 0x80 && text[i + 2] <= 0xBF) {
		
			// Go to next UTF-8 code point
			i += 3;
		}
		
		// Otherwise check if UTF-8 code point is a planes one to three character
		else if(length >= 3 && i < length - 3 && text[i] == 0xF0 && text[i + 1] >= 0x90 && text[i + 1] <= 0xBF && text[i + 2] >= 0x80 && text[i + 2] <= 0xBF && text[i + 3] >= 0x80 && text[i + 3] <= 0xBF) {
		
			// Go to next UTF-8 code point
			i += 4;
		}
		
		// Otherwise check if UTF-8 code point is a planes four to fifteen character
		else if(length >= 3 && i < length - 3 && text[i] >= 0xF1 && text[i] <= 0xF3 && text[i + 1] >= 0x80 && text[i + 1] <= 0xBF && text[i + 2] >= 0x80 && text[i + 2] <= 0xBF && text[i + 3] >= 0x80 && text[i + 3] <= 0xBF) {
		
			// Go to next UTF-8 code point
			i += 4;
		}
		
		// Otherwise check if UTF-8 code point is a plane sixteen character
		else if(length >= 3 && i < length - 3 && text[i] == 0xF4 && text[i + 1] >= 0x80 && text[i + 1] <= 0xBF && text[i + 2] >= 0x80 && text[i + 2] <= 0xBF && text[i + 3] >= 0x80 && text[i + 3] <= 0xBF) {
		
			// Go to next UTF-8 code point
			i += 4;
		}
		
		// Otherwise
		else {
		
			// Return false
			return false;
		}
	}
	
	// Return true
	return true;
}

// Number of bytes required
const uint64_t Common::numberOfBytesRequired(const uint64_t numberOfBits) {

	// Return number of bytes required to store the provided number of bits
	return SaturateMath::add(numberOfBits, BITS_IN_A_BYTE - 1) / BITS_IN_A_BYTE;
}

// Clamp
const uint64_t Common::clamp(const uint64_t value, const uint64_t goal, const uint64_t clampFactor) {

	// Return clamped value
	return max(goal / clampFactor, min(value, goal * clampFactor));
}

// Damp
const uint64_t Common::damp(const uint64_t value, const uint64_t goal, const uint64_t dampFactor) {

	// Return damped value
	return (value + (dampFactor - 1) * goal) / dampFactor;
}

// Number of leading zeros
const int Common::numberOfLeadingZeros(const uint64_t value) {

	// Set number of leading zeros to the maximum number of leading zeros
	int numberOfLeadingZeros = sizeof(value) * Common::BITS_IN_A_BYTE;
	
	// Go through all non-zero trailing bits in the value
	for(uint64_t currentValue = value; currentValue; currentValue >>= 1) {
		
		// Decrement number of leading zeros
		--numberOfLeadingZeros;
	}
	
	// Return number of leasing zeros
	return numberOfLeadingZeros;
}

// Number of ones
const int Common::numberOfOnes(const uint64_t value) {

	// Set number of ones to zero
	int numberOfOnes = 0;
	
	// Go through all bits in the value
	for(uint64_t currentValue = value; currentValue; currentValue >>= 1) {
	
		// Check if bit is set
		if(currentValue & 1) {
		
			// Increment number of ones
			++numberOfOnes;
		}
	}
	
	// Return number of ones
	return numberOfOnes;
}

// To hex string
const string Common::toHexString(const uint8_t *data, const size_t length) {

	// Initialize hex string
	stringstream hexString;
	
	// Go through all bytes in the data
	for(size_t i = 0; i < length; ++i) {
	
		// Append byte as a string to the hex string
		hexString << hex << nouppercase << setw(sizeof("FF") - sizeof('\0')) << setfill('0') << static_cast<uint16_t>(data[i]); 
	}
	
	// Return hex string
	return hexString.str();
}

// Host byte order to big endian
const uint64_t Common::hostByteOrderToBigEndian(const uint64_t value) {

	// Check if Windows
	#ifdef _WIN32
	
		// Check if little endian
		#if BYTE_ORDER == LITTLE_ENDIAN

			// Return value in big endian
			return _byteswap_uint64(value);
		
		// Otherwise
		#else
		
			// Return value in big endian
			return value;
		#endif
	
	// Otherwise check if macOS
	#elif defined __APPLE__
	
		// Return value in big endian
		return OSSwapHostToBigInt64(value);
	
	// Otherwise
	#else
	
		// Return value in big endian
		return htobe64(value);
	#endif
}

// Big endian to host byte order
const uint64_t Common::bigEndianToHostByteOrder(const uint64_t value) {

	// Check if Windows
	#ifdef _WIN32
	
		// Check if little endian
		#if BYTE_ORDER == LITTLE_ENDIAN
	
			// Return value converted to host byte order
			return _byteswap_uint64(value);
		
		// Otherwise
		#else
		
			// Return value converted to host byte order
			return value;
		#endif
	
	// Otherwise check if macOS
	#elif defined __APPLE__
	
		// Return value converted to host byte order
		return OSSwapBigToHostInt64(value);
	
	// Otherwise
	#else
	
		// Return value converted to host byte order
		return be64toh(value);
	#endif
}

// Host byte order to little endian
const uint64_t Common::hostByteOrderToLittleEndian(const uint64_t value) {

	// Check if Windows
	#ifdef _WIN32
	
		// Check if little endian
		#if BYTE_ORDER == LITTLE_ENDIAN

			// Return value in little endian
			return value;
		
		// Otherwise
		#else
		
			// Return value in little endian
			return _byteswap_uint64(value);
		#endif
	
	// Otherwise check if macOS
	#elif defined __APPLE__
	
		// Return value in little endian
		return OSSwapHostToLittleInt64(value);
	
	// Otherwise
	#else
	
		// Return value in little endian
		return htole64(value);
	#endif
}

// Little endian to host byte order
const uint64_t Common::littleEndianToHostByteOrder(const uint64_t value) {

	// Check if Windows
	#ifdef _WIN32
	
		// Check if little endian
		#if BYTE_ORDER == LITTLE_ENDIAN
		
			// Return value converted to host byte order
			return value;
		
		// Otherwise
		#else
	
			// Return value converted to host byte order
			return _byteswap_uint64(value);
		#endif
	
	// Otherwise check if macOS
	#elif defined __APPLE__
	
		// Return value converted to host byte order
		return OSSwapLittleToHostInt64(value);
	
	// Otherwise
	#else
	
		// Return value converted to host byte order
		return le64toh(value);
	#endif
}

// Write uint8
void Common::writeUint8(vector<uint8_t> &buffer, const uint8_t value) {

	// Append value to buffer
	buffer.push_back(value);
}

// Write uint16
void Common::writeUint16(vector<uint8_t> &buffer, const uint16_t value) {

	// Get value in big endian
	const uint16_t valueBigEndian = htons(value);
	
	// Append value in big endian to buffer
	buffer.insert(buffer.cend(), reinterpret_cast<const uint8_t *>(&valueBigEndian), reinterpret_cast<const uint8_t *>(&valueBigEndian) + sizeof(valueBigEndian));
}

// Write uint32
void Common::writeUint32(vector<uint8_t> &buffer, const uint32_t value) {

	// Get value in big endian
	const uint32_t valueBigEndian = htonl(value);
	
	// Append value in big endian to buffer
	buffer.insert(buffer.cend(), reinterpret_cast<const uint8_t *>(&valueBigEndian), reinterpret_cast<const uint8_t *>(&valueBigEndian) + sizeof(valueBigEndian));
}

// Write uint64
void Common::writeUint64(vector<uint8_t> &buffer, const uint64_t value) {

	// Get value in big endian
	const uint64_t valueBigEndian = Common::hostByteOrderToBigEndian(value);
	
	// Append value in big endian to buffer
	buffer.insert(buffer.cend(), reinterpret_cast<const uint8_t *>(&valueBigEndian), reinterpret_cast<const uint8_t *>(&valueBigEndian) + sizeof(valueBigEndian));
}

// Write int64
void Common::writeInt64(vector<uint8_t> &buffer, const int64_t value) {

	// Return write uint64
	return writeUint64(buffer, value);
}

// Display text
void Common::displayText(const string &text) {

	// Try
	try {

		// Lock display lock
		lock_guard lock(displayLock);
		
		// Print text
		cout << text << endl;
	}
	
	// Catch errors
	catch(...) {
	
	}
}
