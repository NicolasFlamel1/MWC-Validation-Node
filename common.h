// Header guard
#ifndef COMMON_H
#define COMMON_H


// Definitions

// Check if Windows
#ifdef _WIN32

	// Set system version
	#define _WIN32_WINNT _WIN32_WINNT_VISTA
	
	// Use Unicode
	#define UNICODE
	#define _UNICODE
#endif


// Header files
#include <atomic>
#include <mutex>
#include <string>
#include <vector>

// Check if Windows
#ifdef _WIN32

	// Header files
	#include <ws2tcpip.h>
	#include <windows.h>

// Otherwise
#else

	// Header files
	#include <arpa/inet.h>
#endif

using namespace std;


// Definitions

// To string
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)


// Classes

// Common class
class Common final {

	// Public
	public:
		
		// Milliseconds in a seconds
		static const int MILLISECONDS_IN_A_SECOND;
		
		// Seconds in a minute
		static const int SECONDS_IN_A_MINUTE;
		
		// Minutes in an hour
		static const int MINUTES_IN_A_HOUR;
		
		// Hours in a day
		static const int HOURS_IN_A_DAY;
		
		// Days in a week
		static const int DAYS_IN_A_WEEK;
		
		// Weeks in a year
		static const int WEEKS_IN_A_YEAR;
		
		// Bits in a byte
		static const int BITS_IN_A_BYTE;
		
		// Bytes in a kilobyte
		static const int BYTES_IN_A_KILOBYTE;
		
		// Tor proxy address
		static const char *TOR_PROXY_ADDRESS;
		
		// Tor proxy port
		static const char *TOR_PROXY_PORT;
		
		// Constructor
		Common() = delete;
	
		// Initialize
		static const bool initialize();
		
		// Set closing
		static void setClosing();
		
		// Is closing
		static const bool isClosing();
		
		// Error occurred
		static const bool errorOccurred();
		
		// Is UTF-8
		static const bool isUtf8(const char *text, const size_t length);
		
		// Number of bytes required
		static const uint64_t numberOfBytesRequired(const uint64_t numberOfBits);
		
		// Clamp
		static const uint64_t clamp(const uint64_t value, const uint64_t goal, const uint64_t clampFactor);
		
		// Damp
		static const uint64_t damp(const uint64_t value, const uint64_t goal, const uint64_t dampFactor);
		
		// Number of leading zeros
		static const int numberOfLeadingZeros(const uint64_t value);
		
		// Number of ones
		static const int numberOfOnes(const uint64_t value);
		
		// To hex string
		static const string toHexString(const uint8_t *data, const size_t length);
		
		// To hex string
		template<typename StorageClass> static const string toHexString(const StorageClass &data);
		
		// Host byte order to big endian
		static const uint64_t hostByteOrderToBigEndian(const uint64_t value);
		
		// Big endian to host byte order
		static const uint64_t bigEndianToHostByteOrder(const uint64_t value);
		
		// Host byte order to little endian
		static const uint64_t hostByteOrderToLittleEndian(const uint64_t value);
		
		// Little endian to host byte order
		static const uint64_t littleEndianToHostByteOrder(const uint64_t value);
		
		// Write uint8
		static void writeUint8(vector<uint8_t> &buffer, const uint8_t value);
		
		// Write uint16
		static void writeUint16(vector<uint8_t> &buffer, const uint16_t value);
		
		// Write uint32
		static void writeUint32(vector<uint8_t> &buffer, const uint32_t value);
		
		// Write uint64
		static void writeUint64(vector<uint8_t> &buffer, const uint64_t value);
		
		// Write int64
		static void writeInt64(vector<uint8_t> &buffer, const int64_t value);
		
		// Display text
		static void displayText(const string &text);
		
		// Read uint8
		template<typename StorageClass> static const uint8_t readUint8(const StorageClass &buffer, const typename StorageClass::size_type offset);
		
		// Read uint16
		template<typename StorageClass> static const uint16_t readUint16(const StorageClass &buffer, const typename StorageClass::size_type offset);
		
		// Read uint32
		template<typename StorageClass> static const uint32_t readUint32(const StorageClass &buffer, const typename StorageClass::size_type offset);
		
		// Read uint64
		template<typename StorageClass> static const uint64_t readUint64(const StorageClass &buffer, const typename StorageClass::size_type offset);
		
		// Read int64
		template<typename StorageClass> static const int64_t readInt64(const StorageClass &buffer, const typename StorageClass::size_type offset);
		
	// Private
	private:
	
		// Closing
		static atomic_bool closing;
		
		// Signal occurred
		static atomic_bool signalOccurred;
		
		// Display mutex
		static mutex displayLock;
};


// Supporting function implementation

// To hex string
template<typename StorageClass> const string Common::toHexString(const StorageClass &data) {

	// Return hex string
	return toHexString(data.data(), data.size());
}

// Read uint8
template<typename StorageClass> const uint8_t Common::readUint8(const StorageClass &buffer, const typename StorageClass::size_type offset) {

	// Check if buffer doesn't contain a uint8
	if(buffer.size() < offset + sizeof(uint8_t)) {
	
		// Throw exception
		throw runtime_error("Buffer doesn't contain a uint8");
	}

	// Return value
	return buffer[offset];
}

// Read uint16
template<typename StorageClass> const uint16_t Common::readUint16(const StorageClass &buffer, const typename StorageClass::size_type offset) {

	// Check if buffer doesn't contain a uint16
	if(buffer.size() < offset + sizeof(uint16_t)) {
	
		// Throw exception
		throw runtime_error("Buffer doesn't contain a uint16");
	}

	// Get value in big endian
	const uint16_t *valueBigEndian = reinterpret_cast<const uint16_t *>(&buffer[offset]);
	
	// Return value converted to host byte order
	return ntohs(*valueBigEndian);
}

// Read uint32
template<typename StorageClass> const uint32_t Common::readUint32(const StorageClass &buffer, const typename StorageClass::size_type offset) {

	// Check if buffer doesn't contain a uint32
	if(buffer.size() < offset + sizeof(uint32_t)) {
	
		// Throw exception
		throw runtime_error("Buffer doesn't contain a uint32");
	}

	// Get value in big endian
	const uint32_t *valueBigEndian = reinterpret_cast<const uint32_t *>(&buffer[offset]);
	
	// Return value converted to host byte order
	return ntohl(*valueBigEndian);
}

// Read uint64
template<typename StorageClass> const uint64_t Common::readUint64(const StorageClass &buffer, const typename StorageClass::size_type offset) {

	// Check if buffer doesn't contain a uint64
	if(buffer.size() < offset + sizeof(uint64_t)) {
	
		// Throw exception
		throw runtime_error("Buffer doesn't contain a uint64");
	}

	// Get value in big endian
	const uint64_t *valueBigEndian = reinterpret_cast<const uint64_t *>(&buffer[offset]);

	// Return value converted to host byte order
	return Common::bigEndianToHostByteOrder(*valueBigEndian);
}

// Read int64
template<typename StorageClass> const int64_t Common::readInt64(const StorageClass &buffer, const typename StorageClass::size_type offset) {

	// Return read uint64
	return readUint64(buffer, offset);
}


#endif
