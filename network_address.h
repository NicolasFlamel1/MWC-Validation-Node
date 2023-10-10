// Header guard
#ifndef MWC_VALIDATION_NODE_NETWORK_ADDRESS_H
#define MWC_VALIDATION_NODE_NETWORK_ADDRESS_H


// Header files
#include "./common.h"

// Check if not Windows
#ifndef _WIN32

	// Header files
	#include <netdb.h>
#endif

using namespace std;


// Namespace
namespace MwcValidationNode {


// Structures

// Network address structure
struct NetworkAddress final {

	// Family
	enum class Family : uint8_t {
	
		// IPv4
		IPV4,
		
		// IPv6
		IPV6,
		
		// Onion service
		ONION_SERVICE,
		
		// Unknown
		UNKNOWN
	};

	// Family
	Family family;
	
	// Address
	const void *address;
	
	// Address length
	size_t addressLength;
	
	// Port
	decltype(sockaddr_in::sin_port) port;
};


}


#endif
