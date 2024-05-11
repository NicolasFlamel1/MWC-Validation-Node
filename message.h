// Header guard
#ifndef MWC_VALIDATION_NODE_MESSAGE_H
#define MWC_VALIDATION_NODE_MESSAGE_H


// Header files
#include "./common.h"
#include <set>
#include "./network_address.h"
#include "./node.h"

using namespace std;


// Namespace
namespace MwcValidationNode {


// Message class
class Message final {

	// Public
	public:
	
		// Type
		enum class Type : uint8_t {

			// Error response
			ERROR_RESPONSE,

			// Hand
			HAND,
			
			// Shake
			SHAKE,
			
			// Ping
			PING,
			
			// Pong
			PONG,
			
			// Get peer addresses
			GET_PEER_ADDRESSES,
			
			// Peer addresses
			PEER_ADDRESSES,
			
			// Get headers
			GET_HEADERS,
			
			// Header
			HEADER,
			
			// Headers
			HEADERS,
			
			// Get block
			GET_BLOCK,
			
			// Block
			BLOCK,
			
			// Get compact block
			GET_COMPACT_BLOCK,
			
			// Compact block
			COMPACT_BLOCK,
			
			// Stem transaction
			STEM_TRANSACTION,
			
			// Transaction
			TRANSACTION,
			
			// Transaction hash set request
			TRANSACTION_HASH_SET_REQUEST,
			
			// Transaction hash set archive
			TRANSACTION_HASH_SET_ARCHIVE,
			
			// Ban reason
			BAN_REASON,
			
			// Get transaction
			GET_TRANSACTION,
			
			// Transaction kernel
			TRANSACTION_KERNEL,
			
			// Unused
			UNUSED1,
			
			// Unused
			UNUSED2,
			
			// Tor address
			TOR_ADDRESS,
			
			// UNKNOWN
			UNKNOWN
		};
		
		// Maximum number of peer addresses
		static const uint32_t MAXIMUM_NUMBER_OF_PEER_ADDRESSES;
		
		// Message header length
		static const size_t MESSAGE_HEADER_LENGTH;
		
		// Maximum number of headers
		static const uint16_t MAXIMUM_NUMBER_OF_HEADERS;
		
		// Maximum number of block hashes
		static const uint8_t MAXIMUM_NUMBER_OF_BLOCK_HASHES;
		
		// Maximum inputs length
		static const size_t MAXIMUM_INPUTS_LENGTH;
		
		// Maximum outputs length
		static const size_t MAXIMUM_OUTPUTS_LENGTH;
		
		// Maximum kernels length
		static const size_t MAXIMUM_KERNELS_LENGTH;
		
		// Constructor
		Message() = delete;
		
		// Create hand message
		static vector<uint8_t> createHandMessage(const uint64_t nonce, const uint64_t totalDifficulty, const NetworkAddress &clientAddress, const NetworkAddress &serverAddress);
		
		// Create ping message
		static vector<uint8_t> createPingMessage(const uint64_t totalDifficulty, const uint64_t height);
		
		// Create pong message
		static vector<uint8_t> createPongMessage(const uint64_t totalDifficulty, const uint64_t height);
		
		// Create get peer addresses message
		static vector<uint8_t> createGetPeerAddressesMessage(const Node::Capabilities capabilities);
		
		// Create peer addresses message
		static vector<uint8_t> createPeerAddressesMessage(const vector<NetworkAddress> &peerAddresses);
		
		// Create get headers message
		static vector<uint8_t> createGetHeadersMessage(const list<array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH>> &blockHashes);
		
		// Create get block message
		static vector<uint8_t> createGetBlockMessage(const uint8_t blockHash[Crypto::BLAKE2B_HASH_LENGTH]);
		
		// Create get transaction hash set message
		static vector<uint8_t> createGetTransactionHashSetMessage(const uint64_t height, const uint8_t blockHash[Crypto::BLAKE2B_HASH_LENGTH]);
		
		// Create error message
		static vector<uint8_t> createErrorMessage();
		
		// Read message header
		static tuple<Type, vector<uint8_t>::size_type> readMessageHeader(const vector<uint8_t> &messageHeader);
		
		// Read shake message
		static tuple<Node::Capabilities, uint64_t, string, uint32_t> readShakeMessage(const vector<uint8_t> &shakeMessage);
		
		// Read ping message
		static uint64_t readPingMessage(const vector<uint8_t> &pingMessage);
		
		// Read pong message
		static uint64_t readPongMessage(const vector<uint8_t> &pongMessage);
		
		// Read get peer addresses message
		static Node::Capabilities readGetPeerAddressesMessage(const vector<uint8_t> &getPeerAddressesMessage);
		
		// Read peer addresses message
		static list<NetworkAddress> readPeerAddressesMessage(const vector<uint8_t> &peerAddressesMessage);
		
		// Read header message
		static Header readHeaderMessage(const vector<uint8_t> &headerMessage);
		
		// Read headers message
		static list<Header> readHeadersMessage(const vector<uint8_t> &headersMessage);
		
		// Read block message
		static tuple<Header, Block> readBlockMessage(const vector<uint8_t> &blockMessage, const uint32_t protocolVersion);
		
		// Read compact block message
		static Header readCompactBlockMessage(const vector<uint8_t> &compactBlockMessage);
		
		// Read stem transaction message
		static vector<uint8_t> readStemTransactionMessage(const vector<uint8_t> &stemTransactionMessage, const uint32_t protocolVersion);
		
		// Read transaction message
		static Transaction readTransactionMessage(const vector<uint8_t> &transactionMessage, const uint32_t protocolVersion);
		
		// Read transaction hash set archive message
		static tuple<array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH>, uint64_t, vector<uint8_t>::size_type> readTransactionHashSetArchiveMessage(const vector<uint8_t> &transactionHashSetArchiveMessage);
		
		// Read transaction kernel message
		static void readTransactionKernelMessage(const vector<uint8_t> &transactionKernelMessage);
		
		// Read Tor address message
		static void readTorAddressMessage(const vector<uint8_t> &torAddressMessage);
	
	// Private
	private:
	
		// Compatible protocol versions
		static const set<uint32_t> COMPATIBLE_PROTOCOL_VERSIONS;
	
		// Magic numbers
		static const uint8_t MAGIC_NUMBERS[];
		
		// Maximum address length
		static const size_t MAXIMUM_ADDRESS_LENGTH;
		
		// Maximum user agent length
		static const size_t MAXIMUM_USER_AGENT_LENGTH;
		
		// Minimum proof nonces bytes length
		static const size_t MINIMUM_PROOF_NONCES_BYTES_LENGTH;
		
		// Get maximum payload length
		static vector<uint8_t>::size_type getMaximumPayloadLength(const Type type);
		
		// Create message header
		static vector<uint8_t> createMessageHeader(const Type type, const vector<uint8_t>::size_type payloadLength);
		
		// Write network address
		static void writeNetworkAddress(vector<uint8_t> &buffer, const NetworkAddress &networkAddress);
		
		// Read network address
		static NetworkAddress readNetworkAddress(const vector<uint8_t> &buffer, const vector<uint8_t>::size_type offset);
		
		// Read header
		static Header readHeader(const vector<uint8_t> &buffer, const vector<uint8_t>::size_type offset);
		
		// Read input
		static Input readInput(const vector<uint8_t> &buffer, const vector<uint8_t>::size_type offset, const uint32_t protocolVersion);
		
		// Read output
		static Output readOutput(const vector<uint8_t> &buffer, const vector<uint8_t>::size_type offset);
		
		// Read rangeproof
		static Rangeproof readRangeproof(const vector<uint8_t> &buffer, const vector<uint8_t>::size_type offset);
		
		// Read kernel
		static Kernel readKernel(const vector<uint8_t> &buffer, const vector<uint8_t>::size_type offset, const uint32_t protocolVersion);
		
		// Read transaction body
		static tuple<list<Input>, list<Output>, list<Rangeproof>, list<Kernel>> readTransactionBody(const vector<uint8_t> &buffer, vector<uint8_t>::size_type offset, const uint32_t protocolVersion, const bool isTransaction, const uint64_t headerHeight = 0, const uint16_t headerVersion = Consensus::getHeaderVersion(0));
};


}


#endif
