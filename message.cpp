// Header files
#include "./common.h"
#include <cstring>
#include "./consensus.h"
#include "./message.h"

using namespace std;


// Namespace
using namespace MwcValidationNode;


// Constants

// Check if floonet
#ifdef FLOONET

	// Magic numbers
	const uint8_t Message::MAGIC_NUMBERS[] = {17, 36};
	
// Otherwise
#else

	// Magic numbers
	const uint8_t Message::MAGIC_NUMBERS[] = {13, 77};
#endif

// Message header length
const size_t Message::MESSAGE_HEADER_LENGTH = sizeof(Message::MAGIC_NUMBERS) + sizeof(Message::Type) + sizeof(uint64_t);

// Maximum number of peer addresses
const uint32_t Message::MAXIMUM_NUMBER_OF_PEER_ADDRESSES = 256;

// Maximum number of headers
const uint16_t Message::MAXIMUM_NUMBER_OF_HEADERS = 512;

// Maximum number of block hashes
const uint8_t Message::MAXIMUM_NUMBER_OF_BLOCK_HASHES = 20;

// Compatible protocol versions
const set<uint32_t> Message::COMPATIBLE_PROTOCOL_VERSIONS = {
	0,
	1,
	2,
	3
};

// Maximum address length
const size_t Message::MAXIMUM_ADDRESS_LENGTH = 100;

// Maximum user agent length
const size_t Message::MAXIMUM_USER_AGENT_LENGTH = 10000;

// Minimum proof nonces bytes length
const size_t Message::MINIMUM_PROOF_NONCES_BYTES_LENGTH = 8;

// Maximum inputs length
const size_t Message::MAXIMUM_INPUTS_LENGTH = 100000;

// Maximum outputs length
const size_t Message::MAXIMUM_OUTPUTS_LENGTH = 100000;

// Maximum kernels length
const size_t Message::MAXIMUM_KERNELS_LENGTH = 100000;


// Supporting function implementation

// Create hand message
vector<uint8_t> Message::createHandMessage(const uint64_t nonce, const uint64_t totalDifficulty, const NetworkAddress &clientAddress, const NetworkAddress &serverAddress) {

	// Initialize payload
	vector<uint8_t> payload;
	
	// Append newest compatible protocol version to payload
	Common::writeUint32(payload, *COMPATIBLE_PROTOCOL_VERSIONS.crbegin());
	
	// Append capabilities to payload
	Common::writeUint32(payload, Node::CAPABILITIES);
	
	// Append nonce to payload
	Common::writeUint64(payload, nonce);
	
	// Check if total difficulty is invalid
	if(totalDifficulty < Consensus::GENESIS_BLOCK_HEADER.getTotalDifficulty()) {
	
		// Throw exception
		throw runtime_error("Total difficulty is invalid");
	}
	
	// Append total difficulty to payload
	Common::writeUint64(payload, totalDifficulty);
	
	// Append client address to payload
	writeNetworkAddress(payload, clientAddress);
	
	// Append server address to payload
	writeNetworkAddress(payload, serverAddress);
	
	// Check if user agent length is invalid
	if(sizeof(Node::USER_AGENT) - sizeof('\0') == 0) {
	
		// Throw exception
		throw runtime_error("User agent length is invalid");
	}
	
	// Check if user agent length is too big
	if(sizeof(Node::USER_AGENT) - sizeof('\0') > MAXIMUM_USER_AGENT_LENGTH) {
	
		// Throw exception
		throw runtime_error("User agent length is too big");
	}
	
	// Append user agent length to payload
	Common::writeUint64(payload, sizeof(Node::USER_AGENT) - sizeof('\0'));
	
	// Check if user agent is invalid
	if(!Common::isUtf8(Node::USER_AGENT, sizeof(Node::USER_AGENT) - sizeof('\0'))) {
	
		// Throw exception
		throw runtime_error("User agent is invalid");
	}
	
	// Append user agent to payload
	payload.insert(payload.cend(), cbegin(Node::USER_AGENT), cend(Node::USER_AGENT) - sizeof('\0'));
	
	// Get genesis block's block hash
	const array blockHash = Consensus::GENESIS_BLOCK_HEADER.getBlockHash();
	
	// Append block hash to payload
	payload.insert(payload.cend(), blockHash.cbegin(), blockHash.cend());
	
	// Create message header
	const vector messageHeader = createMessageHeader(Type::HAND, payload.size());
	
	// Prepend message header to payload
	payload.insert(payload.cbegin(), messageHeader.cbegin(), messageHeader.cend());
	
	// Return payload
	return payload;
}

// Create ping message
vector<uint8_t> Message::createPingMessage(const uint64_t totalDifficulty, const uint64_t height) {

	// Initialize payload
	vector<uint8_t> payload;
	
	// Check if total difficulty is invalid
	if(totalDifficulty < Consensus::GENESIS_BLOCK_HEADER.getTotalDifficulty()) {
	
		// Throw exception
		throw runtime_error("Total difficulty is invalid");
	}
	
	// Append total difficulty to payload
	Common::writeUint64(payload, totalDifficulty);
	
	// Append height to payload
	Common::writeUint64(payload, height);
	
	// Create message header
	const vector messageHeader = createMessageHeader(Type::PING, payload.size());
	
	// Prepend message header to payload
	payload.insert(payload.cbegin(), messageHeader.cbegin(), messageHeader.cend());
	
	// Return payload
	return payload;
}

// Create pong message
vector<uint8_t> Message::createPongMessage(const uint64_t totalDifficulty, const uint64_t height) {

	// Initialize payload
	vector<uint8_t> payload;
	
	// Check if total difficulty is invalid
	if(totalDifficulty < Consensus::GENESIS_BLOCK_HEADER.getTotalDifficulty()) {
	
		// Throw exception
		throw runtime_error("Total difficulty is invalid");
	}
	
	// Append total difficulty to payload
	Common::writeUint64(payload, totalDifficulty);
	
	// Append height to payload
	Common::writeUint64(payload, height);
	
	// Create message header
	const vector messageHeader = createMessageHeader(Type::PONG, payload.size());
	
	// Prepend message header to payload
	payload.insert(payload.cbegin(), messageHeader.cbegin(), messageHeader.cend());
	
	// Return payload
	return payload;
}

// Create get peer addresses message
vector<uint8_t> Message::createGetPeerAddressesMessage(const Node::Capabilities capabilities) {

	// Initialize payload
	vector<uint8_t> payload;
	
	// Append capabilities to payload
	Common::writeUint32(payload, capabilities);
	
	// Create message header
	const vector messageHeader = createMessageHeader(Type::GET_PEER_ADDRESSES, payload.size());
	
	// Prepend message header to payload
	payload.insert(payload.cbegin(), messageHeader.cbegin(), messageHeader.cend());
	
	// Return payload
	return payload;
}

// Create peer addresses message
vector<uint8_t> Message::createPeerAddressesMessage(const vector<NetworkAddress> &peerAddresses) {

	// Initialize payload
	vector<uint8_t> payload;
	
	// Check if peer addresses length is too big
	if(peerAddresses.size() > MAXIMUM_NUMBER_OF_PEER_ADDRESSES) {
	
		// Throw exception
		throw runtime_error("Peer addresses length is too big");
	}
	
	// Append peer addresses length to payload
	Common::writeUint32(payload, peerAddresses.size());
	
	// Go through all peer addresses
	for(const NetworkAddress &peerAddress : peerAddresses) {
	
		// Append peer address to payload
		writeNetworkAddress(payload, peerAddress);
	}
	
	// Create message header
	const vector messageHeader = createMessageHeader(Type::PEER_ADDRESSES, payload.size());
	
	// Prepend message header to payload
	payload.insert(payload.cbegin(), messageHeader.cbegin(), messageHeader.cend());
	
	// Return payload
	return payload;
}

// Create get headers message
vector<uint8_t> Message::createGetHeadersMessage(const list<array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH>> &blockHashes) {

	// Initialize payload
	vector<uint8_t> payload;
	
	// Check if block hashes length is too big
	if(blockHashes.size() > MAXIMUM_NUMBER_OF_BLOCK_HASHES) {
	
		// Throw exception
		throw runtime_error("Block hashes length is too big");
	}
	
	// Append block hashes length to payload
	Common::writeUint8(payload, blockHashes.size());
	
	// Go through all block hashes
	for(const array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH> &blockHash : blockHashes) {
	
		// Append block hash to payload
		payload.insert(payload.cend(), blockHash.cbegin(), blockHash.cend());
	}
	
	// Create message header
	const vector messageHeader = createMessageHeader(Type::GET_HEADERS, payload.size());
	
	// Prepend message header to payload
	payload.insert(payload.cbegin(), messageHeader.cbegin(), messageHeader.cend());
	
	// Return payload
	return payload;
}

// Create get block message
vector<uint8_t> Message::createGetBlockMessage(const uint8_t blockHash[Crypto::BLAKE2B_HASH_LENGTH]) {

	// Initialize payload
	vector<uint8_t> payload;
	
	// Append block hash to payload
	payload.insert(payload.cend(), blockHash, blockHash + Crypto::BLAKE2B_HASH_LENGTH);
	
	// Create message header
	const vector messageHeader = createMessageHeader(Type::GET_BLOCK, payload.size());
	
	// Prepend message header to payload
	payload.insert(payload.cbegin(), messageHeader.cbegin(), messageHeader.cend());
	
	// Return payload
	return payload;
}

// Create get transaction hash set message
vector<uint8_t> Message::createGetTransactionHashSetMessage(const uint64_t height, const uint8_t blockHash[Crypto::BLAKE2B_HASH_LENGTH]) {

	// Initialize payload
	vector<uint8_t> payload;
	
	// Append block hash to payload
	payload.insert(payload.cend(), blockHash, blockHash + Crypto::BLAKE2B_HASH_LENGTH);
	
	// Append height to payload
	Common::writeUint64(payload, height);
	
	// Create message header
	const vector messageHeader = createMessageHeader(Type::TRANSACTION_HASH_SET_REQUEST, payload.size());
	
	// Prepend message header to payload
	payload.insert(payload.cbegin(), messageHeader.cbegin(), messageHeader.cend());
	
	// Return payload
	return payload;
}

// Create error message
vector<uint8_t> Message::createErrorMessage() {

	// Initialize payload
	vector<uint8_t> payload;
	
	// Create message header
	const vector messageHeader = createMessageHeader(Type::ERROR_RESPONSE, payload.size());
	
	// Prepend message header to payload
	payload.insert(payload.cbegin(), messageHeader.cbegin(), messageHeader.cend());
	
	// Return payload
	return payload;
}

// Read message header
tuple<Message::Type, vector<uint8_t>::size_type> Message::readMessageHeader(const vector<uint8_t> &messageHeader) {

	// Check if message header isn't complete
	if(messageHeader.size() < MESSAGE_HEADER_LENGTH) {
	
		// Throw exception
		throw runtime_error("Message header isn't complete");
	}

	// Check if message header's magic numbers aren't valid
	if(memcmp(messageHeader.data(), MAGIC_NUMBERS, sizeof(MAGIC_NUMBERS))) {
	
		// Throw exception
		throw runtime_error("Magic numbers aren't valid");
	}
	
	// Get message header's type
	const Type type = (Common::readUint8(messageHeader, sizeof(MAGIC_NUMBERS)) < static_cast<underlying_type_t<Type>>(Type::UNKNOWN)) ? static_cast<Type>(Common::readUint8(messageHeader, sizeof(MAGIC_NUMBERS))) : Type::UNKNOWN;
	
	// Get message header's payload length
	const uint64_t payloadLength = Common::readUint64(messageHeader, sizeof(MAGIC_NUMBERS) + sizeof(type));
	
	// Check if payload length is too big
	if(payloadLength > getMaximumPayloadLength(type) * 4) {
	
		// Throw exception
		throw runtime_error("Payload length is too big");
	}
	
	// Return type and payload length
	return {type, payloadLength};
}

// Read shake message
tuple<Node::Capabilities, uint64_t, string, uint32_t> Message::readShakeMessage(const vector<uint8_t> &shakeMessage) {

	// Check if shake message doesn't contain a version
	if(shakeMessage.size() < MESSAGE_HEADER_LENGTH + sizeof(uint32_t)) {
	
		// Throw exception
		throw runtime_error("Shake message doesn't contain a version");
	}

	// Get protocol version from message shake
	const uint32_t protocolVersion = min(Common::readUint32(shakeMessage, MESSAGE_HEADER_LENGTH), *COMPATIBLE_PROTOCOL_VERSIONS.crbegin());
	
	// Check if protocol version isn't compatible
	if(!COMPATIBLE_PROTOCOL_VERSIONS.contains(protocolVersion)) {
	
		// Throw exception
		throw runtime_error("Protocol version isn't compatible");
	}
	
	// Check if shake message doesn't contain capabilities
	if(shakeMessage.size() < MESSAGE_HEADER_LENGTH + sizeof(protocolVersion) + sizeof(Node::Capabilities)) {
	
		// Throw exception
		throw runtime_error("Shake message doesn't contain capabilities");
	}
	
	// Get capabilities from shake message
	const Node::Capabilities capabilities = static_cast<Node::Capabilities>(Common::readUint32(shakeMessage, MESSAGE_HEADER_LENGTH + sizeof(protocolVersion)));
	
	// Check if shake message doesn't contain a total difficulty
	if(shakeMessage.size() < MESSAGE_HEADER_LENGTH + sizeof(protocolVersion) + sizeof(capabilities) + sizeof(uint64_t)) {
	
		// Throw exception
		throw runtime_error("Shake message doesn't contain a total difficulty");
	}
	
	// Get total difficulty from shake message
	const uint64_t totalDifficulty = Common::readUint64(shakeMessage, MESSAGE_HEADER_LENGTH + sizeof(protocolVersion) + sizeof(capabilities));
	
	// Check if total difficulty is invalid
	if(totalDifficulty < Consensus::GENESIS_BLOCK_HEADER.getTotalDifficulty()) {
	
		// Throw exception
		throw runtime_error("Total difficulty is invalid");
	}
	
	// Check if shake message doesn't contain a user agent length
	if(shakeMessage.size() < MESSAGE_HEADER_LENGTH + sizeof(protocolVersion) + sizeof(capabilities) + sizeof(totalDifficulty) + sizeof(uint64_t)) {
	
		// Throw exception
		throw runtime_error("Shake message doesn't contain a user agent length");
	}
	
	// Get user agent length from shake message
	const uint64_t userAgentLength = Common::readUint64(shakeMessage, MESSAGE_HEADER_LENGTH + sizeof(protocolVersion) + sizeof(capabilities) + sizeof(totalDifficulty));
	
	// Check if user agent length is invalid
	if(!userAgentLength) {
	
		// Throw exception
		throw runtime_error("User agent length is invalid");
	}
	
	// Check if user agent length is too big
	if(userAgentLength > MAXIMUM_USER_AGENT_LENGTH) {
	
		// Throw exception
		throw runtime_error("User agent length is too big");
	}
	
	// Check if shake message doesn't contain a user agent
	if(shakeMessage.size() < MESSAGE_HEADER_LENGTH + sizeof(protocolVersion) + sizeof(capabilities) + sizeof(totalDifficulty) + sizeof(userAgentLength) + userAgentLength) {
	
		// Throw exception
		throw runtime_error("Shake message doesn't contain a user agent");
	}
	
	// Get user agent from shake message
	const string userAgent(shakeMessage.cbegin() + MESSAGE_HEADER_LENGTH + sizeof(protocolVersion) + sizeof(capabilities) + sizeof(totalDifficulty) + sizeof(userAgentLength), shakeMessage.cbegin() + MESSAGE_HEADER_LENGTH + sizeof(protocolVersion) + sizeof(capabilities) + sizeof(totalDifficulty) + sizeof(userAgentLength) + userAgentLength);
	
	// Check if user agent is invalid
	if(!Common::isUtf8(userAgent.c_str(), userAgent.size())) {
	
		// Throw exception
		throw runtime_error("User agent is invalid");
	}
	
	// Check if shake message doesn't contain a genesis block hash
	if(shakeMessage.size() < MESSAGE_HEADER_LENGTH + sizeof(protocolVersion) + sizeof(capabilities) + sizeof(totalDifficulty) + sizeof(userAgentLength) + userAgentLength + Crypto::BLAKE2B_HASH_LENGTH) {
	
		// Throw exception
		throw runtime_error("Shake message doesn't contain a genesis block hash");
	}
	
	// Get genesis block hash from shake message
	const uint8_t *genesisBlockHash = &shakeMessage[MESSAGE_HEADER_LENGTH + sizeof(protocolVersion) + sizeof(capabilities) + sizeof(totalDifficulty) + sizeof(userAgentLength) + userAgentLength];
	
	// Get genesis block's block hash
	const array blockHash = Consensus::GENESIS_BLOCK_HEADER.getBlockHash();
	
	// Check if genesis block hash is invalid
	if(memcmp(genesisBlockHash, blockHash.data(), blockHash.size())) {
	
		// Throw exception
		throw runtime_error("Genesis block hash is invalid");
	}
	
	// Return capabilities, total difficulty, user agent, and protocol version
	return {capabilities, totalDifficulty, userAgent, protocolVersion};
}

// Read ping message
uint64_t Message::readPingMessage(const vector<uint8_t> &pingMessage) {

	// Check if ping message doesn't contain a total difficulty
	if(pingMessage.size() < MESSAGE_HEADER_LENGTH + sizeof(uint64_t)) {
	
		// Throw exception
		throw runtime_error("Ping message doesn't contain a total difficulty");
	}

	// Get total difficulty from ping message
	const uint64_t totalDifficulty = Common::readUint64(pingMessage, MESSAGE_HEADER_LENGTH);
	
	// Check if total difficulty is invalid
	if(totalDifficulty < Consensus::GENESIS_BLOCK_HEADER.getTotalDifficulty()) {
	
		// Throw exception
		throw runtime_error("Total difficulty is invalid");
	}
	
	// Check if ping message doesn't contain a height
	if(pingMessage.size() < MESSAGE_HEADER_LENGTH + sizeof(totalDifficulty) + sizeof(uint64_t)) {
	
		// Throw exception
		throw runtime_error("Ping message doesn't contain a height");
	}
	
	// Get height from ping message
	const uint64_t height = Common::readUint64(pingMessage, MESSAGE_HEADER_LENGTH + sizeof(totalDifficulty));
	
	// Check if height is invalid
	if(height == Consensus::GENESIS_BLOCK_HEADER.getHeight() && totalDifficulty != Consensus::GENESIS_BLOCK_HEADER.getTotalDifficulty()) {
	
		// Throw exception
		throw runtime_error("Height is invalid");
	}
	
	// Return total difficulty
	return totalDifficulty;
}

// Read pong message
uint64_t Message::readPongMessage(const vector<uint8_t> &pongMessage) {

	// Check if pong message doesn't contain a total difficulty
	if(pongMessage.size() < MESSAGE_HEADER_LENGTH + sizeof(uint64_t)) {
	
		// Throw exception
		throw runtime_error("Pong message doesn't contain a total difficulty");
	}

	// Get total difficulty from pong message
	const uint64_t totalDifficulty = Common::readUint64(pongMessage, MESSAGE_HEADER_LENGTH);
	
	// Check if total difficulty is invalid
	if(totalDifficulty < Consensus::GENESIS_BLOCK_HEADER.getTotalDifficulty()) {
	
		// Throw exception
		throw runtime_error("Total difficulty is invalid");
	}
	
	// Check if pong message doesn't contain a height
	if(pongMessage.size() < MESSAGE_HEADER_LENGTH + sizeof(totalDifficulty) + sizeof(uint64_t)) {
	
		// Throw exception
		throw runtime_error("Pong message doesn't contain a height");
	}
	
	// Get height from pong message
	const uint64_t height = Common::readUint64(pongMessage, MESSAGE_HEADER_LENGTH + sizeof(totalDifficulty));
	
	// Check if height is invalid
	if(height == Consensus::GENESIS_BLOCK_HEADER.getHeight() && totalDifficulty != Consensus::GENESIS_BLOCK_HEADER.getTotalDifficulty()) {
	
		// Throw exception
		throw runtime_error("Height is invalid");
	}
	
	// Return total difficulty
	return totalDifficulty;
}

// Read get peer addresses message
Node::Capabilities Message::readGetPeerAddressesMessage(const vector<uint8_t> &getPeerAddressesMessage) {

	// Check if get peer addresses message doesn't contain capabilities
	if(getPeerAddressesMessage.size() < MESSAGE_HEADER_LENGTH + sizeof(Node::Capabilities)) {
	
		// Throw exception
		throw runtime_error("Get peer addresses message doesn't contain capabilities");
	}

	// Get capabilities from get peer addresses message
	const Node::Capabilities capabilities = static_cast<Node::Capabilities>(Common::readUint32(getPeerAddressesMessage, MESSAGE_HEADER_LENGTH));
	
	// Return capabilities
	return capabilities;
}

// Read peer addresses message
list<NetworkAddress> Message::readPeerAddressesMessage(const vector<uint8_t> &peerAddressesMessage) {

	// Check if peer addresses message doesn't contain the number of peer addresses
	if(peerAddressesMessage.size() < MESSAGE_HEADER_LENGTH + sizeof(uint32_t)) {
	
		// Throw exception
		throw runtime_error("Peer addresses message doesn't contain the number of peer addresses");
	}
	
	// Get number of peer addresses from peer addresses message
	const uint32_t numberOfPeerAddresses = Common::readUint32(peerAddressesMessage, MESSAGE_HEADER_LENGTH);
	
	// Check if number of peer addresses is invalid
	if(numberOfPeerAddresses > MAXIMUM_NUMBER_OF_PEER_ADDRESSES) {
	
		// Throw exception
		throw runtime_error("Number of peer addresses is invalid");
	}
	
	// Initialize network addresses
	list<NetworkAddress> networkAddresses;
	
	// Go through all peer addresses
	vector<uint8_t>::size_type peerAddressOffset = MESSAGE_HEADER_LENGTH + sizeof(numberOfPeerAddresses);
	
	for(uint32_t i = 0; i < numberOfPeerAddresses; ++i) {
	
		// Read network address from peer addresses message
		NetworkAddress networkAddress = readNetworkAddress(peerAddressesMessage, peerAddressOffset);
		
		// Check network addresses's family
		switch(networkAddress.family) {
		
			// IPv4 or IPv6
			case NetworkAddress::Family::IPV4:
			case NetworkAddress::Family::IPV6:
			
				// Update peer address offset
				peerAddressOffset += sizeof(networkAddress.family) + networkAddress.addressLength + sizeof(networkAddress.port);
			
				// Break
				break;
			
			// Onion service
			case NetworkAddress::Family::ONION_SERVICE:
			
				// Update peer address offset
				peerAddressOffset += sizeof(networkAddress.family) + sizeof(uint64_t) + networkAddress.addressLength;
			
				// Break
				break;
			
			// Default
			default:
			
				// Throw exception
				throw runtime_error("Unknown network address family");
			
				// Break
				break;
		}
		
		// Append network address to list
		networkAddresses.push_back(move(networkAddress));
	}
	
	// Return network addresses
	return networkAddresses;
}

// Read header message
Header Message::readHeaderMessage(const vector<uint8_t> &headerMessage) {

	// Return reading header from header message
	return readHeader(headerMessage, MESSAGE_HEADER_LENGTH);
}

// Read headers message
list<Header> Message::readHeadersMessage(const vector<uint8_t> &headersMessage) {

	// Check if headers message doesn't contain the number of headers
	if(headersMessage.size() < MESSAGE_HEADER_LENGTH + sizeof(uint16_t)) {
	
		// Throw exception
		throw runtime_error("Headers message doesn't contain the number of headers");
	}
	
	// Get number of headers from headers message
	const uint16_t numberOfHeaders = Common::readUint16(headersMessage, MESSAGE_HEADER_LENGTH);
	
	// Check if number of headers is invalid
	if(numberOfHeaders > MAXIMUM_NUMBER_OF_HEADERS) {
	
		// Throw exception
		throw runtime_error("Number of headers is invalid");
	}

	// Initialize headers
	list<Header> headers;
	
	// Go through all headers
	vector<uint8_t>::size_type headerOffset = MESSAGE_HEADER_LENGTH + sizeof(numberOfHeaders);
	
	for(uint16_t i = 0; i < numberOfHeaders; ++i) {
	
		// Read header from headers message
		Header header = readHeader(headersMessage, headerOffset);
		
		// Set number of proof nonces bytes
		const uint64_t numberOfProofNoncesBytes = Common::numberOfBytesRequired(header.getEdgeBits() * Crypto::CUCKOO_CYCLE_NUMBER_OF_PROOF_NONCES);
		
		// Update header offset
		headerOffset += sizeof(header.getVersion()) + sizeof(header.getHeight()) + sizeof(int64_t) + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::SECP256K1_PRIVATE_KEY_LENGTH + sizeof(uint64_t) + sizeof(uint64_t) + sizeof(header.getTotalDifficulty()) + sizeof(header.getSecondaryScaling()) + sizeof(header.getNonce()) + sizeof(header.getEdgeBits()) + numberOfProofNoncesBytes;
		
		// Append header to list
		headers.push_back(move(header));
	}
	
	// Return headers
	return headers;
}

// Read block message
tuple<Header, Block> Message::readBlockMessage(const vector<uint8_t> &blockMessage, const uint32_t protocolVersion) {

	// Read header from block message
	const Header header = readHeader(blockMessage, MESSAGE_HEADER_LENGTH);
	
	// Set number of proof nonces bytes
	const uint64_t numberOfProofNoncesBytes = Common::numberOfBytesRequired(header.getEdgeBits() * Crypto::CUCKOO_CYCLE_NUMBER_OF_PROOF_NONCES);
	
	// Set header size
	const size_t headerSize = sizeof(header.getVersion()) + sizeof(header.getHeight()) + sizeof(int64_t) + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::SECP256K1_PRIVATE_KEY_LENGTH + sizeof(uint64_t) + sizeof(uint64_t) + sizeof(header.getTotalDifficulty()) + sizeof(header.getSecondaryScaling()) + sizeof(header.getNonce()) + sizeof(header.getEdgeBits()) + numberOfProofNoncesBytes;
	
	// Read transaction body from block message
	tuple transactionBody = readTransactionBody(blockMessage, MESSAGE_HEADER_LENGTH + headerSize, protocolVersion, false, header.getHeight(), header.getVersion());
	
	// Create block
	const Block block(move(get<0>(transactionBody)), move(get<1>(transactionBody)), move(get<2>(transactionBody)), move(get<3>(transactionBody)), false);
	
	// Return header and block
	return {header, block};
}

// Read compact block message
Header Message::readCompactBlockMessage(const vector<uint8_t> &compactBlockMessage) {

	// Read header from compact block message
	const Header header = readHeader(compactBlockMessage, MESSAGE_HEADER_LENGTH);
	
	// TODO Verify compact block message's nonce and body
	
	// Return header
	return header;
}

// Read stem transaction message
vector<uint8_t> Message::readStemTransactionMessage(const vector<uint8_t> &stemTransactionMessage, const uint32_t protocolVersion) {

	// Check if stem transaction message doesn't contain an offset or the number of inputs
	if(stemTransactionMessage.size() < MESSAGE_HEADER_LENGTH + Crypto::SECP256K1_PRIVATE_KEY_LENGTH + sizeof(uint64_t)) {
	
		// Throw exception
		throw runtime_error("Stem transaction message doesn't contain an offset or the number of inputs");
	}
	
	// Get number of inputs from stem transaction message
	const uint64_t numberOfInputs = Common::readUint64(stemTransactionMessage, MESSAGE_HEADER_LENGTH + Crypto::SECP256K1_PRIVATE_KEY_LENGTH);
	
	// Check if number of inputs is invalid
	if(numberOfInputs > MAXIMUM_INPUTS_LENGTH) {
	
		// Throw exception
		throw runtime_error("Number of inputs is invalid");
	}
	
	// Check if stem transaction message doesn't contain the number of outputs
	if(stemTransactionMessage.size() < MESSAGE_HEADER_LENGTH + Crypto::SECP256K1_PRIVATE_KEY_LENGTH + sizeof(numberOfInputs) + sizeof(uint64_t)) {
	
		// Throw exception
		throw runtime_error("Stem transaction message doesn't contain the number of outputs");
	}
	
	// Get number of outputs from stem transaction message
	const uint64_t numberOfOutputs = Common::readUint64(stemTransactionMessage, MESSAGE_HEADER_LENGTH + Crypto::SECP256K1_PRIVATE_KEY_LENGTH + sizeof(numberOfInputs));
	
	// Check if number of outputs is invalid
	if(numberOfOutputs > MAXIMUM_INPUTS_LENGTH) {
	
		// Throw exception
		throw runtime_error("Number of outputs is invalid");
	}
	
	// Check if stem transaction message doesn't contain the number of kernels
	if(stemTransactionMessage.size() < MESSAGE_HEADER_LENGTH + Crypto::SECP256K1_PRIVATE_KEY_LENGTH + sizeof(numberOfInputs) + sizeof(numberOfOutputs) + sizeof(uint64_t)) {
	
		// Throw exception
		throw runtime_error("Stem transaction message doesn't contain the number of kernels");
	}
	
	// Get number of kernels from stem transaction message
	const uint64_t numberOfKernels = Common::readUint64(stemTransactionMessage, MESSAGE_HEADER_LENGTH + Crypto::SECP256K1_PRIVATE_KEY_LENGTH + sizeof(numberOfInputs) + sizeof(numberOfOutputs));
	
	// Check if number of kernels is invalid
	if(numberOfKernels > MAXIMUM_KERNELS_LENGTH) {
	
		// Throw exception
		throw runtime_error("Number of kernels is invalid");
	}
	
	// Initialize offset
	vector<uint8_t>::size_type offset = MESSAGE_HEADER_LENGTH + Crypto::SECP256K1_PRIVATE_KEY_LENGTH + sizeof(numberOfInputs) + sizeof(numberOfOutputs) + sizeof(numberOfKernels);
	
	// Go through all inputs
	for(uint64_t i = 0; i < numberOfInputs; ++i) {
	
		// Check protocol version
		switch(protocolVersion) {
		
			// Zero, one, or two
			case 0:
			case 1:
			case 2:
			
				// Check if stem transaction message doesn't contain an input
				if(stemTransactionMessage.size() < offset + sizeof(Input::Features) + Crypto::COMMITMENT_LENGTH) {
				
					// Throw exception
					throw runtime_error("Stem transaction message doesn't contain an input");
				}
			
				// Update offset
				offset += sizeof(Input::Features) + Crypto::COMMITMENT_LENGTH;
			
				// Break
				break;
			
			// Three
			case 3:
			
				// Check if stem transaction message doesn't contain an input
				if(stemTransactionMessage.size() < offset + Crypto::COMMITMENT_LENGTH) {
				
					// Throw exception
					throw runtime_error("Stem transaction message doesn't contain an input");
				}
				
				// Update offset
				offset += Crypto::COMMITMENT_LENGTH;
			
				// Break
				break;
		}
	}
	
	// Go through all outputs
	for(uint64_t i = 0; i < numberOfOutputs; ++i) {
	
		// Check if stem transaction message doesn't contain an output or a rangeproof length
		if(stemTransactionMessage.size() < offset + sizeof(Output::Features) + Crypto::COMMITMENT_LENGTH + sizeof(uint64_t)) {
		
			// Throw exception
			throw runtime_error("Stem transaction message doesn't contain an output or a rangeproof length");
		}
		
		// Get rangeproof length from stem transaction message
		const uint64_t rangeproofLength = Common::readUint64(stemTransactionMessage, offset + sizeof(Output::Features) + Crypto::COMMITMENT_LENGTH);
		
		// Check if rangeproof length is invald
		if(rangeproofLength != Crypto::BULLETPROOF_LENGTH) {
		
			// Throw exception
			throw runtime_error("Rangeproof length is invalid");
		}
		
		// Check if stem transaction message doesn't contain a rangeproof
		if(stemTransactionMessage.size() < offset + sizeof(Output::Features) + Crypto::COMMITMENT_LENGTH + sizeof(rangeproofLength) + rangeproofLength) {
		
			// Throw exception
			throw runtime_error("Stem transaction message doesn't contain a rangeproof");
		}
		
		// Update offset
		offset += sizeof(Output::Features) + Crypto::COMMITMENT_LENGTH + sizeof(rangeproofLength) + rangeproofLength;
	}
	
	// Go through all kernels
	for(uint64_t i = 0; i < numberOfKernels; ++i) {
		
		// Check protocol version
		switch(protocolVersion) {
		
			// Zero or one
			case 0:
			case 1:
			
				// Check if stem transaction message doesn't contain a kernel
				if(stemTransactionMessage.size() < offset + sizeof(Kernel::Features) + sizeof(uint64_t) + sizeof(uint64_t) + Crypto::COMMITMENT_LENGTH + Crypto::SINGLE_SIGNER_SIGNATURE_LENGTH) {
				
					// Throw exception
					throw runtime_error("Stem transaction message doesn't contain a kernel");
				}
				
				// Update offset
				offset += sizeof(Kernel::Features) + sizeof(uint64_t) + sizeof(uint64_t) + Crypto::COMMITMENT_LENGTH + Crypto::SINGLE_SIGNER_SIGNATURE_LENGTH;
				
				// Break
				break;
			
			// Two or three
			case 2:
			case 3:
			
				// Check if stem transaction message doesn't contain kernel features
				if(stemTransactionMessage.size() < offset + sizeof(Kernel::Features)) {
				
					// Throw exception
					throw runtime_error("Stem transaction message doesn't contain kernel features");
				}
				
				// Get kernel features from stem transaction message
				const Kernel::Features kernelFeatures = (Common::readUint8(stemTransactionMessage, offset) < static_cast<underlying_type_t<Kernel::Features>>(Kernel::Features::UNKNOWN)) ? static_cast<Kernel::Features>(Common::readUint8(stemTransactionMessage, offset)) : Kernel::Features::UNKNOWN;
				
				// Check kernel features
				switch(kernelFeatures) {
				
					// Plain
					case Kernel::Features::PLAIN:
					
						// Check if stem transaction message doesn't contain a kernel
						if(stemTransactionMessage.size() < offset + sizeof(kernelFeatures) + sizeof(uint64_t) + Crypto::COMMITMENT_LENGTH + Crypto::SINGLE_SIGNER_SIGNATURE_LENGTH) {
						
							// Throw exception
							throw runtime_error("Stem transaction message doesn't contain a kernel");
						}
						
						// Update offset
						offset += sizeof(kernelFeatures) + sizeof(uint64_t) + Crypto::COMMITMENT_LENGTH + Crypto::SINGLE_SIGNER_SIGNATURE_LENGTH;
					
						// Break
						break;
					
					// Coinbase
					case Kernel::Features::COINBASE:
					
						// Check if stem transaction message doesn't contain a kernel
						if(stemTransactionMessage.size() < offset + sizeof(kernelFeatures) + Crypto::COMMITMENT_LENGTH + Crypto::SINGLE_SIGNER_SIGNATURE_LENGTH) {
						
							// Throw exception
							throw runtime_error("Stem transaction message doesn't contain a kernel");
						}
						
						// Update offset
						offset += sizeof(kernelFeatures) + Crypto::COMMITMENT_LENGTH + Crypto::SINGLE_SIGNER_SIGNATURE_LENGTH;
					
						// Break
						break;
				
					// Height locked
					case Kernel::Features::HEIGHT_LOCKED:
					
						// Check if stem transaction message doesn't contain a kernel
						if(stemTransactionMessage.size() < offset + sizeof(kernelFeatures) + sizeof(uint64_t) + sizeof(uint64_t) + Crypto::COMMITMENT_LENGTH + Crypto::SINGLE_SIGNER_SIGNATURE_LENGTH) {
						
							// Throw exception
							throw runtime_error("Stem transaction message doesn't contain a kernel");
						}
						
						// Update offset
						offset += sizeof(kernelFeatures) + sizeof(uint64_t) + sizeof(uint64_t) + Crypto::COMMITMENT_LENGTH + Crypto::SINGLE_SIGNER_SIGNATURE_LENGTH;
						
						// Break
						break;
					
					// No recent duplicate
					case Kernel::Features::NO_RECENT_DUPLICATE:
					
						// Check if stem transaction message doesn't contain a kernel
						if(stemTransactionMessage.size() < offset + sizeof(kernelFeatures) + sizeof(uint64_t) + sizeof(uint16_t) + Crypto::COMMITMENT_LENGTH + Crypto::SINGLE_SIGNER_SIGNATURE_LENGTH) {
						
							// Throw exception
							throw runtime_error("Stem transaction message doesn't contain a kernel");
						}
						
						// Update offset
						offset += sizeof(kernelFeatures) + sizeof(uint64_t) + sizeof(uint16_t) + Crypto::COMMITMENT_LENGTH + Crypto::SINGLE_SIGNER_SIGNATURE_LENGTH;
					
						// Break
						break;
					
					// Default
					default:
					
						// Throw exception
						throw runtime_error("Kernel features is invalid");
					
						// Break
						break;
				}
				
				// Break
				break;
		}
	}
	
	// Create message
	vector message = createMessageHeader(Type::STEM_TRANSACTION, offset - MESSAGE_HEADER_LENGTH);
	
	// Append transaction to message
	message.insert(message.cend(), stemTransactionMessage.cbegin() + MESSAGE_HEADER_LENGTH, stemTransactionMessage.cbegin() + offset);
	
	// Return message
	return message;
}

// Read transaction message
Transaction Message::readTransactionMessage(const vector<uint8_t> &transactionMessage, const uint32_t protocolVersion) {

	// Check if transaction message doesn't contain an offset
	if(transactionMessage.size() < MESSAGE_HEADER_LENGTH + Crypto::SECP256K1_PRIVATE_KEY_LENGTH) {
	
		// Throw exception
		throw runtime_error("Transaction message doesn't contain an offset");
	}
	
	// Get offset from transaction message
	const uint8_t *offset = &transactionMessage[MESSAGE_HEADER_LENGTH];
	
	// Read transaction body from transaction message
	tuple transactionBody = readTransactionBody(transactionMessage, MESSAGE_HEADER_LENGTH + Crypto::SECP256K1_PRIVATE_KEY_LENGTH, protocolVersion, true);
	
	// Return transaction
	return Transaction(offset, move(get<0>(transactionBody)), move(get<1>(transactionBody)), move(get<2>(transactionBody)), move(get<3>(transactionBody)));
}

// Read transaction hash set archive message
tuple<array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH>, uint64_t, vector<uint8_t>::size_type> Message::readTransactionHashSetArchiveMessage(const vector<uint8_t> &transactionHashSetArchiveMessage) {

	// Check if transaction hash set archive message doesn't contain a block hash
	if(transactionHashSetArchiveMessage.size() < MESSAGE_HEADER_LENGTH + Crypto::BLAKE2B_HASH_LENGTH) {
	
		// Throw exception
		throw runtime_error("Transaction hash set archive message doesn't contain a block hash");
	}
	
	// Get block hash from transaction hash set archive message
	array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH> blockHash;
	memcpy(blockHash.data(), &transactionHashSetArchiveMessage[MESSAGE_HEADER_LENGTH], blockHash.size());
	
	// Check if transaction hash set archive message doesn't contain a height
	if(transactionHashSetArchiveMessage.size() < MESSAGE_HEADER_LENGTH + blockHash.size() + sizeof(uint64_t)) {
	
		// Throw exception
		throw runtime_error("Transaction hash set archive message doesn't contain a height");
	}

	// Get height from transaction hash set archive message
	const uint64_t height = Common::readUint64(transactionHashSetArchiveMessage, MESSAGE_HEADER_LENGTH + blockHash.size());
	
	// Check if transaction hash set archive message doesn't contain an attachment length
	if(transactionHashSetArchiveMessage.size() < MESSAGE_HEADER_LENGTH + blockHash.size() + sizeof(height) + sizeof(uint64_t)) {
	
		// Throw exception
		throw runtime_error("Transaction hash set archive message doesn't contain an attachment length");
	}

	// Get attachment length from transaction hash set archive message
	const uint64_t attachmentLength = Common::readUint64(transactionHashSetArchiveMessage, MESSAGE_HEADER_LENGTH + blockHash.size() + sizeof(height));
	
	// Check if attachment length is invalid
	if(!attachmentLength || attachmentLength > numeric_limits<vector<uint8_t>::size_type>::max()) {
	
		// Throw exception
		throw runtime_error("Attachment length is invalid");
	}
	
	// Return block hash, height, and attachment length
	return {blockHash, height, attachmentLength};
}

// Read transaction kernel message
void Message::readTransactionKernelMessage(const vector<uint8_t> &transactionKernelMessage) {

	// Check if transaction kernel message doesn't contain a transaction kernel hash
	if(transactionKernelMessage.size() < MESSAGE_HEADER_LENGTH + Crypto::BLAKE2B_HASH_LENGTH) {
	
		// Throw exception
		throw runtime_error("Transaction kernel message doesn't contain a transaction kernel hash");
	}
}

// Read Tor address message
void Message::readTorAddressMessage(const vector<uint8_t> &torAddressMessage) {

	// Check if Tor address message doesn't contain a Tor address length
	if(torAddressMessage.size() < MESSAGE_HEADER_LENGTH + sizeof(uint64_t)) {
	
		// Throw exception
		throw runtime_error("Tor address message doesn't contain a Tor address length");
	}
	
	// Get Tor address length from Tor address message
	const uint64_t torAddressLength = Common::readUint64(torAddressMessage, MESSAGE_HEADER_LENGTH);
	
	// Check if Tor address length is invalid
	if(!torAddressLength) {
	
		// Throw exception
		throw runtime_error("Tor address length is invalid");
	}
	
	// Check if Tor address length is too big
	if(torAddressLength > MAXIMUM_ADDRESS_LENGTH) {
	
		// Throw exception
		throw runtime_error("Tor address length is too big");
	}
	
	// Check if Tor address message doesn't contain a Tor address
	if(torAddressMessage.size() < MESSAGE_HEADER_LENGTH + sizeof(torAddressLength) + torAddressLength) {
	
		// Throw exception
		throw runtime_error("Tor address message doesn't contain a Tor address");
	}
	
	// Get Tor address from Tor address message
	const uint8_t *torAddress = &torAddressMessage[MESSAGE_HEADER_LENGTH + sizeof(torAddressLength)];
	
	// Check if Tor address is invalid
	if(torAddressLength <= sizeof(".onion") - sizeof('\0') || memcmp(&torAddress[torAddressLength - (sizeof(".onion") - sizeof('\0'))], ".onion", sizeof(".onion") - sizeof('\0')) || memchr(torAddress, '[', torAddressLength) || memchr(torAddress, ']', torAddressLength) || memchr(torAddress, ':', torAddressLength) || !Common::isUtf8(reinterpret_cast<const char *>(torAddress), torAddressLength)) {
	
		// Throw exception
		throw runtime_error("Tor address is invalid");
	}
}

// Get maximum payload length
vector<uint8_t>::size_type Message::getMaximumPayloadLength(const Type type) {

	// Check type
	switch(type) {
	
		// Error response
		case Type::ERROR_RESPONSE:
		
			// Return maximum payload length (mwc-node uses this value)
			return 0;

		// Hand
		case Type::HAND:
		
			// Return maximum payload length (mwc-node uses this value)
			return 128;
		
		// Shake
		case Type::SHAKE:
		
			// Return maximum payload length (mwc-node uses this value)
			return 88;
		
		// Ping
		case Type::PING:
		
			// Return maximum payload length (mwc-node uses this value)
			return 16;
		
		// Pong
		case Type::PONG:
		
			// Return maximum payload length (mwc-node uses this value)
			return 16;
		
		// Get peer addresses
		case Type::GET_PEER_ADDRESSES:
		
			// Return maximum payload length (mwc-node uses this value)
			return 4;
		
		// Peer addresses
		case Type::PEER_ADDRESSES:
		
			// Return maximum payload length (mwc-node uses this value)
			return 4 + (1 + 16 + 2) * MAXIMUM_NUMBER_OF_PEER_ADDRESSES;
		
		// Get headers
		case Type::GET_HEADERS:
		
			// Return maximum payload length (mwc-node uses this value)
			return 1 + 32 * MAXIMUM_NUMBER_OF_BLOCK_HASHES;
		
		// Header
		case Type::HEADER:
		
			// Return maximum payload length (mwc-node uses this value)
			return 365;
		
		// Headers
		case Type::HEADERS:
		
			// Return maximum payload length (mwc-node uses this value)
			return 2 + 365 * MAXIMUM_NUMBER_OF_HEADERS;
		
		// Get block
		case Type::GET_BLOCK:
		
			// Return maximum payload length (mwc-node uses this value)
			return 32;
		
		// Block
		case Type::BLOCK:
		
			// Return maximum payload length (mwc-node uses this value)
			return Consensus::MAXIMUM_BLOCK_LENGTH;
		
		// Get compact block
		case Type::GET_COMPACT_BLOCK:
		
			// Return maximum payload length (mwc-node uses this value)
			return 32;
		
		// Compact block
		case Type::COMPACT_BLOCK:
		
			// Return maximum payload length (mwc-node uses this value)
			return Consensus::MAXIMUM_BLOCK_LENGTH / 10;
		
		// Stem transaction
		case Type::STEM_TRANSACTION:
		
			// Return maximum payload length (mwc-node uses this value)
			return Consensus::MAXIMUM_BLOCK_LENGTH;
		
		// Transaction
		case Type::TRANSACTION:
		
			// Return maximum payload length (mwc-node uses this value)
			return Consensus::MAXIMUM_BLOCK_LENGTH;
		
		// Transaction hash set request
		case Type::TRANSACTION_HASH_SET_REQUEST:
		
			// Return maximum payload length (mwc-node uses this value)
			return 40;
		
		// Transaction hash set archive
		case Type::TRANSACTION_HASH_SET_ARCHIVE:
		
			// Return maximum payload length (mwc-node uses this value)
			return 64;
		
		// Ban reason
		case Type::BAN_REASON:
		
			// Return maximum payload length (mwc-node uses this value)
			return 64;
		
		// Get transaction
		case Type::GET_TRANSACTION:
		
			// Return maximum payload length (mwc-node uses this value)
			return 32;
		
		// Transaction kernel
		case Type::TRANSACTION_KERNEL:
		
			// Return maximum payload length (mwc-node uses this value)
			return 32;
		
		// Tor address
		case Type::TOR_ADDRESS:
		
			// Return maximum payload length (mwc-node uses this value)
			return 128;
		
		// Default
		default:
		
			// Return maximum payload length (mwc-node uses this value)
			return Consensus::MAXIMUM_BLOCK_LENGTH;
	}
}

// Create message header
vector<uint8_t> Message::createMessageHeader(const Type type, const vector<uint8_t>::size_type payloadLength) {

	// Initialize message header
	vector<uint8_t> messageHeader;
	
	// Append magic numbers to message header
	messageHeader.insert(messageHeader.cend(), cbegin(MAGIC_NUMBERS), cend(MAGIC_NUMBERS));
	
	// Append type to message header
	Common::writeUint8(messageHeader, static_cast<underlying_type_t<Type>>(type));
	
	// Check if payload length is too big
	if(payloadLength > getMaximumPayloadLength(type) * 4) {
	
		// Throw exception
		throw runtime_error("Payload length is too big");
	}
	
	// Append payload length to message header
	Common::writeUint64(messageHeader, payloadLength);
	
	// Return message header
	return messageHeader;
}

// Write network address
void Message::writeNetworkAddress(vector<uint8_t> &buffer, const NetworkAddress &networkAddress) {

	// Check network address's family
	switch(networkAddress.family) {
	
		// IPv4
		case NetworkAddress::Family::IPV4:
		
			// Append network address's family to buffer
			Common::writeUint8(buffer, static_cast<underlying_type_t<NetworkAddress::Family>>(networkAddress.family));
			
			// Check if network address's address length is invalid
			if(networkAddress.addressLength != sizeof(in_addr)) {
			
				// Throw exception
				throw runtime_error("Address length is invalid");
			}
		
			// Append network address's address to buffer
			buffer.insert(buffer.cend(), reinterpret_cast<const uint8_t *>(networkAddress.address), reinterpret_cast<const uint8_t *>(networkAddress.address) + networkAddress.addressLength);
			
			// Check if network address's port is invalid
			if(!networkAddress.port) {
			
				// Throw exception
				throw runtime_error("Port is invalid");
			}
			
			// Append network address's port to buffer
			buffer.insert(buffer.cend(), reinterpret_cast<const uint8_t *>(&networkAddress.port), reinterpret_cast<const uint8_t *>(&networkAddress.port) + sizeof(networkAddress.port));
		
			// Break
			break;
		
		// IPv6
		case NetworkAddress::Family::IPV6:
		
			// Append network address's family to buffer
			Common::writeUint8(buffer, static_cast<underlying_type_t<NetworkAddress::Family>>(networkAddress.family));
			
			// Check if network address's address length is invalid
			if(networkAddress.addressLength != sizeof(in6_addr)) {
			
				// Throw exception
				throw runtime_error("Address length is invalid");
			}
		
			// Append network address's address to buffer
			buffer.insert(buffer.cend(), reinterpret_cast<const uint8_t *>(networkAddress.address), reinterpret_cast<const uint8_t *>(networkAddress.address) + networkAddress.addressLength);
			
			// Check if network address's port is invalid
			if(!networkAddress.port) {
			
				// Throw exception
				throw runtime_error("Port is invalid");
			}
			
			// Append network address's port to buffer
			buffer.insert(buffer.cend(), reinterpret_cast<const uint8_t *>(&networkAddress.port), reinterpret_cast<const uint8_t *>(&networkAddress.port) + sizeof(networkAddress.port));
		
			// Break
			break;
		
		// Onion service
		case NetworkAddress::Family::ONION_SERVICE:
		
			// Append network address's family to buffer
			Common::writeUint8(buffer, static_cast<underlying_type_t<NetworkAddress::Family>>(networkAddress.family));
			
			// Check if network address's address length is invalid
			if(!networkAddress.addressLength) {
			
				// Throw exception
				throw runtime_error("Address length is invalid");
			}
			
			// Check if network address's address length is too big
			if(networkAddress.addressLength > MAXIMUM_ADDRESS_LENGTH) {
			
				// Throw exception
				throw runtime_error("Address length is too big");
			}
		
			// Append network adderss's address length to buffer
			Common::writeUint64(buffer, networkAddress.addressLength);
			
			// Check if network address's address is invalid
			if(networkAddress.addressLength <= sizeof(".onion") - sizeof('\0') || memcmp(&reinterpret_cast<const uint8_t *>(networkAddress.address)[networkAddress.addressLength - (sizeof(".onion") - sizeof('\0'))], ".onion", sizeof(".onion") - sizeof('\0')) || memchr(networkAddress.address, '[', networkAddress.addressLength) || memchr(networkAddress.address, ']', networkAddress.addressLength) || memchr(networkAddress.address, ':', networkAddress.addressLength) || !Common::isUtf8(reinterpret_cast<const char *>(networkAddress.address), networkAddress.addressLength)) {
			
				// Throw exception
				throw runtime_error("Address is invalid");
			}
		
			// Append network address's address to buffer
			buffer.insert(buffer.cend(), reinterpret_cast<const uint8_t *>(networkAddress.address), reinterpret_cast<const uint8_t *>(networkAddress.address) + networkAddress.addressLength);
		
			// Break
			break;
		
		// Default
		default:
		
			// Throw exception
			throw runtime_error("Unknown network address family");
		
			// Break
			break;
	}
}

// Read network address
NetworkAddress Message::readNetworkAddress(const vector<uint8_t> &buffer, const vector<uint8_t>::size_type offset) {

	// Initialize network address
	NetworkAddress networkAddress;

	// Check if network address doesn't contain a family
	if(buffer.size() < offset + sizeof(networkAddress.family)) {
	
		// Throw exception
		throw runtime_error("Network address doesn't contain a family");
	}
	
	// Get network address's family from network address
	networkAddress.family = (Common::readUint8(buffer, offset) < static_cast<underlying_type_t<NetworkAddress::Family>>(NetworkAddress::Family::UNKNOWN)) ? static_cast<NetworkAddress::Family>(Common::readUint8(buffer, offset)) : NetworkAddress::Family::UNKNOWN;
	
	// Check network address's family
	switch(networkAddress.family) {
	
		// IPv4
		case NetworkAddress::Family::IPV4:
		
			// Set network address's address length
			networkAddress.addressLength = sizeof(in_addr);
		
			// Check if network address doesn't contain an address
			if(buffer.size() < offset + sizeof(networkAddress.family) + networkAddress.addressLength) {
			
				// Throw exception
				throw runtime_error("Network address doesn't contain an address");
			}
			
			// Set network address's address
			networkAddress.address = &buffer[offset + sizeof(networkAddress.family)];
			
			// Check if network address doesn't contain a port
			if(buffer.size() < offset + sizeof(networkAddress.family) + networkAddress.addressLength + sizeof(networkAddress.port)) {
			
				// Throw exception
				throw runtime_error("Network address doesn't contain a port");
			}
			
			// Set network address's port
			memcpy(&networkAddress.port, &buffer[offset + sizeof(networkAddress.family) + networkAddress.addressLength], sizeof(networkAddress.port));
			
			// Check if network address's port is invalid
			if(!networkAddress.port) {
			
				// Throw exception
				throw runtime_error("Port is invalid");
			}
			
			// Break
			break;
		
		// IPv6
		case NetworkAddress::Family::IPV6:
		
			// Set network address's address length
			networkAddress.addressLength = sizeof(in6_addr);
		
			// Check if network address doesn't contain an address
			if(buffer.size() < offset + sizeof(networkAddress.family) + networkAddress.addressLength) {
			
				// Throw exception
				throw runtime_error("Network address doesn't contain an address");
			}
			
			// Set network address's address
			networkAddress.address = &buffer[offset + sizeof(networkAddress.family)];
			
			// Check if network address doesn't contain a port
			if(buffer.size() < offset + sizeof(networkAddress.family) + networkAddress.addressLength + sizeof(networkAddress.port)) {
			
				// Throw exception
				throw runtime_error("Network address doesn't contain a port");
			}
			
			// Set network address's port
			memcpy(&networkAddress.port, &buffer[offset + sizeof(networkAddress.family) + networkAddress.addressLength], sizeof(networkAddress.port));
			
			// Check if network address's port is invalid
			if(!networkAddress.port) {
			
				// Throw exception
				throw runtime_error("Port is invalid");
			}
			
			// Break
			break;
		
		// Onion service
		case NetworkAddress::Family::ONION_SERVICE:
		
			{
				// Check if network address doesn't contain an address length
				if(buffer.size() < offset + sizeof(networkAddress.family) + sizeof(uint64_t)) {
				
					// Throw exception
					throw runtime_error("Network address doesn't contain an address length");
				}
			
				// Get address length from network address
				const uint64_t addressLength = Common::readUint64(buffer, offset + sizeof(networkAddress.family));
				
				// Check if address length is invalid
				if(!addressLength) {
				
					// Throw exception
					throw runtime_error("Address length is invalid");
				}
				
				// Check if address length is too big
				if(addressLength > MAXIMUM_ADDRESS_LENGTH) {
				
					// Throw exception
					throw runtime_error("Address length is too big");
				}
				
				// Set network address's address length
				networkAddress.addressLength = addressLength;
				
				// Check if network address doesn't contain an address
				if(buffer.size() < offset + sizeof(networkAddress.family) + sizeof(addressLength) + networkAddress.addressLength) {
				
					// Throw exception
					throw runtime_error("Network address doesn't contain an address");
				}
				
				// Set network address's address
				networkAddress.address = &buffer[offset + sizeof(networkAddress.family) + sizeof(addressLength)];
				
				// Check if address is invalid
				if(networkAddress.addressLength <= sizeof(".onion") - sizeof('\0') || memcmp(&reinterpret_cast<const uint8_t *>(networkAddress.address)[networkAddress.addressLength - (sizeof(".onion") - sizeof('\0'))], ".onion", sizeof(".onion") - sizeof('\0')) || memchr(networkAddress.address, '[', networkAddress.addressLength) || memchr(networkAddress.address, ']', networkAddress.addressLength) || memchr(networkAddress.address, ':', networkAddress.addressLength) || !Common::isUtf8(reinterpret_cast<const char *>(networkAddress.address), networkAddress.addressLength)) {
				
					// Throw exception
					throw runtime_error("Address is invalid");
				}
			}
		
			// Break
			break;
		
		// Default
		default:
		
			// Throw exception
			throw runtime_error("Unknown network address family");
		
			// Break
			break;
	}
	
	// Return network address
	return networkAddress;
}

// Read header
Header Message::readHeader(const vector<uint8_t> &buffer, const vector<uint8_t>::size_type offset) {

	// Check if header doesn't contain a version
	if(buffer.size() < offset + sizeof(uint16_t)) {
	
		// Throw exception
		throw runtime_error("Header doesn't contain a version");
	}
	
	// Get version from header
	const uint16_t version = Common::readUint16(buffer, offset);
	
	// Check if header doesn't contain a height
	if(buffer.size() < offset + sizeof(version) + sizeof(uint64_t)) {
	
		// Throw exception
		throw runtime_error("Header doesn't contain a height");
	}
	
	// Get height from header
	const uint64_t height = Common::readUint64(buffer, offset + sizeof(version));
	
	// Check if height is invalid
	if(height == Consensus::GENESIS_BLOCK_HEADER.getHeight()) {
	
		// Throw exception
		throw runtime_error("Height is invalid");
	}
	
	// Check if header doesn't contain a timestamp
	if(buffer.size() < offset + sizeof(version) + sizeof(height) + sizeof(int64_t)) {
	
		// Throw exception
		throw runtime_error("Header doesn't contain a timestamp");
	}
	
	// Get timestamp from header
	const int64_t timestamp = Common::readInt64(buffer, offset + sizeof(version) + sizeof(height));
	
	// Check if timestamp is invalid
	if(timestamp < chrono::duration_cast<chrono::seconds>(chrono::time_point<chrono::system_clock>::min().time_since_epoch()).count() || timestamp > chrono::duration_cast<chrono::seconds>(chrono::time_point<chrono::system_clock>::max().time_since_epoch()).count()) {
	
		// Throw exception
		throw runtime_error("Timestamp is invalid");
	}
	
	// Check if header doesn't contain a previous block hash
	if(buffer.size() < offset + sizeof(version) + sizeof(height) + sizeof(timestamp) + Crypto::BLAKE2B_HASH_LENGTH) {
	
		// Throw exception
		throw runtime_error("Header doesn't contain a previous block hash");
	}
	
	// Get previous block hash from header
	const uint8_t *previousBlockHash = &buffer[offset + sizeof(version) + sizeof(height) + sizeof(timestamp)];
	
	// Check if header doesn't contain a previous header root
	if(buffer.size() < offset + sizeof(version) + sizeof(height) + sizeof(timestamp) + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH) {
	
		// Throw exception
		throw runtime_error("Header doesn't contain a previous header root");
	}
	
	// Get previous header root from header
	const uint8_t *previousHeaderRoot = &buffer[offset + sizeof(version) + sizeof(height) + sizeof(timestamp) + Crypto::BLAKE2B_HASH_LENGTH];
	
	// Check if header doesn't contain an output root
	if(buffer.size() < offset + sizeof(version) + sizeof(height) + sizeof(timestamp) + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH) {
	
		// Throw exception
		throw runtime_error("Header doesn't contain an output root");
	}
	
	// Get output root from header
	const uint8_t *outputRoot = &buffer[offset + sizeof(version) + sizeof(height) + sizeof(timestamp) + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH];
	
	// Check if header doesn't contain a rangeproof root
	if(buffer.size() < offset + sizeof(version) + sizeof(height) + sizeof(timestamp) + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH) {
	
		// Throw exception
		throw runtime_error("Header doesn't contain a rangeproof root");
	}
	
	// Get rangeproof root from header
	const uint8_t *rangeproofRoot = &buffer[offset + sizeof(version) + sizeof(height) + sizeof(timestamp) + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH];
	
	// Check if header doesn't contain a kernel root
	if(buffer.size() < offset + sizeof(version) + sizeof(height) + sizeof(timestamp) + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH) {
	
		// Throw exception
		throw runtime_error("Header doesn't contain a kernel root");
	}
	
	// Get kernel root from header
	const uint8_t *kernelRoot = &buffer[offset + sizeof(version) + sizeof(height) + sizeof(timestamp) + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH];
	
	// Check if header doesn't contain a total kernel offset
	if(buffer.size() < offset + sizeof(version) + sizeof(height) + sizeof(timestamp) + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::SECP256K1_PRIVATE_KEY_LENGTH) {
	
		// Throw exception
		throw runtime_error("Header doesn't contain a total kernel offset");
	}
	
	// Get total kernel offset from header
	const uint8_t *totalKernelOffset = &buffer[offset + sizeof(version) + sizeof(height) + sizeof(timestamp) + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH];
	
	// Check if header doesn't contain an output Merkle mountain range size
	if(buffer.size() < offset + sizeof(version) + sizeof(height) + sizeof(timestamp) + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::SECP256K1_PRIVATE_KEY_LENGTH + sizeof(uint64_t)) {
	
		// Throw exception
		throw runtime_error("Header doesn't contain an output Merkle mountain range size");
	}
	
	// Get output Merkle mountain range size from header
	const uint64_t outputMerkleMountainRangeSize = Common::readUint64(buffer, offset + sizeof(version) + sizeof(height) + sizeof(timestamp) + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::SECP256K1_PRIVATE_KEY_LENGTH);
	
	// Check if header doesn't contain a kernel Merkle mountain range size
	if(buffer.size() < offset + sizeof(version) + sizeof(height) + sizeof(timestamp) + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::SECP256K1_PRIVATE_KEY_LENGTH + sizeof(outputMerkleMountainRangeSize) + sizeof(uint64_t)) {
	
		// Throw exception
		throw runtime_error("Header doesn't contain a kernel Merkle mountain range size");
	}
	
	// Get kernel Merkle mountain range size from header
	const uint64_t kernelMerkleMountainRangeSize = Common::readUint64(buffer, offset + sizeof(version) + sizeof(height) + sizeof(timestamp) + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::SECP256K1_PRIVATE_KEY_LENGTH + sizeof(outputMerkleMountainRangeSize));
	
	// Check if header doesn't contain a total difficulty
	if(buffer.size() < offset + sizeof(version) + sizeof(height) + sizeof(timestamp) + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::SECP256K1_PRIVATE_KEY_LENGTH + sizeof(outputMerkleMountainRangeSize) + sizeof(kernelMerkleMountainRangeSize) + sizeof(uint64_t)) {
	
		// Throw exception
		throw runtime_error("Header doesn't contain a total difficulty");
	}
	
	// Get total difficulty from header
	const uint64_t totalDifficulty = Common::readUint64(buffer, offset + sizeof(version) + sizeof(height) + sizeof(timestamp) + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::SECP256K1_PRIVATE_KEY_LENGTH + sizeof(outputMerkleMountainRangeSize) + sizeof(kernelMerkleMountainRangeSize));
	
	// Check if header doesn't contain a secondary scaling
	if(buffer.size() < offset + sizeof(version) + sizeof(height) + sizeof(timestamp) + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::SECP256K1_PRIVATE_KEY_LENGTH + sizeof(outputMerkleMountainRangeSize) + sizeof(kernelMerkleMountainRangeSize) + sizeof(totalDifficulty) + sizeof(uint32_t)) {
	
		// Throw exception
		throw runtime_error("Header doesn't contain a secondary scaling");
	}
	
	// Get secondary scaling from header
	const uint32_t secondaryScaling = Common::readUint32(buffer, offset + sizeof(version) + sizeof(height) + sizeof(timestamp) + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::SECP256K1_PRIVATE_KEY_LENGTH + sizeof(outputMerkleMountainRangeSize) + sizeof(kernelMerkleMountainRangeSize) + sizeof(totalDifficulty));
	
	// Check if header doesn't contain a nonce
	if(buffer.size() < offset + sizeof(version) + sizeof(height) + sizeof(timestamp) + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::SECP256K1_PRIVATE_KEY_LENGTH + sizeof(outputMerkleMountainRangeSize) + sizeof(kernelMerkleMountainRangeSize) + sizeof(totalDifficulty) + sizeof(secondaryScaling) + sizeof(uint64_t)) {
	
		// Throw exception
		throw runtime_error("Header doesn't contain a nonce");
	}
	
	// Get nonce from header
	const uint64_t nonce = Common::readUint64(buffer, offset + sizeof(version) + sizeof(height) + sizeof(timestamp) + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::SECP256K1_PRIVATE_KEY_LENGTH + sizeof(outputMerkleMountainRangeSize) + sizeof(kernelMerkleMountainRangeSize) + sizeof(totalDifficulty) + sizeof(secondaryScaling));
	
	// Check if header doesn't contain edge bits
	if(buffer.size() < offset + sizeof(version) + sizeof(height) + sizeof(timestamp) + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::SECP256K1_PRIVATE_KEY_LENGTH + sizeof(outputMerkleMountainRangeSize) + sizeof(kernelMerkleMountainRangeSize) + sizeof(totalDifficulty) + sizeof(secondaryScaling) + sizeof(nonce) + sizeof(uint8_t)) {
	
		// Throw exception
		throw runtime_error("Header doesn't contain edge bits");
	}
	
	// Get edge bits from header
	const uint8_t edgeBits = Common::readUint8(buffer, offset + sizeof(version) + sizeof(height) + sizeof(timestamp) + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::SECP256K1_PRIVATE_KEY_LENGTH + sizeof(outputMerkleMountainRangeSize) + sizeof(kernelMerkleMountainRangeSize) + sizeof(totalDifficulty) + sizeof(secondaryScaling) + sizeof(nonce));
	
	// Set number of proof nonces bytes
	const uint64_t numberOfProofNoncesBytes = Common::numberOfBytesRequired(edgeBits * Crypto::CUCKOO_CYCLE_NUMBER_OF_PROOF_NONCES);
	
	// Check if number of proof nonces bytes is invalid
	if(numberOfProofNoncesBytes < MINIMUM_PROOF_NONCES_BYTES_LENGTH) {
	
		// Throw exception
		throw runtime_error("Number of proof nonces bytes is invalid");
	}
	
	// Check if header doesn't contain proof nonces bytes
	if(buffer.size() < offset + sizeof(version) + sizeof(height) + sizeof(timestamp) + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::SECP256K1_PRIVATE_KEY_LENGTH + sizeof(outputMerkleMountainRangeSize) + sizeof(kernelMerkleMountainRangeSize) + sizeof(totalDifficulty) + sizeof(secondaryScaling) + sizeof(nonce) + sizeof(edgeBits) + numberOfProofNoncesBytes) {
	
		// Throw exception
		throw runtime_error("Header doesn't contain proof nonces bytes");
	}
	
	// Set proof nonces bytes
	const uint8_t *proofNoncesBytes = &buffer[offset + sizeof(version) + sizeof(height) + sizeof(timestamp) + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::BLAKE2B_HASH_LENGTH + Crypto::SECP256K1_PRIVATE_KEY_LENGTH + sizeof(outputMerkleMountainRangeSize) + sizeof(kernelMerkleMountainRangeSize) + sizeof(totalDifficulty) + sizeof(secondaryScaling) + sizeof(nonce) + sizeof(edgeBits)];
	
	// Initialize proof nonces
	uint64_t proofNonces[Crypto::CUCKOO_CYCLE_NUMBER_OF_PROOF_NONCES];
	
	// Go through all proof nonces
	for(uint64_t i = 0; i < Crypto::CUCKOO_CYCLE_NUMBER_OF_PROOF_NONCES; ++i) {
	
		// Set proof nonce to zero
		proofNonces[i] = 0;
	
		// Go through all edge bits
		for(uint8_t j = 0; j < edgeBits; ++j) {
		
			// Set bit position
			const uint64_t bitPosition = i * edgeBits + j;
		
			// Set bit in the proof nonce
			proofNonces[i] |= static_cast<uint64_t>((proofNoncesBytes[bitPosition / Common::BITS_IN_A_BYTE] >> (bitPosition % Common::BITS_IN_A_BYTE)) & 1) << j;
		}
	}
	
	// Go through all remaining bits in the proof nonces bytes
	for(uint64_t i = Crypto::CUCKOO_CYCLE_NUMBER_OF_PROOF_NONCES * edgeBits; i < numberOfProofNoncesBytes * Common::BITS_IN_A_BYTE; ++i) {
	
		// Check if proof nonces bit is invalid
		if(proofNoncesBytes[i / Common::BITS_IN_A_BYTE] & (1 << (i % Common::BITS_IN_A_BYTE))) {
		
			// Throw exception
			throw runtime_error("Proof nonces bit is invalid");
		}
	}
	
	// Return header
	return Header(version, height, chrono::time_point<chrono::system_clock>(chrono::seconds(timestamp)), previousBlockHash, previousHeaderRoot, outputRoot, rangeproofRoot, kernelRoot, totalKernelOffset, outputMerkleMountainRangeSize, kernelMerkleMountainRangeSize, totalDifficulty, secondaryScaling, nonce, edgeBits, proofNonces);
}

// Read input
Input Message::readInput(const vector<uint8_t> &buffer, const vector<uint8_t>::size_type offset, const uint32_t protocolVersion) {

	// Initialize features
	Input::Features features;
	
	// Initialize features size
	vector<uint8_t>::size_type featuresSize;
	
	// Check protocol version
	switch(protocolVersion) {
	
		// Zero, one, or two
		case 0:
		case 1:
		case 2:
		
			// Check if input doesn't contain features
			if(buffer.size() < offset + sizeof(features)) {
			
				// Throw exception
				throw runtime_error("Input doesn't contain features");
			}
			
			// Get features from input
			features = (Common::readUint8(buffer, offset) < static_cast<underlying_type_t<Input::Features>>(Input::Features::UNKNOWN)) ? static_cast<Input::Features>(Common::readUint8(buffer, offset)) : Input::Features::UNKNOWN;
			
			// Set features size to the size of the features
			featuresSize = sizeof(features);
			
			// Break
			break;
		
		// Three
		case 3:
		
			// Set features to same as output
			features = Input::Features::SAME_AS_OUTPUT;
		
			// Set features size to zero
			featuresSize = 0;
		
			// Break
			break;
		
		// Default
		default:
		
			// Throw exception
			throw runtime_error("Unknown protocol version");
		
			// Break
			break;
	}

	// Check if input doesn't contain a commitment
	if(buffer.size() < offset + featuresSize + Crypto::COMMITMENT_LENGTH) {
	
		// Throw exception
		throw runtime_error("Input doesn't contain a commitment");
	}
	
	// Get commitment from input
	const uint8_t *commitment = &buffer[offset + featuresSize];
	
	// Return input
	return Input(features, commitment);
}

// Read output
Output Message::readOutput(const vector<uint8_t> &buffer, const vector<uint8_t>::size_type offset) {

	// Check if output doesn't contain features
	if(buffer.size() < offset + sizeof(Output::Features)) {
	
		// Throw exception
		throw runtime_error("Output doesn't contain features");
	}
	
	// Get features from input
	const Output::Features features = (Common::readUint8(buffer, offset) < static_cast<underlying_type_t<Output::Features>>(Output::Features::UNKNOWN)) ? static_cast<Output::Features>(Common::readUint8(buffer, offset)) : Output::Features::UNKNOWN;
	
	// Check if output doesn't contain a commitment
	if(buffer.size() < offset + sizeof(features) + Crypto::COMMITMENT_LENGTH) {
	
		// Throw exception
		throw runtime_error("Output doesn't contain a commitment");
	}
	
	// Get commitment from output
	const uint8_t *commitment = &buffer[offset + sizeof(features)];
	
	// Return output
	return Output(features, commitment);
}

// Read rangeproof
Rangeproof Message::readRangeproof(const vector<uint8_t> &buffer, const vector<uint8_t>::size_type offset) {

	// Check if rangeproof doesn't contain a length
	if(buffer.size() < offset + sizeof(uint64_t)) {
	
		// Throw exception
		throw runtime_error("Rangeproof doesn't contain a length");
	}
	
	// Get length from rangeproof
	const uint64_t length = Common::readUint64(buffer, offset);
	
	// Check if rangeproof doesn't contain a proof
	if(buffer.size() < offset + sizeof(length) + length) {
	
		// Throw exception
		throw runtime_error("Rangeproof doesn't contain a proof");
	}
	
	// Get proof from rangeproof
	const uint8_t *proof = &buffer[offset + sizeof(length)];
	
	// Return rangeproof
	return Rangeproof(length, proof);
}

// Read kernel
Kernel Message::readKernel(const vector<uint8_t> &buffer, const vector<uint8_t>::size_type offset, const uint32_t protocolVersion) {

	// Check if kernel doesn't contain features
	if(buffer.size() < offset + sizeof(Kernel::Features)) {
	
		// Throw exception
		throw runtime_error("Kernel doesn't contain features");
	}
	
	// Get features from kernel
	const Kernel::Features features = (Common::readUint8(buffer, offset) < static_cast<underlying_type_t<Kernel::Features>>(Kernel::Features::UNKNOWN)) ? static_cast<Kernel::Features>(Common::readUint8(buffer, offset)) : Kernel::Features::UNKNOWN;
	
	// Set fee to zero
	uint64_t fee = 0;
	
	// Set lock height to zero
	uint64_t lockHeight = 0;
	
	// Set relative height to zero
	uint64_t relativeHeight = 0;
	
	// Initialize features size
	vector<uint8_t>::size_type featuresSize;
	
	// Check protocol version
	switch(protocolVersion) {
	
		// Zero or one
		case 0:
		case 1:
		
			// Check if kernel doesn't contain a fee
			if(buffer.size() < offset + sizeof(features) + sizeof(fee)) {
			
				// Throw exception
				throw runtime_error("Kernel doesn't contain a fee");
			}
			
			// Get fee from kernel
			fee = Common::readUint64(buffer, offset + sizeof(features));
			
			// Check features
			switch(features) {
			
				// Plain, coinbase, or height locked
				case Kernel::Features::PLAIN:
				case Kernel::Features::COINBASE:
				case Kernel::Features::HEIGHT_LOCKED:
				
					// Check if kernel doesn't contain a lock height
					if(buffer.size() < offset + sizeof(features) + sizeof(fee) + sizeof(lockHeight)) {
					
						// Throw exception
						throw runtime_error("Kernel doesn't contain a lock height");
					}
					
					// Get lock height from kernel
					lockHeight = Common::readUint64(buffer, offset + sizeof(features) + sizeof(fee));
					
					// Set features size
					featuresSize = sizeof(fee) + sizeof(lockHeight);
					
					// Break
					break;
				
				// No recent duplicate
				case Kernel::Features::NO_RECENT_DUPLICATE:
				
					// Check if kernel doesn't contain a relative height
					if(buffer.size() < offset + sizeof(features) + sizeof(fee) + sizeof(relativeHeight)) {
					
						// Throw exception
						throw runtime_error("Kernel doesn't contain a relative height");
					}
					
					// Get relative height from kernel
					relativeHeight = Common::readUint64(buffer, offset + sizeof(features) + sizeof(fee));
					
					// Set features size
					featuresSize = sizeof(fee) + sizeof(relativeHeight);
					
					// Break
					break;
				
				// Default
				default:
				
					// Throw exception
					throw runtime_error("Unknown features");
				
					// Break
					break;
			}
			
			// Break
			break;
		
		// Two or three
		case 2:
		case 3:
		
			// Check features
			switch(features) {
			
				// Plain
				case Kernel::Features::PLAIN:
				
					// Check if kernel doesn't contain a fee
					if(buffer.size() < offset + sizeof(features) + sizeof(fee)) {
					
						// Throw exception
						throw runtime_error("Kernel doesn't contain a fee");
					}
					
					// Get fee from kernel
					fee = Common::readUint64(buffer, offset + sizeof(features));
					
					// Set features size
					featuresSize = sizeof(fee);
				
					// Break
					break;
				
				// Coinbase
				case Kernel::Features::COINBASE:
				
					// Set features size
					featuresSize = 0;
				
					// Break
					break;
				
				// Height locked
				case Kernel::Features::HEIGHT_LOCKED:
				
					// Check if kernel doesn't contain a fee
					if(buffer.size() < offset + sizeof(features) + sizeof(fee)) {
					
						// Throw exception
						throw runtime_error("Kernel doesn't contain a fee");
					}
					
					// Get fee from kernel
					fee = Common::readUint64(buffer, offset + sizeof(features));
					
					// Check if kernel doesn't contain a lock height
					if(buffer.size() < offset + sizeof(features) + sizeof(fee) + sizeof(lockHeight)) {
					
						// Throw exception
						throw runtime_error("Kernel doesn't contain a lock height");
					}
					
					// Get lock height from kernel
					lockHeight = Common::readUint64(buffer, offset + sizeof(features) + sizeof(fee));
					
					// Set features size
					featuresSize = sizeof(fee) + sizeof(lockHeight);
				
					// Break
					break;
				
				// No recent duplicate
				case Kernel::Features::NO_RECENT_DUPLICATE:
				
					// Check if kernel doesn't contain a fee
					if(buffer.size() < offset + sizeof(features) + sizeof(fee)) {
					
						// Throw exception
						throw runtime_error("Kernel doesn't contain a fee");
					}
					
					// Get fee from kernel
					fee = Common::readUint64(buffer, offset + sizeof(features));
					
					// Check if kernel doesn't contain a relative height
					if(buffer.size() < offset + sizeof(features) + sizeof(fee) + sizeof(uint16_t)) {
					
						// Throw exception
						throw runtime_error("Kernel doesn't contain a relative height");
					}
					
					// Get relative height from kernel
					relativeHeight = Common::readUint16(buffer, offset + sizeof(features) + sizeof(fee));
					
					// Set features size
					featuresSize = sizeof(fee) + sizeof(uint16_t);
				
					// Break
					break;
				
				// Default
				default:
				
					// Throw exception
					throw runtime_error("Unknown features");
				
					// Break
					break;
			}
		
			// Break
			break;
		
		// Default
		default:
		
			// Throw exception
			throw runtime_error("Unknown protocol version");
		
			// Break
			break;
	}
	
	// Check if kernel doesn't contain an excess
	if(buffer.size() < offset + sizeof(features) + featuresSize + Crypto::COMMITMENT_LENGTH) {
	
		// Throw exception
		throw runtime_error("Kernel doesn't contain an excess");
	}
	
	// Get excess from kernel
	const uint8_t *excess = &buffer[offset + sizeof(features) + featuresSize];
	
	// Check if kernel doesn't contain a signature
	if(buffer.size() < offset + sizeof(features) + featuresSize + Crypto::COMMITMENT_LENGTH + Crypto::SINGLE_SIGNER_SIGNATURE_LENGTH) {
	
		// Throw exception
		throw runtime_error("Kernel doesn't contain a signature");
	}
	
	// Get signature from kernel
	const uint8_t *signature = &buffer[offset + sizeof(features) + featuresSize + Crypto::COMMITMENT_LENGTH];
	
	// Return kernel
	return Kernel(features, fee, lockHeight, relativeHeight, excess, signature);
}

// Read transaction body
tuple<list<Input>, list<Output>, list<Rangeproof>, list<Kernel>> Message::readTransactionBody(const vector<uint8_t> &buffer, vector<uint8_t>::size_type offset, const uint32_t protocolVersion, const bool isTransaction, const uint64_t headerHeight, const uint16_t headerVersion) {

	// Check if transaction body doesn't contain the number of inputs
	if(buffer.size() < offset + sizeof(uint64_t)) {
	
		// Throw exception
		throw runtime_error("Transaction body doesn't contain the number of inputs");
	}
	
	// Get number of inputs from transaction body
	const uint64_t numberOfInputs = Common::readUint64(buffer, offset);
	
	// Check if number of inputs is invalid
	if(numberOfInputs > MAXIMUM_INPUTS_LENGTH) {
	
		// Throw exception
		throw runtime_error("Number of inputs is invalid");
	}
	
	// Check if transaction body doesn't contain the number of outputs
	if(buffer.size() < offset + sizeof(numberOfInputs) + sizeof(uint64_t)) {
	
		// Throw exception
		throw runtime_error("Transaction body doesn't contain the number of outputs");
	}
	
	// Get number of outputs from transaction body
	const uint64_t numberOfOutputs = Common::readUint64(buffer, offset + sizeof(numberOfInputs));
	
	// Check if number of outputs is invalid
	if(numberOfOutputs > MAXIMUM_INPUTS_LENGTH) {
	
		// Throw exception
		throw runtime_error("Number of outputs is invalid");
	}
	
	// Check if transaction body doesn't contain the number of kernels
	if(buffer.size() < offset + sizeof(numberOfInputs) + sizeof(numberOfOutputs) + sizeof(uint64_t)) {
	
		// Throw exception
		throw runtime_error("Transaction body doesn't contain the number of kernels");
	}
	
	// Get number of kernels from transaction body
	const uint64_t numberOfKernels = Common::readUint64(buffer, offset + sizeof(numberOfInputs) + sizeof(numberOfOutputs));
	
	// Check if number of kernels is invalid
	if(numberOfKernels > MAXIMUM_KERNELS_LENGTH) {
	
		// Throw exception
		throw runtime_error("Number of kernels is invalid");
	}
	
	// Update offset
	offset += sizeof(numberOfInputs) + sizeof(numberOfOutputs) + sizeof(numberOfKernels);
	
	// Initialize inputs
	list<Input> inputs;
	
	// Go through all inputs
	for(uint64_t i = 0; i < numberOfInputs; ++i) {
	
		// Read input from transaction body
		Input input = readInput(buffer, offset, protocolVersion);
		
		// Check protocol version
		switch(protocolVersion) {
		
			// Zero, one, or two
			case 0:
			case 1:
			case 2:
			
				// Update offset
				offset += sizeof(input.getFeatures()) + Crypto::COMMITMENT_LENGTH;
			
				// Break
				break;
			
			// Three
			case 3:
			
				// Update offset
				offset += Crypto::COMMITMENT_LENGTH;
			
				// Break
				break;
		}
		
		// Append input to list
		inputs.push_back(move(input));
	}
	
	// Initialize outputs and rangeproofs
	list<Output> outputs;
	list<Rangeproof> rangeproofs;
	
	// Go through all outputs
	for(uint64_t i = 0; i < numberOfOutputs; ++i) {
	
		// Read output from transaction body
		Output output = readOutput(buffer, offset);
		
		// Check if output is invalid
		if(isTransaction && output.getFeatures() == Output::Features::COINBASE) {
		
			// Throw exception
			throw runtime_error("Output is invalid");
		}
		
		// Update offset
		offset += sizeof(output.getFeatures()) + Crypto::COMMITMENT_LENGTH;
		
		// Read rangeproof from transaction body
		Rangeproof rangeproof = readRangeproof(buffer, offset);
		
		// Update offset
		offset += sizeof(rangeproof.getLength()) + rangeproof.getLength();
		
		// Check if rangeproof is invalid
		if(!secp256k1_bulletproof_rangeproof_verify(Crypto::getSecp256k1Context(), Crypto::getSecp256k1ScratchSpace(), Crypto::getSecp256k1Generators(), rangeproof.getProof(), rangeproof.getLength(), nullptr, &output.getCommitment(), 1, sizeof(uint64_t) * Common::BITS_IN_A_BYTE, &secp256k1_generator_const_h, nullptr, 0)) {
		
			// Throw exception
			throw runtime_error("Rangeproof is invalid");
		}
		
		// Append output to list
		outputs.push_back(move(output));
		
		// Append rangeproof to list
		rangeproofs.push_back(move(rangeproof));
	}
	
	// Initialize kernels
	list<Kernel> kernels;
	
	// Go through all kernels
	for(uint64_t i = 0; i < numberOfKernels; ++i) {
	
		// Read kernel from transaction body
		Kernel kernel = readKernel(buffer, offset, protocolVersion);
		
		// Check kernel's features
		switch(kernel.getFeatures()) {
		
			// Coinbase
			case Kernel::Features::COINBASE:
			
				// Check if kernel is invalid
				if(isTransaction) {
				
					// Throw exception
					throw runtime_error("Kernel is invalid");
				}
				
				// Break
				break;
				
			// Height locked
			case Kernel::Features::HEIGHT_LOCKED:
			
				// Check if kernel's lock height is greater than the header's height
				if(!isTransaction && kernel.getLockHeight() > headerHeight) {
				
					// Throw exception
					throw runtime_error("Kernel's lock height is greater than the header's height");
				}
				
				// Break
				break;
			
			// No recent duplicate
			case Kernel::Features::NO_RECENT_DUPLICATE:
			
				// Check if header version is less than four
				if(!isTransaction && headerVersion < 4) {
				
					// Throw exception
					throw runtime_error("Header version is less than four");
				}
				
				// Break
				break;
			
			// Default
			default:
			
				// Break
				break;
		}
		
		// Check protocol version
		switch(protocolVersion) {
		
			// Zero or one
			case 0:
			case 1:
			
				// Update offset
				offset += sizeof(kernel.getFeatures()) + sizeof(kernel.getFee()) + sizeof(uint64_t) + Crypto::COMMITMENT_LENGTH + Crypto::SINGLE_SIGNER_SIGNATURE_LENGTH;
				
				// Break
				break;
			
			// Two or three
			case 2:
			case 3:
		
				// Check kernel's features
				switch(kernel.getFeatures()) {
				
					// Plain
					case Kernel::Features::PLAIN:
					
						// Update offset
						offset += sizeof(kernel.getFeatures()) + sizeof(kernel.getFee()) + Crypto::COMMITMENT_LENGTH + Crypto::SINGLE_SIGNER_SIGNATURE_LENGTH;
					
						// Break
						break;
					
					// Coinbase
					case Kernel::Features::COINBASE:
					
						// Update offset
						offset += sizeof(kernel.getFeatures()) + Crypto::COMMITMENT_LENGTH + Crypto::SINGLE_SIGNER_SIGNATURE_LENGTH;
					
						// Break
						break;
				
					// Height locked
					case Kernel::Features::HEIGHT_LOCKED:
					
						// Update offset
						offset += sizeof(kernel.getFeatures()) + sizeof(kernel.getFee()) + sizeof(kernel.getLockHeight()) + Crypto::COMMITMENT_LENGTH + Crypto::SINGLE_SIGNER_SIGNATURE_LENGTH;
						
						// Break
						break;
					
					// No recent duplicate
					case Kernel::Features::NO_RECENT_DUPLICATE:
					
						// Update offset
						offset += sizeof(kernel.getFeatures()) + sizeof(kernel.getFee()) + sizeof(uint16_t) + Crypto::COMMITMENT_LENGTH + Crypto::SINGLE_SIGNER_SIGNATURE_LENGTH;
					
						// Break
						break;
					
					// Default
					default:
					
						// Throw exception
						throw runtime_error("Unknown features");
					
						// Break
						break;
				}
				
				// Break
				break;
		}
		
		// Append kernel to list
		kernels.push_back(move(kernel));
	}
	
	// Return inputs, outputs, rangeproofs, and kernels
	return {inputs, outputs, rangeproofs, kernels};
}
