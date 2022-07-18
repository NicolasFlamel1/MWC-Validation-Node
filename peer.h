// Header guard
#ifndef PEER_H
#define PEER_H


// Header files
#include "./common.h"
#include <future>
#include "./node.h"

// Check if not Windows
#ifndef _WIN32

	// Header files
	#include <netdb.h>
#endif

using namespace std;


// Classes

// Peer class
class Peer final {

	// Public
	public:
	
		// Connection state
		enum class ConnectionState {
		
			// Connecting
			CONNECTING,
			
			// Disconnected
			DISCONNECTED,
		
			// Connected
			CONNECTED,
			
			// Connected and healthy
			CONNECTED_AND_HEALTHY
		};
		
		// Syncing state
		enum class SyncingState {
		
			// Not syncing
			NOT_SYNCING,
			
			// Requesting headers
			REQUESTING_HEADERS,
			
			// Requested headers
			REQUESTED_HEADERS,
			
			// Requesting transaction hash set
			REQUESTING_TRANSACTION_HASH_SET,
			
			// Requested transaction has hset
			REQUESTED_TRANSACTION_HASH_SET,
			
			// Processing transaction hash set
			PROCESSING_TRANSACTION_HASH_SET,
			
			// Requesting block
			REQUESTING_BLOCK,
			
			// Requested block
			REQUESTED_BLOCK,
			
			// Processing block
			PROCESSING_BLOCK
		};
	
		// Constructor
		explicit Peer(const string &address, Node &node, condition_variable &eventOccurred, const mt19937_64::result_type randomSeed);
		
		// Destructor
		~Peer();
		
		// Get lock
		shared_mutex &getLock();
		
		// Get connection state
		const ConnectionState getConnectionState() const;
		
		// Get syncing state
		const SyncingState getSyncingState() const;
		
		// Get identifier
		const string &getIdentifier() const;
		
		// Get total difficulty
		const uint64_t getTotalDifficulty() const;
		
		// Is message queue full
		const bool isMessageQueueFull() const;
		
		// Start syncing
		void startSyncing(const MerkleMountainRange<Header> &headers, const uint64_t syncedHeaderIndex);
	
	// Private
	private:
		
		// Communication state
		enum class CommunicationState;
		
		// Connect timeout
		static const int CONNECT_TIMEOUT;
		
		// Read timeout
		static const chrono::seconds READ_TIMEOUT;
		
		// Write timeout
		static const chrono::seconds WRITE_TIMEOUT;
		
		// Linger timeout
		static const decltype(linger::l_linger) LINGER_TIMEOUT;
		
		// Read and write poll timeout
		static const int READ_AND_WRITE_POLL_TIMEOUT;
		
		// Closing write timeout
		static const decltype(timeval::tv_sec) CLOSING_WRITE_TIMEOUT;
		
		// Connecting read timeout
		static const decltype(timeval::tv_sec) CONNECTING_READ_TIMEOUT;
		
		// Connecting write timeout
		static const decltype(timeval::tv_sec) CONNECTING_WRITE_TIMEOUT;
		
		// Peer addresses received required duration
		static const chrono::minutes PEER_ADDRESSES_RECEIVED_REQUIRED_DURATION;
		
		// Get peer addresses interval
		static const chrono::minutes GET_PEER_ADDRESSES_INTERVAL;
		
		// Ping interval
		static const chrono::seconds PING_INTERVAL;
		
		// Communication required timeout
		static const chrono::minutes COMMUNICATION_REQUIRED_TIMEOUT;
		
		// Sync stuck duration
		static const chrono::hours SYNC_STUCK_DURATION;
		
		// Check number of messages interval
		static const chrono::minutes CHECK_NUMBER_OF_MESSAGES_INTERVAL;
		
		// Maximum number of messages sent per interval
		static const int MAXIMUM_NUMBER_OF_MESSAGES_SENT_PER_INTERVAL;
		
		// Maximum number of messages received per interval
		static const int MAXIMUM_NUMBER_OF_MESSAGES_RECEIVED_PER_INTERVAL;
		
		// Reserved number of messages per interval
		static const int RESERVED_NUMBER_OF_MESSAGES_PER_INTERVAL;
		
		// Short block hash length
		static const size_t SHORT_BLOCK_HASH_LENGTH;
		
		// Get headers response required duration
		static const chrono::minutes GET_HEADERS_RESPONSE_REQUIRED_DURATION;
		
		// Get transaction hash set response required duration
		static const chrono::minutes GET_TRANSACTION_HASH_SET_RESPONSE_REQUIRED_DURATION;
		
		// Get transaction hash set attachment required duration
		static const chrono::minutes GET_TRANSACTION_HASH_SET_ATTACHMENT_REQUIRED_DURATION;
		
		// Get block response required duration
		static const chrono::minutes GET_BLOCK_RESPONSE_REQUIRED_DURATION;
		
		// Maximum allowed number of reorgs during headers sync
		static const int MAXIMUM_ALLOWED_NUMBER_OF_REORGS_DURING_HEADERS_SYNC;
		
		// Maximum allowed number of reorgs during block sync
		static const int MAXIMUM_ALLOWED_NUMBER_OF_REORGS_DURING_BLOCK_SYNC;
		
		// Connect
		void connect(const string &address);
		
		// Read and write
		void readAndWrite();
		
		// Disconnect
		void disconnect();
		
		// Process requests and/or responses
		const bool processRequestsAndOrResponses();
		
		// Get locator headers block hashes
		const list<array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH>> getLocatorHeadersBlockHashes() const;
		
		// Process header
		const bool processHeaders(list<Header> &&headers);
		
		// Process transaction hash set archive
		const bool processTransactionHashSetArchive(vector<uint8_t> &&buffer, const vector<uint8_t>::size_type transactionHashSetArchiveAttachmentIndex, const vector<uint8_t>::size_type transactionHashSetArchiveAttachmentLength, const Header *transactionHashSetArchiveHeader);
		
		// Process block
		const bool processBlock(vector<uint8_t> &&buffer);
		
		// Stop read and write
		atomic_bool stopReadAndWrite;
		
		// Connection state
		ConnectionState connectionState;
		
		// Syncing state
		SyncingState syncingState;
		
		// Communication state
		CommunicationState communicationState;
		
		// Check if Windows
		#ifdef _WIN32
		
			// Socket
			SOCKET socket;
			
		// Otherwise
		#else
		
			// Socket
			int socket;
		#endif
		
		// Read buffer
		vector<uint8_t> readBuffer;
		
		// Write buffer
		vector<uint8_t> writeBuffer;
		
		// Node
		Node &node;
		
		// Event occurred
		condition_variable &eventOccurred;
		
		// Capabilities
		Node::Capabilities capabilities;
		
		// User agent
		string userAgent;
		
		// Protocol version
		uint32_t protocolVersion;
		
		// Total difficulty
		uint64_t totalDifficulty;
		
		// Headers
		MerkleMountainRange<Header> headers;
		
		// Use node headers
		bool useNodeHeaders;
		
		// Synced header index
		uint64_t syncedHeaderIndex;
		
		// Number of messages sent
		int numberOfMessagesSent;
		
		// Number of messages received
		int numberOfMessagesReceived;
		
		// Last ping time
		chrono::time_point<chrono::steady_clock> lastPingTime;
		
		// Total difficulty last changed time
		chrono::time_point<chrono::steady_clock> totalDifficultyLastChangedTime;
		
		// Current sync response required time
		optional<chrono::time_point<chrono::steady_clock>> currentSyncResponseRequiredTime;
		
		// Number of reorgs during headers sync
		int numberOfReorgsDuringHeadersSync;
		
		// Transaction hash set response received
		bool transactionHashSetResponseReceived;
		
		// Number of reorgs during block sync
		int numberOfReorgsDuringBlockSync;
		
		// Random number generator
		mt19937_64 randomNumberGenerator;
		
		// Nonce
		const uint64_t nonce;
		
		// Lock
		shared_mutex lock;
		
		// Identifier
		string identifier;
		
		// Worker operation
		future<bool> workerOperation;
		
		// Main thread
		thread mainThread;
};


#endif
