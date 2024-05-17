// Header guard
#ifndef MWC_VALIDATION_NODE_NODE_H
#define MWC_VALIDATION_NODE_NODE_H


// Header files
#include "./common.h"
#include <condition_variable>
#include <functional>
#include <list>
#include <random>
#include <shared_mutex>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include "./block.h"
#include "./header.h"
#include "./mempool.h"
#include "./merkle_mountain_range.h"

using namespace std;


// Namespace
namespace MwcValidationNode {


// Classes

// Peer class forward declaration
class Peer;

// Node class
class Node final {

	// Public
	public:
	
		// Capabilities
		enum Capabilities : uint32_t {

			// Unknown
			UNKNOWN = 0,
			
			// Header history
			HEADER_HISTORY = 1 << 0,
			
			// Transaction hash set history
			TRANSACTION_HASH_SET_HISTORY = 1 << 1,
			
			// Peer list
			PEER_LIST = 1 << 2,
			
			// Transaction kernel hash
			TRANSACTION_KERNEL_HASH = 1 << 3,
			
			// Check if Tor is enabled
			#ifdef TOR_ENABLE
			
				// Tor address
				TOR_ADDRESS = 1 << 4,
				
				// Full node
				FULL_NODE = HEADER_HISTORY | TRANSACTION_HASH_SET_HISTORY | PEER_LIST | TRANSACTION_KERNEL_HASH | TOR_ADDRESS
				
			// Otherwise
			#else
			
				// Full node
				FULL_NODE = HEADER_HISTORY | TRANSACTION_HASH_SET_HISTORY | PEER_LIST | TRANSACTION_KERNEL_HASH
			#endif
		};
		
		// Capabilities
		static const Capabilities CAPABILITIES;
		
		// User agent
		static constexpr const char USER_AGENT[] = TOSTRING(PROGRAM_NAME) " " TOSTRING(PROGRAM_VERSION);
	
		// Constructor
		explicit Node(const string &torProxyAddress = "localhost", const string &torProxyPort = "9050");
		
		// Destructor
		~Node();
		
		// Save
		void save(ofstream &file) const;
		
		// Restore
		void restore(ifstream &file);
		
		// Set on start syncing callback
		void setOnStartSyncingCallback(const function<void()> &onStartSyncingCallback);
		
		// Set on synced callback
		void setOnSyncedCallback(const function<void()> &onSyncedCallback);
		
		// Set on error callback
		void setOnErrorCallback(const function<void()> &onErrorCallback);
		
		// Set on transaction hash set callback
		void setOnTransactionHashSetCallback(const function<bool(const MerkleMountainRange<Header> &headers, const Header &transactionHashSetArchiveHeader, const MerkleMountainRange<Kernel> &kernels, const MerkleMountainRange<Output> &outputs, const MerkleMountainRange<Rangeproof> &rangeproofs)> &onTransactionHashSetCallback);
		
		// Set on block callback
		void setOnBlockCallback(const function<bool(const Header &header, const Block &block, const uint64_t oldHeight)> &onBlockCallback);
		
		// Set on peer connect callback
		void setOnPeerConnectCallback(const function<void(const string &peerIdentifier)> &onPeerConnectCallback);
		
		// Set on peer disconnect callback
		void setOnPeerDisconnectCallback(const function<void(const string &peerIdentifier)> &onPeerDisconnectCallback);
		
		// Set on transaction callback
		void setOnTransactionCallback(const function<void(const Transaction &transaction, const unordered_set<const Transaction *> &replacedTransactions)> &onTransactionCallback);
		
		// Start
		void start(const char *customDnsSeed = nullptr, const uint64_t baseFee = DEFAULT_BASE_FEE);
		
		// Stop
		void stop();
		
		// Get peers
		list<Peer> &getPeers();
		
		// Disconnect
		void disconnect();
		
		// Get thread
		thread &getThread();
		
		// Get lock
		shared_mutex &getLock();
	
		// Get total difficulty
		uint64_t getTotalDifficulty() const;
		
		// Get height
		uint64_t getHeight() const;
		
		// Get headers
		const MerkleMountainRange<Header> &getHeaders() const;
		
		// Get kernels
		const MerkleMountainRange<Kernel> &getKernels() const;
		
		// Get outputs
		const MerkleMountainRange<Output> &getOutputs() const;
		
		// Get rangeproofs
		const MerkleMountainRange<Rangeproof> &getRangeproofs() const;
		
		// Add unused peer candidate
		void addUnusedPeerCandidate(string &&peerCandidate);
		
		// Is unused peer candidate valid
		bool isUnusedPeerCandidateValid(const string &peerCandidate) const;
		
		// Get currently used peer candidates
		unordered_set<string> &getCurrentlyUsedPeerCandidates();
		
		// Add recently attempted peer candidate
		void addRecentlyAttemptedPeerCandidate(const string &peerCandidate);
		
		// Is peer candidate recently attempted
		bool isPeerCandidateRecentlyAttempted(const string &peerCandidate) const;
		
		// Get healthy peers
		unordered_map<string, pair<chrono::time_point<chrono::steady_clock>, Capabilities>> &getHealthyPeers();
		
		// Add healthy peer
		void addHealthyPeer(const string &peer, const Capabilities capabilities);
		
		// Is peer healthy
		bool isPeerHealthy(const string &peer) const;
		
		// Add banned peer
		void addBannedPeer(const string &peer);
		
		// Is peer banned
		bool isPeerBanned(const string &peer) const;
		
		// Set sync state
		void setSyncState(MerkleMountainRange<Header> &&headers, const Header &transactionHashSetArchiveHeader, MerkleMountainRange<Kernel> &&kernels, MerkleMountainRange<Output> &&outputs, MerkleMountainRange<Rangeproof> &&rangeproofs);
		
		// Update sync state
		bool updateSyncState(MerkleMountainRange<Header> &&headers, const uint64_t syncedHeaderIndex, const Block &block);
		
		// Update sync state
		bool updateSyncState(const uint64_t syncedHeaderIndex, const Block &block);
		
		// Peer connected
		void peerConnected(const string &peerIdentifier);
		
		// Get Tor proxy address
		const string &getTorProxyAddress() const;
		
		// Get Tor proxy port
		const string &getTorProxyPort() const;
		
		// Get DNS seeds
		const unordered_set<string> &getDnsSeeds() const;
		
		// Broadcast transaction
		void broadcastTransaction(const Transaction &transaction);
		
		// Broadcast block
		void broadcastBlock(Header &&header, Block &&block);
		
		// Get mempool
		const Mempool &getMempool() const;
		
		// Add to mempool
		void addToMempool(Transaction &&transaction);
		
		// Get next block
		tuple<Header, Block> getNextBlock(const function<tuple<Output, Rangeproof, Kernel>(const uint64_t amount)> &createCoinbase);
		
	// Private
	private:
		
		// Default DNS seeds
		static const unordered_set<string> DEFAULT_DNS_SEEDS;
		
		// Desired number of peers
		static const list<Peer>::size_type DESIRED_NUMBER_OF_PEERS;
		
		// Minimum number of connected and healthy peers to start syncing
		static const list<Peer>::size_type MINIMUM_NUMBER_OF_CONNECTED_AND_HEALTHY_PEERS_TO_START_SYNCING;

		// Delay before syncing duration
		static const chrono::seconds DELAY_BEFORE_SYNCING_DURATION;
		
		// Peer event occurred timeout
		static const chrono::seconds PEER_EVENT_OCCURRED_TIMEOUT;
		
		// Unused peer candidate valid duration
		static const chrono::minutes UNUSED_PEER_CANDIDATE_VALID_DURATION;
		
		// Unused peer candidates cleanup interval
		static const chrono::minutes UNUSED_PEER_CANDIDATES_CLEANUP_INTERVAL;
		
		// Recently attempted peer candidate duration
		static const chrono::seconds RECENTLY_ATTEMPTED_PEER_CANDIDATE_DURATION;
		
		// Recently attempted peer candidates cleanup interval
		static const chrono::minutes RECENTLY_ATTEMPTED_PEER_CANDIDATES_CLEANUP_INTERVAL;
		
		// Healthy peer duration
		static const chrono::hours HEALTHY_PEER_DURATION;
		
		// Healthy peers cleanup interval
		static const chrono::hours HEALTHY_PEERS_CLEANUP_INTERVAL;
		
		// Banned peer duration
		static const chrono::hours BANNED_PEER_DURATION;
		
		// Banned peers cleanup interval
		static const chrono::hours BANNED_PEERS_CLEANUP_INTERVAL;
		
		// Remove random peer interval
		static const chrono::hours REMOVE_RANDOM_PEER_INTERVAL;
		
		// Default base fee
		static const uint64_t DEFAULT_BASE_FEE;
		
		// Cleanup mempool
		void cleanupMempool();
		
		// Apply block to sync state
		bool applyBlockToSyncState(const uint64_t syncedHeaderIndex, const Block &block);
		
		// Monitor
		void monitor();
		
		// Broadcast pending transactions
		void broadcastPendingTransactions();
		
		// Broadcast pending block
		void broadcastPendingBlock();
		
		// Remove disconnected peers
		void removeDisconnectedPeers();
		
		// Remove random peer
		void removeRandomPeer();
		
		// Connect to more peers
		void connectToMorePeers();
		
		// Sync
		void sync();
		
		// Remove invalid unused peer candidates
		void removeInvalidUnusedPeerCandidates();
		
		// Remove not recently attempted peer candidates
		void removeNotRecentlyAttemptedPeerCandidates();
		
		// Remove unhealthy peers
		void removeUnhealthyPeers();
		
		// Remove unbanned peers
		void removeUnbannedPeers();
		
		// On start syncing callback
		function<void()> onStartSyncingCallback;
		
		// On synced callback
		function<void()> onSyncedCallback;
		
		// On error callback
		function<void()> onErrorCallback;
		
		// On transaction hash set callback
		function<bool(const MerkleMountainRange<Header> &headers, const Header &transactionHashSetArchiveHeader, const MerkleMountainRange<Kernel> &kernels, const MerkleMountainRange<Output> &outputs, const MerkleMountainRange<Rangeproof> &rangeproofs)> onTransactionHashSetCallback;
		
		// On block callback
		function<bool(const Header &header, const Block &block, const uint64_t oldHeight)> onBlockCallback;
		
		// On peer connect callback
		function<void(const string &peerIdentifier)> onPeerConnectCallback;
		
		// On peer disconnect callback
		function<void(const string &peerIdentifier)> onPeerDisconnectCallback;
		
		// On transaction callback
		function<void(const Transaction &transaction, const unordered_set<const Transaction *> &replacedTransactions)> onTransactionCallback;
		
		// Tor proxy address
		const string torProxyAddress;
		
		// Tor proxy port
		const string torProxyPort;
		
		// Custom DNS seeds
		unordered_set<string> customDnsSeeds;
		
		// Base fee
		uint64_t baseFee;
		
		// Random number generator
		mt19937_64 randomNumberGenerator;
		
		// Peer event occurred
		condition_variable peerEventOccurred;
		
		// Lock
		shared_mutex lock;
	
		// Headers
		MerkleMountainRange<Header> headers;
		
		// Synced header index
		uint64_t syncedHeaderIndex;
		
		// Kernels
		MerkleMountainRange<Kernel> kernels;
		
		// Outputs
		MerkleMountainRange<Output> outputs;
		
		// Rangeproofs
		MerkleMountainRange<Rangeproof> rangeproofs;
		
		// Is syncing
		bool isSyncing;
		
		// Is synced
		bool isSynced;
		
		// Unused peer candidates
		unordered_map<string, chrono::time_point<chrono::steady_clock>> unusedPeerCandidates;
		
		// Currently used peer candidates
		unordered_set<string> currentlyUsedPeerCandidates;
		
		// Recently attempted peer candidates
		unordered_map<string, chrono::time_point<chrono::steady_clock>> recentlyAttemptedPeerCandidates;
		
		// Healthy peers
		unordered_map<string, pair<chrono::time_point<chrono::steady_clock>, Capabilities>> healthyPeers;
		
		// Banned peers
		unordered_map<string, chrono::time_point<chrono::steady_clock>> bannedPeers;
	
		// Peers
		list<Peer> peers;
		
		// Mempool
		Mempool mempool;
		
		// Pending transactions
		list<Transaction> pendingTransactions;
		
		// Pending block
		optional<const tuple<const Header, const Block>> pendingBlock;
		
		// Stop monitoring
		atomic_bool stopMonitoring;
		
		// Main thread
		thread mainThread;
};


}


#endif
