// Header files
#include "./common.h"
#include "./consensus.h"
#include "./crypto.h"
#include "./message.h"
#include "./node.h"
#include "./peer.h"
#include "./saturate_math.h"

using namespace std;


// Namespace
using namespace MwcValidationNode;


// Constants

// Check if Tor is enabled
#ifdef TOR_ENABLE

	// Capabilities
	const Node::Capabilities Node::CAPABILITIES = static_cast<MwcValidationNode::Node::Capabilities>(Node::Capabilities::PEER_LIST | Node::Capabilities::TOR_ADDRESS);

// Otherwise
#else

	// Capabilities
	const Node::Capabilities Node::CAPABILITIES = Node::Capabilities::PEER_LIST;
#endif

// Check if floonet
#ifdef FLOONET

	// Default DNS seeds
	const unordered_set<string> Node::DEFAULT_DNS_SEEDS = {
		"seed1.mwc.mw:13414",
		"seed2.mwc.mw:13414",
		
		// Check if Tor is enabled
		#ifdef TOR_ENABLE
		
			"wt635fgwmhokk25lv7y2jvrg63mokg7nfni5owrtzalz3nx22dgjytid.onion",
			"kin4i3wohlsqlzrdwdlowh2kaa7wtkxsvp6asn7vttspnrwowgquglyd.onion",
			"vstdjxrzh67udhm3fedanul2sy7fwudasjmwxy54pady6dxclty2zmqd.onion"
		#endif
	};

// Otherwise
#else

	// Default DNS seeds
	const unordered_set<string> Node::DEFAULT_DNS_SEEDS = {
		"mainnet.seed1.mwc.mw:3414",
		"mainnet.seed2.mwc.mw:3414",
		"greg1.mainnet.seed.mwc.mw:3414",
		"greg2.mainnet.seed.mwc.mw:3414",
		"mwcseed.ddns.net:3414",
		
		// Check if Tor is enabled
		#ifdef TOR_ENABLE
		
			"uukwrgtxogz6kkpcejssb7aenb7ey7pr3h5i4llhse445dfpbp63osyd.onion",
			"xsjhexie5v7gxmdkvzkzb4qifywnolb6v22wzvppscs2gog6ljribuad.onion",
			"ltjbwsexjixh5p2qxjohxd342fxhag7ljuvkjnnmkuu6wer6cg4skoad.onion",
			"wmksifwk6gh22qydmbbnv7iyphnr7jfmwsazgxbo244mkwa2k2fol2yd.onion",
			"z5ys2rogjas46tpyu343m4tamkiog6pkpznfwpu3iff55b7xypd3wcad.onion",
			"n4ac7b65tgtachkh5ii5zytmjkbqc3bq64rhllhz4npyrbxvz7ic5byd.onion"
		#endif
	};
#endif

// Desired number of peers
const list<Peer>::size_type Node::DESIRED_NUMBER_OF_PEERS = 8;

// Minimum number of connected and healthy peers to start syncing
const list<Peer>::size_type Node::MINIMUM_NUMBER_OF_CONNECTED_AND_HEALTHY_PEERS_TO_START_SYNCING = 4;

// Delay before syncing duration
const chrono::seconds Node::DELAY_BEFORE_SYNCING_DURATION = 60s;

// Peer event occurred timeout
const chrono::seconds Node::PEER_EVENT_OCCURRED_TIMEOUT = 1s;

// Unused peer candidate valid duration
const chrono::minutes Node::UNUSED_PEER_CANDIDATE_VALID_DURATION = 30min;

// Unused peer candidates cleanup interval
const chrono::minutes Node::UNUSED_PEER_CANDIDATES_CLEANUP_INTERVAL = 60min;

// Recently attempted peer candidate duration
const chrono::seconds Node::RECENTLY_ATTEMPTED_PEER_CANDIDATE_DURATION = 30s;

// Recently attempted peer candidates cleanup interval
const chrono::minutes Node::RECENTLY_ATTEMPTED_PEER_CANDIDATES_CLEANUP_INTERVAL = 1min;

// Healthy peer duration
const chrono::hours Node::HEALTHY_PEER_DURATION = 24h;

// Healthy peers cleanup interval
const chrono::hours Node::HEALTHY_PEERS_CLEANUP_INTERVAL = 48h;

// Banned peer duration
const chrono::hours Node::BANNED_PEER_DURATION = 3h;

// Banned peers cleanup interval
const chrono::hours Node::BANNED_PEERS_CLEANUP_INTERVAL = 6h;

// Remove random peer interval
const chrono::hours Node::REMOVE_RANDOM_PEER_INTERVAL = 6h;

// Default base fee
const uint64_t Node::DEFAULT_BASE_FEE = 1000000;


// Supporting function implementation

// Constructor
Node::Node(const string &torProxyAddress, const string &torProxyPort) :

	// Set Tor proxy address
	torProxyAddress(torProxyAddress),
	
	// Set Tor proxy port
	torProxyPort(torProxyPort),
	
	// Create random number generator with a random device
	randomNumberGenerator(random_device()()),
	
	// Set headers to include the genesis block header
	headers({Consensus::GENESIS_BLOCK_HEADER}),
	
	// Set synced header index to the newest known height
	syncedHeaderIndex(headers.back().getHeight()),
	
	// Set kernels to include the genesis block kernel
	kernels({Consensus::GENESIS_BLOCK_KERNEL}),
	
	// Set outputs to include the genesis block output
	outputs({Consensus::GENESIS_BLOCK_OUTPUT}),
	
	// Set rangeproofs to include the genesis block rangeproof
	rangeproofs({Consensus::GENESIS_BLOCK_RANGEPROOF}),
	
	// Set is syncing to false
	isSyncing(false),
	
	// Set is synced to false
	isSynced(false),

	// Set stop monitoring to false
	stopMonitoring(false)
{
}

// Destructor
Node::~Node() {

	// Set stop monitoring to true
	stopMonitoring.store(true);

	// Check if main thread is running
	if(mainThread.joinable()) {
	
		// Try
		try {

			// Wait for main thread to finish
			mainThread.join();
		}
	
		// Catch errors
		catch(...) {
		
			// Set closing
			Common::setClosing();
		}
	}
}

// Save
void Node::save(ofstream &file) const {

	// Write headers to file
	headers.save(file);
		
	// Write synced header index to file
	const uint64_t serializedSyncedHeaderIndex = Common::hostByteOrderToBigEndian(syncedHeaderIndex);
	file.write(reinterpret_cast<const char *>(&serializedSyncedHeaderIndex), sizeof(serializedSyncedHeaderIndex));
	
	// Write kernels to file
	kernels.save(file);
	
	// Write outputs to file
	outputs.save(file);
	
	// Write rangeproofs to file
	rangeproofs.save(file);
	
	// Write healthy peers size to file
	const uint64_t serializedHealthyPeersSize = Common::hostByteOrderToBigEndian(healthyPeers.size());
	file.write(reinterpret_cast<const char *>(&serializedHealthyPeersSize), sizeof(serializedHealthyPeersSize));
	
	// Go through all healthy peers
	for(const pair<const string, pair<chrono::time_point<chrono::steady_clock>, Capabilities>> &healthyPeer : healthyPeers) {
	
		// Write identifier size to file
		const uint64_t serializedIdentifierSize = Common::hostByteOrderToBigEndian(healthyPeer.first.size());
		file.write(reinterpret_cast<const char *>(&serializedIdentifierSize), sizeof(serializedIdentifierSize));
		
		// Write identifier to file
		file.write(healthyPeer.first.data(), healthyPeer.first.size());
		
		// Write capabilities to file
		const uint32_t serializedCapabilities = htonl(static_cast<underlying_type_t<Capabilities>>(healthyPeer.second.second));
		file.write(reinterpret_cast<const char *>(&serializedCapabilities), sizeof(serializedCapabilities));
	}
}

// Restore
void Node::restore(ifstream &file) {

	// Read headers from file
	headers = MerkleMountainRange<Header>::restore(file);
	
	// Read synced header index from file
	uint64_t serializedSyncedHeaderIndex;
	file.read(reinterpret_cast<char *>(&serializedSyncedHeaderIndex), sizeof(serializedSyncedHeaderIndex));
	syncedHeaderIndex = Common::bigEndianToHostByteOrder(serializedSyncedHeaderIndex);
	
	// Read kernels from file
	kernels = MerkleMountainRange<Kernel>::restore(file);
	
	// Read outputs from file
	outputs = MerkleMountainRange<Output>::restore(file);
	
	// Read rangeproofs from file
	rangeproofs = MerkleMountainRange<Rangeproof>::restore(file);
	
	// Read healthy peers size from file
	uint64_t serializedHealthyPeersSize;
	file.read(reinterpret_cast<char *>(&serializedHealthyPeersSize), sizeof(serializedHealthyPeersSize));
	const uint64_t healthyPeersSize = Common::bigEndianToHostByteOrder(serializedHealthyPeersSize);
	
	// Go through all healthy peers
	for(uint64_t i = 0; i < healthyPeersSize; ++i) {
	
		// Read identifier size from file
		uint64_t serializedIdentifierSize;
		file.read(reinterpret_cast<char *>(&serializedIdentifierSize), sizeof(serializedIdentifierSize));
		
		// Read identifier from file
		string identifier(Common::bigEndianToHostByteOrder(serializedIdentifierSize), '\0');
		file.read(identifier.data(), identifier.size());
		
		// Read capabilities from file
		uint32_t serializedCapabilities;
		file.read(reinterpret_cast<char *>(&serializedCapabilities), sizeof(serializedCapabilities));
		
		// Add healthy peer to healthy peers
		healthyPeers.emplace(move(identifier), make_pair(chrono::steady_clock::now(), static_cast<Capabilities>(ntohl(serializedCapabilities))));
	}
	
	// Go through all healthy peers
	for(const pair<const string, pair<chrono::time_point<chrono::steady_clock>, Capabilities>> &healthyPeer : healthyPeers) {
	
		// Add healthy peer to unused peer candidates
		unusedPeerCandidates.emplace(healthyPeer.first, chrono::steady_clock::now());
	}
}

// Set on start syncing callback
void Node::setOnStartSyncingCallback(const function<void()> &onStartSyncingCallback) {

	// Set on start syncing callback
	this->onStartSyncingCallback = onStartSyncingCallback;
}

// Set on synced callback
void Node::setOnSyncedCallback(const function<void()> &onSyncedCallback) {

	// Set on synced callback
	this->onSyncedCallback = onSyncedCallback;
}

// Set on error callback
void Node::setOnErrorCallback(const function<void()> &onErrorCallback) {

	// Set on error callback
	this->onErrorCallback = onErrorCallback;
}

// Set on transaction hash set callback
void Node::setOnTransactionHashSetCallback(const function<bool(const MerkleMountainRange<Header> &headers, const Header &transactionHashSetArchiveHeader, const MerkleMountainRange<Kernel> &kernels, const MerkleMountainRange<Output> &outputs, const MerkleMountainRange<Rangeproof> &rangeproofs)> &onTransactionHashSetCallback) {

	// Set on transaction hash set callback
	this->onTransactionHashSetCallback = onTransactionHashSetCallback;
}

// Set on reorg callback
void Node::setOnReorgCallback(const function<bool(const uint64_t newHeight)> &onReorgCallback) {

	// Set on reorg callback
	this->onReorgCallback = onReorgCallback;
}

// Set on block callback
void Node::setOnBlockCallback(const function<bool(const Header &header, const Block &block)> &onBlockCallback) {

	// Set on block callback
	this->onBlockCallback = onBlockCallback;
}

// Set on peer connect callback
void Node::setOnPeerConnectCallback(const function<void(const string &peerIdentifier)> &onPeerConnectCallback) {

	// Set on peer connect callback
	this->onPeerConnectCallback = onPeerConnectCallback;
}

// Set on peer disconnect callback
void Node::setOnPeerDisconnectCallback(const function<void(const string &peerIdentifier)> &onPeerDisconnectCallback) {

	// Set on peer disconnect callback
	this->onPeerDisconnectCallback = onPeerDisconnectCallback;
}

// Start
void Node::start(const char *customDnsSeed) {

	// Check if custom DNS seed exists
	if(customDnsSeed) {
	
		// Set custom DNS seed
		customDnsSeeds.emplace(customDnsSeed);
	}
	
	// Create main thread
	mainThread = thread(&Node::monitor, this);
}

// Stop
void Node::stop() {

	// Set stop monitoring to true
	stopMonitoring.store(true);
	
	// Notify that an event occurred
	peerEventOccurred.notify_one();
}

// Get peers
list<Peer> &Node::getPeers() {

	// Return peers
	return peers;
}

// Disconnect
void Node::disconnect() {

	// Go through all peers
	for(Peer &peer : peers) {
		
		// Stop peer
		peer.stop();
		
		// Set error occurred to false
		bool errorOccurred = false;
		
		// Check if peer's thread is running
		if(peer.getThread().joinable()) {
		
			// Try
			try {
		
				// Wait for peer's thread to finish
				peer.getThread().join();
			}
		
			// Catch errors
			catch(...) {
			
				// Set error occurred to true
				errorOccurred = true;
			}
		}
		
		// Check if peer's worker operation is running
		if(peer.isWorkerOperationRunning()) {
		
			// Set error occurred
			errorOccurred = true;
		}
		
		// Check if error didn't occur
		if(!errorOccurred) {
		
			// Check if peer was syncing
			if(peer.getSyncingState() != Peer::SyncingState::NOT_SYNCING) {
			
				// Try
				try {
			
					// Lock for writing
					lock_guard writeLock(lock);
				
					// Check if performing initial sync and the peer obtained new headers
					if(syncedHeaderIndex == Consensus::GENESIS_BLOCK_HEADER.getHeight() && !peer.getHeaders().empty() && peer.getHeaders().back().getHeight() > syncedHeaderIndex) {
					
						// Set headers to peer's headers
						headers = move(peer.getHeaders());
					}
				}
				
				// Catch errors
				catch(...) {
				
				}
			}
		}
	}
	
	// Disconnect from peers
	peers.clear();
}

// Get thread
thread &Node::getThread() {

	// Return main thread
	return mainThread;
}

// Get lock
shared_mutex &Node::getLock() {

	// Return lock
	return lock;
}

// Get total difficulty
uint64_t Node::getTotalDifficulty() const {

	// Return total difficulty of the synced header
	return headers.getLeaf(syncedHeaderIndex)->getTotalDifficulty();
}

// Get height
uint64_t Node::getHeight() const {

	// Return height
	return syncedHeaderIndex;
}

// Get headers
const MerkleMountainRange<Header> &Node::getHeaders() const {

	// Return headers
	return headers;
}

// Get kernels
const MerkleMountainRange<Kernel> &Node::getKernels() const {

	// Return kernels
	return kernels;
}

// Get outputs
const MerkleMountainRange<Output> &Node::getOutputs() const {

	// Return outputs
	return outputs;
}

// Get rangeproofs
const MerkleMountainRange<Rangeproof> &Node::getRangeproofs() const {

	// Return rangeproofs
	return rangeproofs;
}

// Add unused peer candidate
void Node::addUnusedPeerCandidate(string &&peerCandidate) {

	// Add peer candidate to list of unused peer candidates
	unusedPeerCandidates[move(peerCandidate)] = chrono::steady_clock::now();
}

// Is unused peer candidate valid
bool Node::isUnusedPeerCandidateValid(const string &peerCandidate) const {

	// Return if unused peer candidate is valid
	return unusedPeerCandidates.contains(peerCandidate) && chrono::steady_clock::now() - unusedPeerCandidates.at(peerCandidate) <= UNUSED_PEER_CANDIDATE_VALID_DURATION;
}

// Get currently used peer candidates
unordered_set<string> &Node::getCurrentlyUsedPeerCandidates() {

	// Return currently used peer candidates
	return currentlyUsedPeerCandidates;
}

// Add recently attempted peer candidate
void Node::addRecentlyAttemptedPeerCandidate(const string &peerCandidate) {

	// Add peer candidate to list of recently attempted peer candidates
	recentlyAttemptedPeerCandidates[peerCandidate] = chrono::steady_clock::now();
}

// Is peer candidate recently attempted
bool Node::isPeerCandidateRecentlyAttempted(const string &peerCandidate) const {

	// Return if peer candidate was recently attempted
	return recentlyAttemptedPeerCandidates.contains(peerCandidate) && chrono::steady_clock::now() - recentlyAttemptedPeerCandidates.at(peerCandidate) <= RECENTLY_ATTEMPTED_PEER_CANDIDATE_DURATION;
}

// Get healthy peers
unordered_map<string, pair<chrono::time_point<chrono::steady_clock>, Node::Capabilities>> &Node::getHealthyPeers() {

	// Return healthy peers
	return healthyPeers;
}

// Add healthy peer
void Node::addHealthyPeer(const string &peer, const Capabilities capabilities) {

	// Add peer to list of healthy peers
	healthyPeers[peer] = {chrono::steady_clock::now(), capabilities};
}

// Is peer healthy
bool Node::isPeerHealthy(const string &peer) const {

	// Return if peer is healthy
	return healthyPeers.contains(peer) && (currentlyUsedPeerCandidates.contains(peer) || chrono::steady_clock::now() - healthyPeers.at(peer).first <= HEALTHY_PEER_DURATION);
}

// Add banned peer
void Node::addBannedPeer(const string &peer) {

	// Add peer to list of banned peers
	bannedPeers[peer] = chrono::steady_clock::now();
	
	// Check if peer is healthy
	if(healthyPeers.contains(peer)) {
	
		// Remove peer from healthy peers
		healthyPeers.erase(peer);
	}
}

// Is peer banned
bool Node::isPeerBanned(const string &peer) const {

	// Return if peer is banned
	return bannedPeers.contains(peer) && chrono::steady_clock::now() - bannedPeers.at(peer) <= BANNED_PEER_DURATION;
}

// Set sync state
void Node::setSyncState(MerkleMountainRange<Header> &&headers, const Header &transactionHashSetArchiveHeader, MerkleMountainRange<Kernel> &&kernels, MerkleMountainRange<Output> &&outputs, MerkleMountainRange<Rangeproof> &&rangeproofs) {

	// Check if on transaction hash set callback exists
	if(onTransactionHashSetCallback) {
	
		// Check if running on transaction hash set callback failed
		if(!onTransactionHashSetCallback(headers, transactionHashSetArchiveHeader, kernels, outputs, rangeproofs)) {
		
			// Set is syncing to false
			isSyncing = false;
			
			// Return
			return;
		}
	}
	
	// Check if pruning rangeproofs
	#ifdef PRUNE_RANGEPROOFS
	
		// Go through all rangeproofs
		for(MerkleMountainRange<Rangeproof>::const_iterator i = rangeproofs.cbegin(); i != rangeproofs.cend();) {
		
			// Get rangeproof
			const pair<uint64_t, Rangeproof> &rangeproof = *i;
			
			// Go to next rangeproof
			++i;
			
			// Prune rangeproof
			rangeproofs.pruneLeaf(rangeproof.first, true);
		}
	#endif
	
	// Check if pruning kernels
	#ifdef PRUNE_KERNELS
	
		// Go through all kernels
		for(MerkleMountainRange<Kernel>::const_iterator i = kernels.cbegin(); i != kernels.cend();) {
		
			// Get kernel
			const pair<uint64_t, Kernel> &kernel = *i;
			
			// Go to next kernel
			++i;
			
			// Prune kernel
			kernels.pruneLeaf(kernel.first, true);
		}
	
		// Set kernels minimum size to the transaction hash set archive header
		kernels.setMinimumSize(transactionHashSetArchiveHeader.getKernelMerkleMountainRangeSize());
	#endif
	
	// Check if pruning headers
	#ifdef PRUNE_HEADERS
	
		// Loop while headers can be pruned
		while(transactionHashSetArchiveHeader.getHeight() - headers.front().getHeight() > Consensus::DIFFICULTY_ADJUSTMENT_WINDOW && transactionHashSetArchiveHeader.getHeight() - headers.front().getHeight() >= Consensus::COINBASE_MATURITY) {
		
			// Prune oldest header
			headers.pruneLeaf(headers.front().getHeight(), true);
		}
	
		// Set headers minimum size to the transaction hash set archive header
		headers.setMinimumSize(MerkleMountainRange<Header>::getSizeAtNumberOfLeaves(transactionHashSetArchiveHeader.getHeight() + 1));
	#endif
	
	// Check if headers minimum size can be updated
	if(MerkleMountainRange<Header>::getSizeAtNumberOfLeaves(headers.front().getHeight() + 1) > headers.getMinimumSize()) {
	
		// Set headers minimum size to the first header
		headers.setMinimumSize(MerkleMountainRange<Header>::getSizeAtNumberOfLeaves(headers.front().getHeight() + 1));
	}
	
	// Check if kernels minimum size can be updated
	if(headers.front().getKernelMerkleMountainRangeSize() > kernels.getMinimumSize()) {
	
		// Set kernels minimum size to the first header
		kernels.setMinimumSize(headers.front().getKernelMerkleMountainRangeSize());
	}
	
	// Check if outputs minimum size can be updated
	if(headers.front().getOutputMerkleMountainRangeSize() > outputs.getMinimumSize()) {
	
		// Set outputs minimum size to the first header
		outputs.setMinimumSize(headers.front().getOutputMerkleMountainRangeSize());
	}
	
	// Check if rangeproofs minimum size can be updated
	if(headers.front().getOutputMerkleMountainRangeSize() > rangeproofs.getMinimumSize()) {
	
		// Set rangeproofs minimum size to the first header
		rangeproofs.setMinimumSize(headers.front().getOutputMerkleMountainRangeSize());
	}
	
	// Free memory
	Common::freeMemory();
	
	// Set headers to headers
	this->headers = move(headers);
	
	// Set synced header index to the transaction hash set archive header's height
	this->syncedHeaderIndex = transactionHashSetArchiveHeader.getHeight();
	
	// Set kernels to kernels
	this->kernels = move(kernels);
	
	// Set outputs to outputs
	this->outputs = move(outputs);
	
	// Set rangeproofs to rangeproofs
	this->rangeproofs = move(rangeproofs);
	
	// Clear mempool
	mempool.clear();
	
	// Set is syncing to false
	isSyncing = false;
	
	// Set is synced to false
	isSynced = false;
}

// Update sync state
bool Node::updateSyncState(MerkleMountainRange<Header> &&headers, const uint64_t syncedHeaderIndex, const Block &block) {

	// Check if a reorg occurred
	if(this->syncedHeaderIndex >= syncedHeaderIndex) {
	
		// Check if on reorg callback exists
		if(onReorgCallback) {
		
			// Check if running on reorg callback failed
			if(!onReorgCallback(syncedHeaderIndex)) {
			
				// Set is syncing to false
				isSyncing = false;
				
				// Return true
				return true;
			}
		}
	}
	
	// Set headers to headers
	this->headers = move(headers);
	
	// Return applying block to sync state
	return applyBlockToSyncState(syncedHeaderIndex, block);
}

// Update sync state
bool Node::updateSyncState(const uint64_t syncedHeaderIndex, const Block &block) {

	// Check if a reorg occurred
	if(this->syncedHeaderIndex >= syncedHeaderIndex) {
	
		// Check if on reorg callback exists
		if(onReorgCallback) {
		
			// Check if running on reorg callback failed
			if(!onReorgCallback(syncedHeaderIndex)) {
			
				// Set is syncing to false
				isSyncing = false;
				
				// Return true
				return true;
			}
		}
	}
	
	// Return applying block to sync state
	return applyBlockToSyncState(syncedHeaderIndex, block);
}

// Peer connected
void Node::peerConnected(const string &peerIdentifier) {

	// Check if on peer connect callback exists
	if(onPeerConnectCallback) {
	
		// Run on peer connect callback
		onPeerConnectCallback(peerIdentifier);
	}
}

// Get Tor proxy address
const string &Node::getTorProxyAddress() const {

	// Return Tor proxy address
	return torProxyAddress;
}

// Get Tor proxy port
const string &Node::getTorProxyPort() const {

	// Return Tor proxy port
	return torProxyPort;
}

// Get DNS seeds
const unordered_set<string> &Node::getDnsSeeds() const {

	// Check if uisng custom DNS seeds
	if(!customDnsSeeds.empty()) {
	
		// Return custom DNS seeds
		return customDnsSeeds;
	}
	
	// Otherwise
	else {
	
		// Return default DNS seeds
		return DEFAULT_DNS_SEEDS;
	}
}

// Add to mempool
void Node::addToMempool(Transaction &&transaction) {

	// Check if mempool is enabled
	#ifdef ENABLE_MEMPOOL
	
		// Lock for writing
		lock_guard writeLock(lock);
		
		// Check if synced
		if(isSynced) {
		
			// Check if transaction can be added to a block with a coinbase output and kernel
			if(transaction.getOutputs().size() <= Message::MAXIMUM_OUTPUTS_LENGTH - 1 && transaction.getKernels().size() <= Message::MAXIMUM_KERNELS_LENGTH - 1) {
		
				// Go through all of the transaction's inputs
				for(Input &input : transaction.getInputs()) {
				
					// Check if input's features are the same as the output's
					if(input.getFeatures() == Input::Features::SAME_AS_OUTPUT) {
					
						// Check if output doesn't exist
						const vector inputLookupValue = input.getLookupValue();
						const Output *output = outputs.getLeafByLookupValue(inputLookupValue);
						if(!output) {
						
							// Check if output doesn't exist in the mempool
							output = mempool.getOutput(inputLookupValue);
							if(!output) {
							
								// Return
								return;
							}
						}
						
						// Set input's features to the output's features
						input.setFeatures(static_cast<Input::Features>(output->getFeatures()));
					}
				}
				
				// Check if transaction isn't already in the mempool
				if(!mempool.contains(transaction)) {
				
					// Check if transaction's fees are less than the required fees
					if(transaction.getFees() < transaction.getRequiredFees(DEFAULT_BASE_FEE)) {
					
						// Return
						return;
					}
					
					// Initialize replaced fees to zero
					uint64_t replacedFees = 0;
					
					// Initialize replaced transactions
					unordered_set<const Transaction *> replacedTransactions;
					
					// Initialize removed outputs
					unordered_set<vector<uint8_t>, Common::Uint8VectorHash> removedOutputs;
			
					// Go through all of the transaction's outputs
					for(const Output &output : transaction.getOutputs()) {
					
						// Check if output already exists
						const vector outputLookupValue = output.getLookupValue().value();
						if(outputs.leafWithLookupValueExists(outputLookupValue)) {
						
							// Return
							return;
						}
						
						// Check if output already exists in the mempool
						const Transaction *existingTransaction = mempool.getTransaction(outputLookupValue);
						if(existingTransaction) {
						
							// Add existing transaction's fees to replaced fees
							replacedFees = SaturateMath::add(replacedFees, existingTransaction->getFees());
							
							// Add existing transaction to list of transactions to replace
							replacedTransactions.emplace(existingTransaction);
							
							// Go through all of the existing transaction's outputs
							for(const Output &existingOutput : existingTransaction->getOutputs()) {
							
								// Add existing output to list of removed outputs
								removedOutputs.emplace(existingOutput.getLookupValue().value());
							}
						}
					}
					
					// Check if transaction replaces other transactions
					if(!replacedTransactions.empty()) {
					
						// Go through all of the transaction's outputs
						for(const Output &output : transaction.getOutputs()) {
						
							// Remove output from list of removed outputs
							removedOutputs.erase(output.getLookupValue().value());
						}
						
						// Go through all transactions in the mempool
						unordered_set<vector<uint8_t>, Common::Uint8VectorHash> inputDependencies;
						for(Mempool::const_iterator i = mempool.cbegin(); i != mempool.cend();) {
						
							// Get existing transaction
							const Transaction &existingTransaction = *i;
							
							// Check if existing transaction isn't already being replaced
							if(!replacedTransactions.contains(&existingTransaction)) {
							
								// Initialize remove transaction to false
								bool removeTransaction = false;
								
								// Go through all of the existing transactions inputs
								for(const Input &input : existingTransaction.getInputs()) {
								
									// Check if output doesn't exist
									vector inputLookupValue = input.getLookupValue();
									if(!outputs.leafWithLookupValueExists(inputLookupValue)) {
									
										// Check if output will be removed
										if(removedOutputs.contains(inputLookupValue)) {
										
											// Set remove transaction to true
											removeTransaction = true;
											
											// Break
											break;
										}
										
										// Add output to input dependencies
										inputDependencies.emplace(move(inputLookupValue));
									}
								}
								
								// Check if removing transaction
								if(removeTransaction) {
								
									// Add existing transaction's fees to replaced fees
									replacedFees = SaturateMath::add(replacedFees, existingTransaction.getFees());
									
									// Add existing transaction to list of transactions to replace
									replacedTransactions.emplace(&existingTransaction);
									
									// Initialize recheck transactions to false
									bool recheckTransactions = false;
									
									// Go through all of the existing transaction's outputs
									for(const Output &existingOutput : existingTransaction.getOutputs()) {
									
										// Check if existing output is the input to another transaction
										vector outputLookupValue = existingOutput.getLookupValue().value();
										if(inputDependencies.contains(outputLookupValue)) {
										
											// Set recheck transactions to true
											recheckTransactions = true;
										}
										
										// Add existing output to list of removed outputs
										removedOutputs.emplace(move(outputLookupValue));
									}
									
									// Check if rechecking transactions
									if(recheckTransactions) {
									
										// Go to first transaction
										i = mempool.cbegin();
										
										// Clear input dependencies
										inputDependencies.clear();
									}
									
									// Otherwise
									else {
									
										// Go to next transaction
										++i;
									}
								}
								
								// Otherwise
								else {
								
									// Go to next transaction
									++i;
								}
							}
							
							// Otherwise
							else {
							
								// Go to next transaction
								++i;
							}
						}
						
						// Check if transaction's fees aren't greater than the fees of the transactions it replaces
						if(transaction.getFees() <= replacedFees) {
						
							// Return
							return;
						}
					}
					
					// Get next header height
					const uint64_t nextHeaderHeight = SaturateMath::add(syncedHeaderIndex, 1);
					
					// Get unspendable coinbase outputs starting index at the next header's height
					const uint64_t unspendableCoinbaseOutputsStartingIndex = MerkleMountainRange<Header>::getNumberOfLeavesAtSize(headers.getLeaf(SaturateMath::subtract(nextHeaderHeight, Consensus::COINBASE_MATURITY))->getOutputMerkleMountainRangeSize());
					
					// Go through all of the transaction's inputs
					for(const Input &input : transaction.getInputs()) {
					
						// Check if output doesn't exist
						const vector inputLookupValue = input.getLookupValue();
						const Output *output = outputs.getLeafByLookupValue(inputLookupValue);
						if(!output) {
						
							// Check if output doesn't exist in the mempool, it has coinbase features, or it will be replaced
							output = mempool.getOutput(inputLookupValue);
							if(!output || output->getFeatures() == Output::Features::COINBASE || replacedTransactions.contains(mempool.getTransaction(inputLookupValue))) {
							
								// Return
								return;
							}
						}
						
						// Otherwise check if output has coinbase features
						else if(output->getFeatures() == Output::Features::COINBASE) {
						
							// Check if output won't reach maturity by the next header's height
							if(nextHeaderHeight < Consensus::COINBASE_MATURITY || outputs.getLeafIndexByLookupValue(inputLookupValue) >= unspendableCoinbaseOutputsStartingIndex) {
							
								// Return
								return;
							}
						}
						
						// Check if input's features don't match the output's features
						if(static_cast<underlying_type_t<Input::Features>>(input.getFeatures()) != static_cast<underlying_type_t<Output::Features>>(output->getFeatures())) {
						
							// Return
							return;
						}
					}
					
					// Go through all of the transaction's kernels
					for(const Kernel &kernel : transaction.getKernels()) {
					
						// Check kernel's features
						switch(kernel.getFeatures()) {
						
							// Height locked
							case Kernel::Features::HEIGHT_LOCKED:
							
								// Check if kernel's lock height is greater than the next header's height
								if(kernel.getLockHeight() > nextHeaderHeight) {
								
									// Return
									return;
								}
								
								// Break
								break;
							
							// No recent duplicate
							case Kernel::Features::NO_RECENT_DUPLICATE:
							
								// Check if header version at next header's height is less than four
								if(Consensus::getHeaderVersion(nextHeaderHeight) < 4) {
								
									// Return
									return;
								}
								
								// TODO Support NRD kernels
								return;
								
								// Break
								break;
							
							// Default
							default:
							
								// Break
								break;
						}
					}
					
					// Try
					try {
					
						// Go through all replaced transactions
						for(const Transaction *replacedTransaction : replacedTransactions) {
						
							// Remove transaction from mempool
							mempool.erase(*replacedTransaction);
						}
						
						// Insert transaction into mempool
						mempool.insert(move(transaction));
					}
					
					// Catch errors
					catch(...) {
					
						// Clear mempool
						mempool.clear();
					}
				}
			}
		}
	#endif
}

// Get next block
tuple<Header, Block> Node::getNextBlock(const function<tuple<Output, Rangeproof, Kernel>(const uint64_t amount)> &createCoinbase) {

	// Check if mempool is enabled
	#ifdef ENABLE_MEMPOOL
	
		// Check if not synced
		if(!isSynced) {
		
			// Throw exception
			throw runtime_error("Node isn't sycned");
		}
		
		// Get next header height
		const uint64_t nextHeaderHeight = SaturateMath::add(syncedHeaderIndex, 1);
		
		// Check if next header height is before the C31 hard fork height
		// TODO support C29
		if(nextHeaderHeight < Consensus::C31_HARD_FORK_HEIGHT) {
		
			// Throw exception
			throw runtime_error("Next block isn't supported at height");
		}
		
		// Initialize block inputs, outputs, and kernels
		unordered_map<vector<uint8_t>, const Input *, Common::Uint8VectorHash> blockInputs;
		unordered_map<vector<uint8_t>, pair<const Output *, const Rangeproof *>, Common::Uint8VectorHash> blockOutputs;
		unordered_map<vector<uint8_t>, const Kernel *, Common::Uint8VectorHash> blockKernels;
		
		// Initialize fees to zero
		uint64_t fees = 0;
		
		// Initialize offsets
		vector<const uint8_t *> offsets;
		
		// Go through all fees in the mempool in descending order
		unordered_set<const Transaction *> includedTransactions;
		unordered_set<vector<uint8_t>, Common::Uint8VectorHash> pendingOutputs;
		for(map<uint64_t, unordered_set<const Transaction *>>::const_reverse_iterator i = mempool.getFees().crbegin(); i != mempool.getFees().crend();) {
		
			// Initialize recheck transactions to false
			bool recheckTransactions = false;
			
			// Go through all transactions with the fees
			for(const Transaction *transaction : i->second) {
			
				// Check if transaction isn't already included in the block
				if(!includedTransactions.contains(transaction)) {
			
					// Check if block with the transaction won't have too many inputs, outputs, or kernels
					if(blockInputs.size() + transaction->getInputs().size() <= Message::MAXIMUM_INPUTS_LENGTH && blockOutputs.size() + transaction->getOutputs().size() <= Message::MAXIMUM_OUTPUTS_LENGTH - 1 && blockKernels.size() + transaction->getKernels().size() <= Message::MAXIMUM_KERNELS_LENGTH - 1) {
				
						// Check if block's weight with the transaction is valid
						if(Consensus::getBlockWeight(blockInputs.size() + transaction->getInputs().size(), blockOutputs.size() + transaction->getOutputs().size() + 1, blockKernels.size() + transaction->getKernels().size() + 1) <= Consensus::MAXIMUM_BLOCK_WEIGHT) {
				
							// Initialize include transaction to true
							bool includeTransaction = true;
							
							// Go through all of the transaction's kernels
							for(const Kernel &kernel : transaction->getKernels()) {
							
								// Check if kernel already exists in the block
								if(blockKernels.contains(kernel.serialize())) {
								
									// Set include transaction to false
									includeTransaction = false;
									
									// Break
									break;
								}
							}
							
							// Check if including transaction
							if(includeTransaction) {
						
								// Go through all of the transaction's inputs
								for(const Input &input : transaction->getInputs()) {
									
									// Check if input already exists in the block
									vector inputLookupValue = input.getLookupValue();
									if(blockInputs.contains(inputLookupValue)) {
									
										// Set include transaction to false
										includeTransaction = false;
										
										// Break
										break;
									}
									
									// Otherwise check if output doesn't exist
									else if(!outputs.leafWithLookupValueExists(inputLookupValue) && !blockOutputs.contains(inputLookupValue)) {
									
										// Set include transaction to false
										includeTransaction = false;
										
										// Add output to pending outputs
										pendingOutputs.emplace(move(inputLookupValue));
										
										// Break
										break;
									}
								}
							}
							
							// Check if including transaction
							if(includeTransaction) {
							
								// Add transaction to list of included transactions
								includedTransactions.emplace(transaction);
								
								// Check if transaction's offset isn't zero
								if(any_of(transaction->getOffset(), transaction->getOffset() + Crypto::SECP256K1_PRIVATE_KEY_LENGTH, [](const uint8_t value) {
	
									// Return if value isn't zero
									return value;
								
								})) {
								
									// Add transaction's offset to list of offsets
									offsets.push_back(transaction->getOffset());
								}
							
								// Go through all of the transaction's inputs
								for(const Input &input : transaction->getInputs()) {
								
									// Check if input is the output from another transaction in the block
									vector inputLookupValue = input.getLookupValue();
									if(blockOutputs.contains(inputLookupValue)) {
									
										// Remove output from block outputs
										blockOutputs.erase(inputLookupValue);
									}
									
									// Otherwise
									else {
								
										// Add input to block inputs
										blockInputs.emplace(move(inputLookupValue), &input);
									}
								}
								
								// Go through all of the transaction's outputs
								list<Output>::const_iterator j = transaction->getOutputs().cbegin();
								for(list<Rangeproof>::const_iterator k = transaction->getRangeproofs().cbegin(); j != transaction->getOutputs().cend(); ++j, ++k) {
								
									// Check if output is the input to another transaction
									vector outputLookupValue = j->getLookupValue().value();
									if(pendingOutputs.contains(outputLookupValue)) {
									
										// Set recheck transactions to true
										recheckTransactions = true;
									}
									
									// Add output and rangeproof to block outputs
									blockOutputs.emplace(move(outputLookupValue), make_pair(&*j, &*k));
								}
								
								// Go through all of the transaction's kernels
								for(const Kernel &kernel : transaction->getKernels()) {
								
									// Add kernel to block kernels
									blockKernels.emplace(kernel.serialize(), &kernel);
									
									// Add kernel's fees to fees
									fees = SaturateMath::add(fees, kernel.getFee());
								}
								
								// Check if rechecking transactions
								if(recheckTransactions) {
								
									// Break
									break;
								}
							}
						}
					}
				}
			}
			
			// Check if rechecking transactions
			if(recheckTransactions) {
			
				// Go to first fees
				i = mempool.getFees().crbegin();
				
				// Clear pending outputs
				pendingOutputs.clear();
			}
			
			// Otherwise
			else {
			
				// Go to next fees
				++i;
			}
		}
		
		// Get coinbase reward at next header's height
		const uint64_t coinbaseReward = Consensus::getCoinbaseReward(nextHeaderHeight);
		
		// Create coinbase for block's reward and fees
		tuple coinbase = createCoinbase(SaturateMath::add(coinbaseReward, fees));
		
		// Check if coinbase output or kernel already exist
		const vector coinbaseOutputLookupValue = get<0>(coinbase).getLookupValue().value();
		if(outputs.leafWithLookupValueExists(coinbaseOutputLookupValue) || blockInputs.contains(coinbaseOutputLookupValue) || blockOutputs.contains(coinbaseOutputLookupValue) || blockKernels.contains(get<2>(coinbase).serialize())) {
		
			// Throw exception
			throw runtime_error("Coinbase output or kernel already exist");
		}
		
		// Go through all of the block's inputs
		list<Input> sortedInputs;
		for(const pair<const vector<uint8_t>, const Input *> &input : blockInputs) {
		
			// Add input to sorted inputs
			sortedInputs.push_back(*input.second);
		}
		
		// Sort sorted inputs
		sortedInputs.sort([](const Input &firstInput, const Input &secondInput) {
		
			// Get serialized first input
			const vector serializedFirstInput = firstInput.serialize();
			
			// Check if creating first input's hash failed
			uint8_t firstInputHash[Crypto::BLAKE2B_HASH_LENGTH];
			if(blake2b(firstInputHash, sizeof(firstInputHash), serializedFirstInput.data(), serializedFirstInput.size(), nullptr, 0)) {
			
				// Throw exception
				throw runtime_error("Creating first input's hash failed");
			}
			
			// Get serialized second input
			const vector serializedSecondInput = secondInput.serialize();
			
			// Check if creating second input's hash failed
			uint8_t secondInputHash[Crypto::BLAKE2B_HASH_LENGTH];
			if(blake2b(secondInputHash, sizeof(secondInputHash), serializedSecondInput.data(), serializedSecondInput.size(), nullptr, 0)) {
			
				// Throw exception
				throw runtime_error("Creating second input's hash failed");
			}
			
			// Return comparing the first and second input hashes
			return memcmp(firstInputHash, secondInputHash, sizeof(secondInputHash));
		});
		
		// Go through all of the block's outputs
		list<pair<Output, Rangeproof>> sortedOutputsAndRangeproofs;
		for(const pair<const vector<uint8_t>, pair<const Output *, const Rangeproof *>> &output : blockOutputs) {
		
			// Add output to sorted outputs and rangeproofs
			sortedOutputsAndRangeproofs.emplace_back(*output.second.first, *output.second.second);
		}
		
		// Add coinbase output and rangeproof to sorted outputs and rangeproofs
		sortedOutputsAndRangeproofs.emplace_back(move(get<0>(coinbase)), move(get<1>(coinbase)));
		
		// Sort sorted outputs and rangeproofs
		sortedOutputsAndRangeproofs.sort([](const pair<Output, Rangeproof> &firstOutputAndRangeproof, const pair<Output, Rangeproof> &secondOutputAndRangeproof) {
		
			// Get serialized first output and rangeproof's output
			const vector serializedFirstOutput = firstOutputAndRangeproof.first.serialize();
			
			// Check if creating first output's hash failed
			uint8_t firstOutputHash[Crypto::BLAKE2B_HASH_LENGTH];
			if(blake2b(firstOutputHash, sizeof(firstOutputHash), serializedFirstOutput.data(), serializedFirstOutput.size(), nullptr, 0)) {
			
				// Throw exception
				throw runtime_error("Creating first output's hash failed");
			}
			
			// Get serialized second output and rangeproof's output
			const vector serializedSecondOutput = secondOutputAndRangeproof.first.serialize();
			
			// Check if creating second output's hash failed
			uint8_t secondOutputHash[Crypto::BLAKE2B_HASH_LENGTH];
			if(blake2b(secondOutputHash, sizeof(secondOutputHash), serializedSecondOutput.data(), serializedSecondOutput.size(), nullptr, 0)) {
			
				// Throw exception
				throw runtime_error("Creating second output's hash failed");
			}
			
			// Return comparing the first and second output hashes
			return memcmp(firstOutputHash, secondOutputHash, sizeof(secondOutputHash));
		});
		
		// Go through all sorted outputs and rangeproofs
		list<Output> sortedOutputs;
		list<Rangeproof> sortedRangeproofs;
		for(pair<Output, Rangeproof> &outputAndRangeproof : sortedOutputsAndRangeproofs) {
		
			// Add output to sorted outputs
			sortedOutputs.emplace_back(move(outputAndRangeproof.first));
			
			// Add rangeproof to sorted rangeproofs
			sortedRangeproofs.emplace_back(move(outputAndRangeproof.second));
		}
		
		// Go through all of the block's kernels
		list<Kernel> sortedKernels;
		for(const pair<const vector<uint8_t>, const Kernel *> &kernel : blockKernels) {
		
			// Add kernel to sorted kernels
			sortedKernels.push_back(*kernel.second);
		}
		
		// Add coinbase kernel to sorted kernels
		sortedKernels.emplace_back(move(get<2>(coinbase)));
		
		// Sort sorted kernels
		sortedKernels.sort([](const Kernel &firstKernel, const Kernel &secondKernel) {
		
			// Get serialized first kernel
			const vector serializedFirstKernel = firstKernel.serialize();
			
			// Check if creating first kernel's hash failed
			uint8_t firstKernelHash[Crypto::BLAKE2B_HASH_LENGTH];
			if(blake2b(firstKernelHash, sizeof(firstKernelHash), serializedFirstKernel.data(), serializedFirstKernel.size(), nullptr, 0)) {
			
				// Throw exception
				throw runtime_error("Creating first kernel's hash failed");
			}
			
			// Get serialized second kernel
			const vector serializedSecondKernel = secondKernel.serialize();
			
			// Check if creating second kernel's hash failed
			uint8_t secondKernelHash[Crypto::BLAKE2B_HASH_LENGTH];
			if(blake2b(secondKernelHash, sizeof(secondKernelHash), serializedSecondKernel.data(), serializedSecondKernel.size(), nullptr, 0)) {
			
				// Throw exception
				throw runtime_error("Creating second kernel's hash failed");
			}
			
			// Return comparing the first and second kernel hashes
			return memcmp(firstKernelHash, secondKernelHash, sizeof(secondKernelHash));
		});
		
		// Create block from sorted inputs, outputs, rangeproofs, and kernels
		const Block block(move(sortedInputs), move(sortedOutputs), move(sortedRangeproofs), move(sortedKernels), false, false);
		
		// Get previous header
		const Header *previousHeader = headers.getLeaf(syncedHeaderIndex);
		
		// Check if previous header's total kernel offset isn't zero
		if(any_of(previousHeader->getTotalKernelOffset(), previousHeader->getTotalKernelOffset() + Crypto::SECP256K1_PRIVATE_KEY_LENGTH, [](const uint8_t value) {

			// Return if value isn't zero
			return value;
		
		})) {
		
			// Add previous header's total kernel offset to list of offsets
			offsets.push_back(previousHeader->getTotalKernelOffset());
		}
		
		// Initialize total kernel offset
		uint8_t totalKernelOffset[Crypto::SECP256K1_PRIVATE_KEY_LENGTH] = {};
		
		// Check if non-zero offsets exist
		if(!offsets.empty()) {
		
			// Check if getting total kernel offset failed
			if(!secp256k1_pedersen_blind_sum(secp256k1_context_no_precomp, totalKernelOffset, offsets.data(), offsets.size(), offsets.size())) {
			
				// Throw exception
				throw runtime_error("Getting total kernel offset failed");
			}
		
			// Check if total kernel offset is invalid
			if(any_of(cbegin(totalKernelOffset), cend(totalKernelOffset), [](const uint8_t value) {
			
				// Return if value isn't zero
				return value;
			
			}) && !secp256k1_ec_seckey_verify(secp256k1_context_no_precomp, totalKernelOffset)) {
			
				// Throw exception
				throw runtime_error("Total kernel offset is invalid");
			}
		}
		
		// Try
		try {
		
			// Go through all of the block's kernels
			for(const Kernel &kernel : block.getKernels()) {
			
				// Append kernel to kernels
				kernels.appendLeaf(kernel);
			}
			
			// Go through all of the block's outputs
			for(const Output &output : block.getOutputs()) {
			
				// Append output to outputs
				outputs.appendLeaf(output);
			}
			
			// Go through all of the block's rangeproofs
			for(const Rangeproof &rangeproof : block.getRangeproofs()) {
			
				// Append rangeproof to rangeproofs
				rangeproofs.appendLeaf(rangeproof);
			}
		}
		
		// Catch errors
		catch(...) {
		
			// Set headers to include the genesis block header
			headers.clear();
			headers.appendLeaf(Consensus::GENESIS_BLOCK_HEADER);
			
			// Set synced header index to the newest known height
			syncedHeaderIndex = headers.back().getHeight();
			
			// Set kernels to include the genesis block kernel
			kernels.clear();
			kernels.appendLeaf(Consensus::GENESIS_BLOCK_KERNEL);
			
			// Set outputs to include the genesis block output
			outputs.clear();
			outputs.appendLeaf(Consensus::GENESIS_BLOCK_OUTPUT);
			
			// Set rangeproofs to include the genesis block rangeproof
			rangeproofs.clear();
			rangeproofs.appendLeaf(Consensus::GENESIS_BLOCK_RANGEPROOF);
			
			// Clear mempool
			mempool.clear();
			
			// Set is synced to false
			isSynced = false;
			
			// Throw exception
			throw runtime_error("Adding block to Merkle mountain ranges failed");
		}
		
		// Try
		try {
			
			// Create header
			const uint64_t proofNonces[Crypto::CUCKOO_CYCLE_NUMBER_OF_PROOF_NONCES] = {};
			const Header header(Consensus::getHeaderVersion(nextHeaderHeight), nextHeaderHeight, max(chrono::system_clock::now(), previousHeader->getTimestamp() + 1s), previousHeader->getBlockHash().data(), headers.getRootAtNumberOfLeaves(previousHeader->getHeight() + 1).data(), outputs.getRootAtSize(outputs.getSize()).data(), rangeproofs.getRootAtSize(rangeproofs.getSize()).data(), kernels.getRootAtSize(kernels.getSize()).data(), totalKernelOffset, outputs.getSize(), kernels.getSize(), previousHeader->getTotalDifficulty(), Consensus::MINIMUM_SECONDARY_SCALING, 0, Consensus::C31_EDGE_BITS, proofNonces, false);
			
			// Try
			try {
			
				// Undo changed to kernels, outputs, and rangeproofs
				kernels.rewindToSize(previousHeader->getKernelMerkleMountainRangeSize());
				outputs.rewindToSize(previousHeader->getOutputMerkleMountainRangeSize());
				rangeproofs.rewindToSize(previousHeader->getOutputMerkleMountainRangeSize());
			}
			
			// Catch errors
			catch(...) {
			
				// Set headers to include the genesis block header
				headers.clear();
				headers.appendLeaf(Consensus::GENESIS_BLOCK_HEADER);
				
				// Set synced header index to the newest known height
				syncedHeaderIndex = headers.back().getHeight();
				
				// Set kernels to include the genesis block kernel
				kernels.clear();
				kernels.appendLeaf(Consensus::GENESIS_BLOCK_KERNEL);
				
				// Set outputs to include the genesis block output
				outputs.clear();
				outputs.appendLeaf(Consensus::GENESIS_BLOCK_OUTPUT);
				
				// Set rangeproofs to include the genesis block rangeproof
				rangeproofs.clear();
				rangeproofs.appendLeaf(Consensus::GENESIS_BLOCK_RANGEPROOF);
				
				// Clear mempool
				mempool.clear();
				
				// Set is synced to false
				isSynced = false;
				
				// Throw exception
				throw runtime_error("Removing block to Merkle mountain ranges failed");
			}
			
			// Return header and block
			return {header, block};
		}
		
		// Catch errors
		catch(...) {
		
			// Try
			try {
			
				// Undo changed to kernels, outputs, and rangeproofs
				kernels.rewindToSize(previousHeader->getKernelMerkleMountainRangeSize());
				outputs.rewindToSize(previousHeader->getOutputMerkleMountainRangeSize());
				rangeproofs.rewindToSize(previousHeader->getOutputMerkleMountainRangeSize());
			}
			
			// Catch errors
			catch(...) {
			
				// Set headers to include the genesis block header
				headers.clear();
				headers.appendLeaf(Consensus::GENESIS_BLOCK_HEADER);
				
				// Set synced header index to the newest known height
				syncedHeaderIndex = headers.back().getHeight();
				
				// Set kernels to include the genesis block kernel
				kernels.clear();
				kernels.appendLeaf(Consensus::GENESIS_BLOCK_KERNEL);
				
				// Set outputs to include the genesis block output
				outputs.clear();
				outputs.appendLeaf(Consensus::GENESIS_BLOCK_OUTPUT);
				
				// Set rangeproofs to include the genesis block rangeproof
				rangeproofs.clear();
				rangeproofs.appendLeaf(Consensus::GENESIS_BLOCK_RANGEPROOF);
				
				// Clear mempool
				mempool.clear();
				
				// Set is synced to false
				isSynced = false;
			}
			
			// Rethrow error
			throw;
		}
	
	// Otherwise
	#else
	
		// Throw exception
		throw runtime_error("Mempool isn't enabled");
	#endif
}

// Cleanup mempool
void Node::cleanupMempool() {

	// Check if mempool is enabled
	#ifdef ENABLE_MEMPOOL
	
		// Check if synced
		if(isSynced) {
		
			// Try
			try {
			
				// Get next header height
				const uint64_t nextHeaderHeight = SaturateMath::add(syncedHeaderIndex, 1);
				
				// Get unspendable coinbase outputs starting index at the next header's height
				const uint64_t unspendableCoinbaseOutputsStartingIndex = MerkleMountainRange<Header>::getNumberOfLeavesAtSize(headers.getLeaf(SaturateMath::subtract(nextHeaderHeight, Consensus::COINBASE_MATURITY))->getOutputMerkleMountainRangeSize());
				
				// Go through all transactions in the mempool
				for(Mempool::const_iterator i = mempool.cbegin(); i != mempool.cend();) {
				
					// Get transaction
					const Transaction &transaction = *i;
					
					// Initialize remove transaction to false
					bool removeTransaction = false;
					
					// Go through all of the transaction's outputs
					for(const Output &output : transaction.getOutputs()) {
					
						// Check if output already exists
						if(outputs.leafWithLookupValueExists(output.getLookupValue().value())) {
						
							// Set remove transaction to true
							removeTransaction = true;
							
							// Break
							break;
						}
					}
					
					// Check if not removing transaction
					if(!removeTransaction) {
					
						// Go through all of the transaction's inputs
						for(const Input &input : transaction.getInputs()) {
						
							// Check if output doesn't exist
							const vector inputLookupValue = input.getLookupValue();
							const Output *output = outputs.getLeafByLookupValue(inputLookupValue);
							if(!output) {
							
								// Check if output doesn't exist in the mempool or it has coinbase features
								output = mempool.getOutput(inputLookupValue);
								if(!output || output->getFeatures() == Output::Features::COINBASE) {
								
									// Set remove transaction to true
									removeTransaction = true;
									
									// Break
									break;
								}
							}
							
							// Check if output has coinbase features
							else if(output->getFeatures() == Output::Features::COINBASE) {
							
								// Check if output won't reach maturity by the next header's height
								if(nextHeaderHeight < Consensus::COINBASE_MATURITY || outputs.getLeafIndexByLookupValue(inputLookupValue) >= unspendableCoinbaseOutputsStartingIndex) {
								
									// Set remove transaction to true
									removeTransaction = true;
									
									// Break
									break;
								}
							}
							
							// Check if input's features don't match the output's features
							if(static_cast<underlying_type_t<Input::Features>>(input.getFeatures()) != static_cast<underlying_type_t<Output::Features>>(output->getFeatures())) {
							
								// Set remove transaction to true
								removeTransaction = true;
								
								// Break
								break;
							}
						}
					}
					
					// Check if not removing transaction
					if(!removeTransaction) {
				
						// Go through all of the transaction's kernels
						for(const Kernel &kernel : transaction.getKernels()) {
						
							// Check kernel's features
							switch(kernel.getFeatures()) {
							
								// Height locked
								case Kernel::Features::HEIGHT_LOCKED:
								
									// Check if kernel's lock height is greater than the next header's height
									if(kernel.getLockHeight() > nextHeaderHeight) {
									
										// Set remove transaction to true
										removeTransaction = true;
									}
									
									// Break
									break;
								
								// No recent duplicate
								case Kernel::Features::NO_RECENT_DUPLICATE:
								
									// Check if header version at next header's height is less than four
									if(Consensus::getHeaderVersion(nextHeaderHeight) < 4) {
									
										// Set remove transaction to true
										removeTransaction = true;
									}
									
									// TODO Support NRD kernels
									removeTransaction = true;
									
									// Break
									break;
								
								// Default
								default:
								
									// Break
									break;
							}
							
							// Check if removing transaction
							if(removeTransaction) {
							
								// Break
								break;
							}
						}
					}
					
					// Check if removing transaction
					if(removeTransaction) {
					
						// Remove transaction from mempool and go to next transaction
						i = mempool.erase(i);
					}
					
					// Otherwise
					else {
					
						// Go to next transaction
						++i;
					}
				}
				
				// Go through all transactions in the mempool
				unordered_set<vector<uint8_t>, Common::Uint8VectorHash> inputDependencies;
				for(Mempool::const_iterator i = mempool.cbegin(); i != mempool.cend();) {
				
					// Get transaction
					const Transaction &transaction = *i;
					
					// Initialize remove transaction to false
					bool removeTransaction = false;
					
					// Go through all of the transaction's inputs
					for(const Input &input : transaction.getInputs()) {
					
						// Check if output doesn't exist
						vector inputLookupValue = input.getLookupValue();
						if(!outputs.leafWithLookupValueExists(inputLookupValue)) {
						
							// Check if output doesn't exist in the mempool
							if(!mempool.getOutput(inputLookupValue)) {
						
								// Set remove transaction to true
								removeTransaction = true;
								
								// Break
								break;
							}
							
							// Otherwise
							else {
							
								// Add output to input dependencies
								inputDependencies.emplace(move(inputLookupValue));
							}
						}
					}
					
					// Check if removing transaction
					if(removeTransaction) {
					
						// Initialize recheck transactions to false
						bool recheckTransactions = false;
						
						// Go through all of the transaction's outputs
						for(const Output &output : transaction.getOutputs()) {
						
							// Check if output is the input to another transaction
							if(inputDependencies.contains(output.getLookupValue().value())) {
							
								// Set recheck transactions to true
								recheckTransactions = true;
								
								// Break
								break;
							}
						}
						
						// Check if rechecking transactions
						if(recheckTransactions) {
						
							// Remove transaction from mempool
							mempool.erase(i);
							
							// Go to the first transaction
							i = mempool.cbegin();
							
							// Clear input dependencies
							inputDependencies.clear();
						}
						
						// Otherwise
						else {
						
							// Remove transaction from mempool and go to next transaction
							i = mempool.erase(i);
						}
					}
					
					// Otherwise
					else {
					
						// Go to next transaction
						++i;
					}
				}
			}
			
			// Catch errors
			catch(...) {
			
				// Clear mempool
				mempool.clear();
			}
		}
	#endif
}

// Apply block to sync state
bool Node::applyBlockToSyncState(const uint64_t syncedHeaderIndex, const Block &block) {
	
	// Set synced header index to synced header index
	this->syncedHeaderIndex = syncedHeaderIndex;
	
	// Set result to true
	bool result = true;
	
	// Set callback failed to false
	bool callbackFailed = false;

	// Try
	try {
		
		// Rewind kernels, outputs, and rangeproofs to the previous synced header
		kernels.rewindToSize(headers.getLeaf(syncedHeaderIndex - 1)->getKernelMerkleMountainRangeSize());
		outputs.rewindToSize(headers.getLeaf(syncedHeaderIndex - 1)->getOutputMerkleMountainRangeSize());
		rangeproofs.rewindToSize(headers.getLeaf(syncedHeaderIndex - 1)->getOutputMerkleMountainRangeSize());
		
		// Go through all of the block's outputs
		for(const Output &output : block.getOutputs()) {
		
			// Check if output already exists
			if(outputs.getLeafByLookupValue(output.getLookupValue().value())) {
			
				// Set result to false
				result = false;
			
				// Throw exception
				throw runtime_error("Output already exists");
			}
		
			// Append output to outputs
			outputs.appendLeaf(output);
		}
		
		// Go through all of the block's rangeproofs
		for(const Rangeproof &rangeproof : block.getRangeproofs()) {
		
			// Append rangeproof to rangeproofs
			rangeproofs.appendLeaf(rangeproof);
			
			// Check if pruning rangeproofs
			#ifdef PRUNE_RANGEPROOFS
			
				// Prune rangeproof
				rangeproofs.pruneLeaf(rangeproofs.getNumberOfLeaves() - 1);
			#endif
		}
		
		// Get header at the synced header index
		const Header *header = headers.getLeaf(syncedHeaderIndex);
		
		// Get unspendable coinbase outputs starting index
		const uint64_t unspendableCoinbaseOutputsStartingIndex = MerkleMountainRange<Header>::getNumberOfLeavesAtSize(headers.getLeaf(SaturateMath::subtract(header->getHeight(), Consensus::COINBASE_MATURITY))->getOutputMerkleMountainRangeSize());
		
		// Go through all of the block's inputs
		for(const Input &input : block.getInputs()) {
		
			// Check if input isn't spending an output
			const Output *output = outputs.getLeafByLookupValue(input.getLookupValue());
			if(!output) {
			
				// Set result to false
				result = false;
			
				// Throw exception
				throw runtime_error("Input isn't spending an output");
			}
			
			// Check if input's features don't match the output's features
			if(input.getFeatures() != Input::Features::SAME_AS_OUTPUT && static_cast<underlying_type_t<Input::Features>>(input.getFeatures()) != static_cast<underlying_type_t<Output::Features>>(output->getFeatures())) {
			
				// Set result to false
				result = false;
			
				// Throw exception
				throw runtime_error("Input's features don't match the output's features");
			}
			
			// Get the index of the output being spent
			const uint64_t outputIndex = outputs.getLeafIndexByLookupValue(input.getLookupValue());
			
			// Check if input has coinbase features
			if(input.getFeatures() == Input::Features::COINBASE || (input.getFeatures() == Input::Features::SAME_AS_OUTPUT && output->getFeatures() == Output::Features::COINBASE)) {
			
				// Check if output hasn't reached maturity
				if(header->getHeight() < Consensus::COINBASE_MATURITY || outputIndex >= unspendableCoinbaseOutputsStartingIndex) {
				
					// Set result to false
					result = false;
				
					// Throw exception
					throw runtime_error("Output hasn't reached maturity");
				}
			}
		
			// Prune output
			outputs.pruneLeaf(outputIndex);
			
			// Check if not pruning rangeproofs
			#ifndef PRUNE_RANGEPROOFS
			
				// Prune rangeproof
				rangeproofs.pruneLeaf(outputIndex);
			#endif
		}
		
		// Check if outputs size doesn't match the header's output Merkle mountain range size
		if(outputs.getSize() != header->getOutputMerkleMountainRangeSize()) {
		
			// Set result to false
			result = false;
		
			// Throw exception
			throw runtime_error("Outputs size doesn't match the header's output Merkle mountain range size");
		}
		
		// Check if outputs root doesn't match the header's output root
		if(memcmp(outputs.getRootAtSize(outputs.getSize()).data(), header->getOutputRoot(), Crypto::BLAKE2B_HASH_LENGTH)) {
		
			// Set result to false
			result = false;
		
			// Throw exception
			throw runtime_error("Outputs root doesn't match the header's output root");
		}
		
		// Check if rangeproofs size doesn't match the header's output Merkle mountain range size
		if(rangeproofs.getSize() != header->getOutputMerkleMountainRangeSize()) {
		
			// Set result to false
			result = false;
		
			// Throw exception
			throw runtime_error("Rangeproofs size doesn't match the header's output Merkle mountain range size");
		}
		
		// Check if rangeproofs root doesn't match the header's rangeproof root
		if(memcmp(rangeproofs.getRootAtSize(rangeproofs.getSize()).data(), header->getRangeproofRoot(), Crypto::BLAKE2B_HASH_LENGTH)) {
		
			// Set result to false
			result = false;
		
			// Throw exception
			throw runtime_error("Rangeproofs root doesn't match the header's rangeproof root");
		}
		
		// Go through all of the block's kernels
		for(const Kernel &kernel : block.getKernels()) {
		
			// TODO NRD check for floonet
		
			// Append kernel to kernels
			kernels.appendLeaf(kernel);
			
			// Check if pruning kernels
			#ifdef PRUNE_KERNELS
			
				// Prune kernel
				kernels.pruneLeaf(kernels.getNumberOfLeaves() - 1);
			#endif
		}
		
		// Check if kernels size doesn't match the header's kernel Merkle mountain range size
		if(kernels.getSize() != header->getKernelMerkleMountainRangeSize()) {
		
			// Set result to false
			result = false;
		
			// Throw exception
			throw runtime_error("Kernels size doesn't match the header's kernel Merkle mountain range size");
		}
		
		// Check if kernels root doesn't match the header's kernel root
		if(memcmp(kernels.getRootAtSize(kernels.getSize()).data(), header->getKernelRoot(), Crypto::BLAKE2B_HASH_LENGTH)) {
		
			// Set result to false
			result = false;
		
			// Throw exception
			throw runtime_error("Kernels root doesn't match the header's kernel root");
		}
		
		// Check if header's version is at least three
		if(header->getVersion() >= 3) {
		
			// TODO replay attack check
		}
		
		// Check if verifying kernel sums failed
		if(!Crypto::verifyKernelSums(*header, kernels, outputs)) {
		
			// Set result to false
			result = false;
		
			// Throw exception
			throw runtime_error("Verifying kernel sums failed");
		}
		
		// Clean up mempool
		cleanupMempool();
		
		// Check if on block callback exists
		if(onBlockCallback) {
		
			// Check if running on block callback failed
			if(!onBlockCallback(*header, block)) {
			
				// Set callback failed to true
				callbackFailed = true;
				
				// Throw exception
				throw runtime_error("Running on block callback failed");
			}
		}
	}
	
	// Catch errors
	catch(...) {
	
		// Check if updating sync state failed or callback failed
		if(!result || callbackFailed) {
		
			// Check if node state wasn't already reset
			if(this->syncedHeaderIndex != Consensus::GENESIS_BLOCK_HEADER.getHeight()) {
	
				// Decrement synced header index
				--this->syncedHeaderIndex;
			
				// Rewind kernels, outputs, and rangeproofs to the synced header
				kernels.rewindToSize(headers.getLeaf(this->syncedHeaderIndex)->getKernelMerkleMountainRangeSize());
				outputs.rewindToSize(headers.getLeaf(this->syncedHeaderIndex)->getOutputMerkleMountainRangeSize());
				rangeproofs.rewindToSize(headers.getLeaf(this->syncedHeaderIndex)->getOutputMerkleMountainRangeSize());
				
				// Clean up mempool
				cleanupMempool();
			}
			
			// Otherwise
			else {
			
				// Set is syncing to false
				isSyncing = false;
				
				// Return true
				return true;
			}
		}
		
		// Otherwise
		else {
		
			// Set headers to include the genesis block header
			headers.clear();
			headers.appendLeaf(Consensus::GENESIS_BLOCK_HEADER);
			
			// Set synced header index to the newest known height
			this->syncedHeaderIndex = headers.back().getHeight();
			
			// Set kernels to include the genesis block kernel
			kernels.clear();
			kernels.appendLeaf(Consensus::GENESIS_BLOCK_KERNEL);
			
			// Set outputs to include the genesis block output
			outputs.clear();
			outputs.appendLeaf(Consensus::GENESIS_BLOCK_OUTPUT);
			
			// Set rangeproofs to include the genesis block rangeproof
			rangeproofs.clear();
			rangeproofs.appendLeaf(Consensus::GENESIS_BLOCK_RANGEPROOF);
			
			// Clear mempool
			mempool.clear();
			
			// Set is syncing to false
			isSyncing = false;
			
			// Set is synced to false
			isSynced = false;
			
			// Return true
			return true;
		}
	}
	
	// Check if pruning headers
	#ifdef PRUNE_HEADERS
	
		// Loop while headers can be pruned
		while(this->syncedHeaderIndex - headers.front().getHeight() > Consensus::DIFFICULTY_ADJUSTMENT_WINDOW && this->syncedHeaderIndex - headers.front().getHeight() >= Consensus::COINBASE_MATURITY && this->syncedHeaderIndex - headers.front().getHeight() > Consensus::CUT_THROUGH_HORIZON) {
		
			// Prune oldest header
			headers.pruneLeaf(headers.front().getHeight(), true);
		}
	#endif
	
	// Check if headers minimum size can be updated
	if(MerkleMountainRange<Header>::getSizeAtNumberOfLeaves(headers.front().getHeight() + 1) > headers.getMinimumSize()) {
	
		// Set headers minimum size to the first header
		headers.setMinimumSize(MerkleMountainRange<Header>::getSizeAtNumberOfLeaves(headers.front().getHeight() + 1));
	}
	
	// Check if kernels minimum size can be updated
	if(headers.front().getKernelMerkleMountainRangeSize() > kernels.getMinimumSize()) {
	
		// Set kernels minimum size to the first header
		kernels.setMinimumSize(headers.front().getKernelMerkleMountainRangeSize());
	}
	
	// Check if outputs minimum size can be updated
	if(headers.front().getOutputMerkleMountainRangeSize() > outputs.getMinimumSize()) {
	
		// Set outputs minimum size to the first header
		outputs.setMinimumSize(headers.front().getOutputMerkleMountainRangeSize());
	}
	
	// Check if rangeproofs minimum size can be updated
	if(headers.front().getOutputMerkleMountainRangeSize() > rangeproofs.getMinimumSize()) {
	
		// Set rangeproofs minimum size to the first header
		rangeproofs.setMinimumSize(headers.front().getOutputMerkleMountainRangeSize());
	}
	
	// Free memory
	Common::freeMemory();
	
	// Check if updating sync state failed
	if(!result) {
	
		// Return false
		return false;
	}
	
	// Set is syncing to false
	isSyncing = false;
	
	// Return true
	return true;
}

// Monitor
void Node::monitor() {

	// Try
	try {
	
		// Set start monitoring time to now
		const chrono::time_point startMonitoringTime = chrono::steady_clock::now();
	
		// Set last remove random peer time to now
		chrono::time_point lastRemoveRandomPeerTime = chrono::steady_clock::now();
	
		// Set last unused peer candidates cleanup time to now
		chrono::time_point lastUnusedPeerCandidatesCleanupTime = chrono::steady_clock::now();
		
		// Set last recently attempted peer candidates cleanup time to now
		chrono::time_point lastRecentlyAttemptedPeerCandidatesCleanupTime = chrono::steady_clock::now();
		
		// Set last healthy peers cleanup time to now
		chrono::time_point lastHealthyPeersCleanupTime = chrono::steady_clock::now();
		
		// Set last banned peers cleanup time to now
		chrono::time_point lastBannedPeersCleanupTime = chrono::steady_clock::now();
		
		// Loop while not stopping monitoring and not closing
		while(!stopMonitoring.load() && !Common::isClosing()) {
		
			// Remove disconnected peers
			removeDisconnectedPeers();
			
			// Set number of connected and healthy peers to zero
			list<Peer>::size_type numberOfConnectedAndHealthyPeers = 0;
			
			// Go through all peers
			for(Peer &peer : peers) {
				
				// Try
				try {
				
					// Lock peer for reading
					shared_lock peerReadLock(peer.getLock());
					
					// Check if peer is connected and healthy
					if(peer.getConnectionState() == Peer::ConnectionState::CONNECTED_AND_HEALTHY) {
					
						// Increment number of connected an healthy peers
						++numberOfConnectedAndHealthyPeers;
					}
				}
				
				// Catch errors
				catch(...) {
				
				}
			}
			
			// Check if desired number of connected and healthy peers isn't reached
			if(numberOfConnectedAndHealthyPeers != DESIRED_NUMBER_OF_PEERS) {
			
				// Set last remove random peer time to now
				lastRemoveRandomPeerTime = chrono::steady_clock::now();
			}
			
			// Otherwise check if its time to remove a random peer
			else if(chrono::steady_clock::now() - lastRemoveRandomPeerTime >= REMOVE_RANDOM_PEER_INTERVAL) {
			
				// Remove random peer
				removeRandomPeer();
			
				// Set last remove random peer time to now
				lastRemoveRandomPeerTime = chrono::steady_clock::now();
			}
			
			// Check if enough healthy peers are connected to sync or a healthy peer is connected and time to start syncing
			if(numberOfConnectedAndHealthyPeers >= MINIMUM_NUMBER_OF_CONNECTED_AND_HEALTHY_PEERS_TO_START_SYNCING || (numberOfConnectedAndHealthyPeers && chrono::steady_clock::now() - startMonitoringTime >= DELAY_BEFORE_SYNCING_DURATION)) {
			
				// Sync
				sync();
			}
			
			// Check if more peers are desired
			if(peers.size() < DESIRED_NUMBER_OF_PEERS) {
		
				// Connect to more peers
				connectToMorePeers();
			}
			
			// Check if time to cleanup unused peer candidates
			if(chrono::steady_clock::now() - lastUnusedPeerCandidatesCleanupTime >= UNUSED_PEER_CANDIDATES_CLEANUP_INTERVAL) {
			
				// Remove invalid unused peer candidates
				removeInvalidUnusedPeerCandidates();
			
				// Set last unused peer candidates cleanup time to now
				lastUnusedPeerCandidatesCleanupTime = chrono::steady_clock::now();
			}
			
			// Check if time to cleanup recently attempted peer candidates
			if(chrono::steady_clock::now() - lastRecentlyAttemptedPeerCandidatesCleanupTime >= RECENTLY_ATTEMPTED_PEER_CANDIDATES_CLEANUP_INTERVAL) {
			
				// Remove not recently attempted peer candidates
				removeNotRecentlyAttemptedPeerCandidates();
			
				// Set last recently attempted peer candidates cleanup time to now
				lastRecentlyAttemptedPeerCandidatesCleanupTime = chrono::steady_clock::now();
			}
			
			// Check if time to cleanup healthy peers
			if(chrono::steady_clock::now() - lastHealthyPeersCleanupTime >= HEALTHY_PEERS_CLEANUP_INTERVAL) {
			
				// Remove unhealthy peers
				removeUnhealthyPeers();
				
				// Set last healthy peers cleanup time to now
				lastHealthyPeersCleanupTime = chrono::steady_clock::now();
			}
			
			// Check if time to cleanup banned peers
			if(chrono::steady_clock::now() - lastBannedPeersCleanupTime >= BANNED_PEERS_CLEANUP_INTERVAL) {
			
				// Remove unbanned peers
				removeUnbannedPeers();
				
				// Set last banned peers cleanup time to now
				lastBannedPeersCleanupTime = chrono::steady_clock::now();
			}
			
			// Wait for a peer event to occur
			mutex peerEventOccurredMutex;
			unique_lock peerEventOccurredLock(peerEventOccurredMutex);
			
			peerEventOccurred.wait_for(peerEventOccurredLock, PEER_EVENT_OCCURRED_TIMEOUT);
		}
	}
	
	// Catch errors
	catch(...) {
	
		// Set closing
		Common::setClosing();
	}
	
	// Check if an error occurred
	if(Common::errorOccurred()) {
	
		// Check if on error callback exists
		if(onErrorCallback) {
		
			// Run on error callback
			onErrorCallback();
		}
	}
}

// Remove disconnected peers
void Node::removeDisconnectedPeers() {

	// Set peers disconnected to false
	bool peersDisconnected = false;
	
	// Go through all peers
	for(list<Peer>::iterator i = peers.begin(); i != peers.end();) {
	
		// Get peer
		Peer &peer = *i;
		
		// Set syncing peer disconnected to false
		bool syncingPeerDisconnected = false;
		
		// Try
		try {
		
			// Lock peer for reading
			shared_lock peerReadLock(peer.getLock());
			
			// Check if peer is disconnected
			if(peer.getConnectionState() == Peer::ConnectionState::DISCONNECTED) {
			
				// Set peers disconnected to true
				peersDisconnected = true;
			
				// Check if peer was syncing
				if(peer.getSyncingState() != Peer::SyncingState::NOT_SYNCING) {
				
					// Set syncing peer disconnected to true
					syncingPeerDisconnected = true;
				}
			
				// Unlock peer read lock
				peerReadLock.unlock();
				
				// Check if peer has an identifier
				if(!peer.getIdentifier().empty()) {
				
					// Check if on peer disconnect callback exists
					if(onPeerDisconnectCallback) {
					
						// Run on peer disconnect callback
						onPeerDisconnectCallback(peer.getIdentifier());
					}
				}
			}
			
			// Otherwise
			else {
			
				// Unlock peer read lock
				peerReadLock.unlock();
			
				// Increment index
				++i;
			
				// Go to next peer
				continue;
			}
		}
		
		// Catch errors
		catch(...) {
		
			// Increment index
			++i;
		
			// Go to next peer
			continue;
		}
		
		// Check if peer has an identifier
		if(!peer.getIdentifier().empty()) {
		
			// Lock for writing
			lock_guard writeLock(lock);
			
			// Check if peer is a currently used peer candidate
			if(currentlyUsedPeerCandidates.contains(peer.getIdentifier())) {
			
				// Remove peer from the list of currently used peer candidates
				currentlyUsedPeerCandidates.erase(peer.getIdentifier());
			}
		}
		
		// Check if syncing peer was disconnected
		if(syncingPeerDisconnected) {
		
			// Stop peer
			peer.stop();
			
			// Set error occurred to false
			bool errorOccurred = false;
			
			// Check if peer's thread is running
			if(peer.getThread().joinable()) {
			
				// Try
				try {
			
					// Wait for peer's thread to finish
					peer.getThread().join();
				}
			
				// Catch errors
				catch(...) {
				
					// Set error occurred to true
					errorOccurred = true;
				}
			}
			
			// Check if peer's worker operation is running
			if(peer.isWorkerOperationRunning()) {
			
				// Set error occurred
				errorOccurred = true;
			}
		
			// Lock for writing
			lock_guard writeLock(lock);
			
			// Check if error didn't occur
			if(!errorOccurred) {
			
				// Check if performing initial sync and the peer obtained new headers
				if(syncedHeaderIndex == Consensus::GENESIS_BLOCK_HEADER.getHeight() && !peer.getHeaders().empty() && peer.getHeaders().back().getHeight() > syncedHeaderIndex) {
				
					// Set headers to peer's headers
					headers = move(peer.getHeaders());
				}
			}
			
			// Set is syncing to false
			isSyncing = false;
		}
		
		// Remove peer and go to next peer
		i = peers.erase(i);
	}
	
	// Check if peers were disconnected
	if(peersDisconnected) {
	
		// Free memory
		Common::freeMemory();
	}
}

// Remove random peer
void Node::removeRandomPeer() {

	// Set peer distribution
	uniform_int_distribution<list<Peer>::size_type> peerDistribution(0, DESIRED_NUMBER_OF_PEERS - 1);
	
	// Loop until peer is remove
	while(true) {

		// Set peer to a random peer
		list<Peer>::iterator peer = peers.begin();
		
		advance(peer, peerDistribution(randomNumberGenerator));
		
		// Set syncing peer disconnected to false
		bool syncingPeerDisconnected = false;
		
		// Try
		try {
		
			// Lock peer for reading
			shared_lock peerReadLock(peer->getLock());
			
			// Check if peer is disconnected or peer is connected and healthy and not syncing
			if(peer->getConnectionState() == Peer::ConnectionState::DISCONNECTED || (peer->getConnectionState() == Peer::ConnectionState::CONNECTED_AND_HEALTHY && peer->getSyncingState() == Peer::SyncingState::NOT_SYNCING)) {
			
				// Check if peer was syncing
				if(peer->getSyncingState() != Peer::SyncingState::NOT_SYNCING) {
				
					// Set syncing peer disconnected to true
					syncingPeerDisconnected = true;
				}
				
				// Unlock peer read lock
				peerReadLock.unlock();
				
				// Check if peer has an identifier
				if(!peer->getIdentifier().empty()) {
				
					// Check if on peer disconnect callback exists
					if(onPeerDisconnectCallback) {
					
						// Run on peer disconnect callback
						onPeerDisconnectCallback(peer->getIdentifier());
					}
				}
			}
			
			// Otherwise
			else {
			
				// Go to next random peer
				continue;
			}
		}
		
		// Catch errors
		catch(...) {
		
			// Break
			break;
		}
		
		// Check if peer has an identifier
		if(!peer->getIdentifier().empty()) {
		
			// Lock for writing
			lock_guard writeLock(lock);
			
			// Check if peer is a currently used peer candidate
			if(currentlyUsedPeerCandidates.contains(peer->getIdentifier())) {
			
				// Remove peer from the list of currently used peer candidates
				currentlyUsedPeerCandidates.erase(peer->getIdentifier());
			}
		}
		
		// Check if syncing peer was disconnected
		if(syncingPeerDisconnected) {
		
			// Stop peer
			peer->stop();
			
			// Set error occurred to false
			bool errorOccurred = false;
			
			// Check if peer's thread is running
			if(peer->getThread().joinable()) {
			
				// Try
				try {
			
					// Wait for peer's thread to finish
					peer->getThread().join();
				}
			
				// Catch errors
				catch(...) {
				
					// Set error occurred to true
					errorOccurred = true;
				}
			}
			
			// Check if peer's worker operation is running
			if(peer->isWorkerOperationRunning()) {
			
				// Set error occurred
				errorOccurred = true;
			}
		
			// Lock for writing
			lock_guard writeLock(lock);
			
			// Check if error didn't occur
			if(!errorOccurred) {
			
				// Check if performing initial sync and the peer obtained new headers
				if(syncedHeaderIndex == Consensus::GENESIS_BLOCK_HEADER.getHeight() && !peer->getHeaders().empty() && peer->getHeaders().back().getHeight() > syncedHeaderIndex) {
				
					// Set headers to peer's headers
					headers = move(peer->getHeaders());
				}
			}
			
			// Set is syncing to false
			isSyncing = false;
		}

		// Remove peer
		peers.erase(peer);
		
		// Free memory
		Common::freeMemory();
		
		// Break
		break;
	}
}

// Connect to more peers
void Node::connectToMorePeers() {

	// Lock for writing
	lock_guard writeLock(lock);
	
	// Check if more unused peer candidates are needed to obtain the desired number of peers
	if(SaturateMath::add(peers.size(), unusedPeerCandidates.size()) < DESIRED_NUMBER_OF_PEERS) {
	
		// Go through all DNS seeds
		for(const string &dnsSeed : getDnsSeeds()) {
	
			// Add DNS seed to unused peer candidates
			addUnusedPeerCandidate(string(dnsSeed));
		}
	}
	
	// Go through all of the unused peer candidates until at the desired number of peers
	for(unordered_map<string, chrono::time_point<chrono::steady_clock>>::const_iterator i = unusedPeerCandidates.cbegin(); i != unusedPeerCandidates.cend() && peers.size() != DESIRED_NUMBER_OF_PEERS;) {
	
		// Get peer candidate
		const pair<string, chrono::time_point<chrono::steady_clock>> &peerCandidate = *i;
		
		// Check if peer candidate is valid
		if(isUnusedPeerCandidateValid(peerCandidate.first)) {
	
			// Try
			try {
			
				// Create peer from peer candidate
				peers.emplace_back(peerCandidate.first, *this, peerEventOccurred, randomNumberGenerator());
			}
			
			// Catch errors
			catch(...) {
			
				// Increment index
				++i;
			
				// Go to next unused peer candidate
				continue;
			}
		}
		
		// Remove unused peer candidate from list
		i = unusedPeerCandidates.erase(i);
	}
}

// Sync
void Node::sync() {

	// Lock for writing
	lock_guard writeLock(lock);
	
	// Check if not already syncing
	if(!isSyncing) {
	
		// Initialize peers write locks
		unique_lock<shared_mutex> peersWriteLocks[peers.size()];
		
		// Set highest total difficulty to zero
		uint64_t highestTotalDifficulty = 0;
		
		// Go through all peers
		list<Peer>::size_type peerIndex = 0;
		for(list<Peer>::iterator i = peers.begin(); i != peers.end(); ++i, ++peerIndex) {
		
			// Get peer
			Peer &peer = *i;
			
			// Set peer's write lock in the list of peers write locks
			peersWriteLocks[peerIndex] = unique_lock(peer.getLock());
			
			// Check if peer is connected and healthy
			if(peer.getConnectionState() == Peer::ConnectionState::CONNECTED_AND_HEALTHY) {
			
				// Check if peer's total difficulty is higher than the highest total difficulty
				if(peer.getTotalDifficulty() > highestTotalDifficulty) {
				
					// Set the highest total difficulty to the peer's total difficulty
					highestTotalDifficulty = peer.getTotalDifficulty();
				}
			}
		}
		
		// Check if total difficulty is less than the highest total difficulty
		if(getTotalDifficulty() < highestTotalDifficulty) {
		
			// Initialize syncable peers
			vector<Peer *> syncablePeers;
		
			// Go through all peers
			peerIndex = 0;
			for(list<Peer>::iterator i = peers.begin(); i != peers.end(); ++i, ++peerIndex) {
			
				// Get peer
				Peer &peer = *i;
				
				// Check if peer is connected and healthy
				if(peer.getConnectionState() == Peer::ConnectionState::CONNECTED_AND_HEALTHY) {
				
					// Check if peer has the highest total difficulty and its message queue isn't full
					if(peer.getTotalDifficulty() == highestTotalDifficulty && !peer.isMessageQueueFull()) {
					
						// Add peer to list or syncable peers
						syncablePeers.push_back(&peer);
					}
					
					// Otherwise
					else {
					
						// Unlock peer's write lock
						peersWriteLocks[peerIndex].unlock();
					}
				}
				
				// Otherwise
				else {
				
					// Unlock peer's write lock
					peersWriteLocks[peerIndex].unlock();
				}
			}
			
			// Check if a syncable peer exists
			if(!syncablePeers.empty()) {
			
				// Set peer distribution
				uniform_int_distribution<vector<Peer *>::size_type> peerDistribution(0, syncablePeers.size() - 1);
				
				// Start syncing with a random syncable peer
				syncablePeers[peerDistribution(randomNumberGenerator)]->startSyncing(headers, syncedHeaderIndex);
				
				// Set is syncing to true
				isSyncing = true;
				
				// Check if on start syncing callback exists
				if(onStartSyncingCallback) {
				
					// Run on start syncing callback
					onStartSyncingCallback();
					
					// Remove on start syncing callback
					onStartSyncingCallback = nullptr;
				}
			}
		}
		
		// Otherwise
		else {
		
			// Check if on start syncing callback exists
			if(onStartSyncingCallback) {
			
				// Run on start syncing callback
				onStartSyncingCallback();
				
				// Remove on start syncing callback
				onStartSyncingCallback = nullptr;
			}
			
			// Set is synced to true
			isSynced = true;
			
			// Check if on synced callback exists
			if(onSyncedCallback) {
			
				// Run on synced callback
				onSyncedCallback();
				
				// Remove on synced callback
				onSyncedCallback = nullptr;
			}
		}
	}
}

// Remove invalid unused peer candidates
void Node::removeInvalidUnusedPeerCandidates() {

	// Lock for writing
	lock_guard writeLock(lock);

	// Go through all of the unused peer candidates
	for(unordered_map<string, chrono::time_point<chrono::steady_clock>>::const_iterator i = unusedPeerCandidates.cbegin(); i != unusedPeerCandidates.cend();) {
	
		// Get peer candidate
		const pair<string, chrono::time_point<chrono::steady_clock>> &peerCandidate = *i;
		
		// Check if peer candidate isn't valid
		if(!isUnusedPeerCandidateValid(peerCandidate.first)) {
		
			// Remove peer candidate from list
			i = unusedPeerCandidates.erase(i);
		}
		
		// Otherwise
		else {
		
			// Go to next unused peer candidate
			++i;
		}
	}
}

// Remove not recently attempted peer candidates
void Node::removeNotRecentlyAttemptedPeerCandidates() {

	// Lock for writing
	lock_guard writeLock(lock);

	// Go through all of the recently attempted peer candidates
	for(unordered_map<string, chrono::time_point<chrono::steady_clock>>::const_iterator i = recentlyAttemptedPeerCandidates.cbegin(); i != recentlyAttemptedPeerCandidates.cend();) {
	
		// Get peer candidate
		const pair<string, chrono::time_point<chrono::steady_clock>> &peerCandidate = *i;
		
		// Check if peer candidate isn't recently attempted
		if(!isPeerCandidateRecentlyAttempted(peerCandidate.first)) {
		
			// Remove peer candidate from list
			i = recentlyAttemptedPeerCandidates.erase(i);
		}
		
		// Otherwise
		else {
		
			// Go to next recently attempted peer candidate
			++i;
		}
	}
}

// Remove unhealthy peers
void Node::removeUnhealthyPeers() {

	// Lock sfor writing
	lock_guard writeLock(lock);

	// Go through all of the healthy peers
	for(unordered_map<string, pair<chrono::time_point<chrono::steady_clock>, Capabilities>>::const_iterator i = healthyPeers.cbegin(); i != healthyPeers.cend();) {
	
		// Get peer
		const pair<string, pair<chrono::time_point<chrono::steady_clock>, Capabilities>> &peer = *i;
		
		// Check if peer isn't healthy
		if(!isPeerHealthy(peer.first)) {
		
			// Remove peer from list
			i = healthyPeers.erase(i);
		}
		
		// Otherwise
		else {
		
			// Go to next healthy peer
			++i;
		}
	}
}

// Remove unbanned peers
void Node::removeUnbannedPeers() {

	// Lock for writing
	lock_guard writeLock(lock);

	// Go through all of the banned peers
	for(unordered_map<string, chrono::time_point<chrono::steady_clock>>::const_iterator i = bannedPeers.cbegin(); i != bannedPeers.cend();) {
	
		// Get peer
		const pair<string, chrono::time_point<chrono::steady_clock>> &peer = *i;
		
		// Check if peer isn't banned
		if(!isPeerBanned(peer.first)) {
		
			// Remove peer from list
			i = bannedPeers.erase(i);
		}
		
		// Otherwise
		else {
		
			// Go to next banned peer
			++i;
		}
	}
}
