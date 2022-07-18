// Header files
#include "./common.h"
#include "./consensus.h"
#include "./crypto.h"
#include "./node.h"
#include "./peer.h"
#include "./saturate_math.h"

using namespace std;


// Constants

// Capabilities
const Node::Capabilities Node::CAPABILITIES = Node::Capabilities::PEER_LIST;

// Check if floonet
#ifdef FLOONET

	// DNS seeds
	const unordered_set<string> Node::DNS_SEEDS = {
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

	// DNS seeds
	const unordered_set<string> Node::DNS_SEEDS = {
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
const list<Peer>::size_type Node::MINIMUM_NUMBER_OF_CONNECTED_AND_HEALTHY_PEERS_TO_START_SYNCING = 3;

// Delay before syncing duration
const chrono::seconds Node::DELAY_BEFORE_SYNCING_DURATION = 30s;

// Peer event occurred timeout
const chrono::milliseconds Node::PEER_EVENT_OCCURRED_TIMEOUT = 100ms;

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


// Supporting function implementation

// Constructor
Node::Node() :

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

	// Set stop monitoring to false
	stopMonitoring(false),
	
	// Create main thread
	mainThread(&Node::monitor, this)
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
const uint64_t Node::getTotalDifficulty() const {

	// Return total difficulty of the synced header
	return headers.getLeaf(syncedHeaderIndex)->getTotalDifficulty();
}

// Get height
const uint64_t Node::getHeight() const {

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
const bool Node::isUnusedPeerCandidateValid(const string &peerCandidate) const {

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
const bool Node::isPeerCandidateRecentlyAttempted(const string &peerCandidate) const {

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
const bool Node::isPeerHealthy(const string &peer) const {

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
const bool Node::isPeerBanned(const string &peer) const {

	// Return if peer is banned
	return bannedPeers.contains(peer) && chrono::steady_clock::now() - bannedPeers.at(peer) <= BANNED_PEER_DURATION;
}

// Set sync state
void Node::setSyncState(MerkleMountainRange<Header> &&headers, const uint64_t syncedHeaderIndex, MerkleMountainRange<Kernel> &&kernels, MerkleMountainRange<Output> &&outputs, MerkleMountainRange<Rangeproof> &&rangeproofs) {

	// Check if a reorg occurred
	if(this->syncedHeaderIndex >= syncedHeaderIndex) {
	
		// Display text
		Common::displayText("Reorg occurred with depth: " + to_string(this->syncedHeaderIndex - syncedHeaderIndex + 1));
	}
	
	// Set headers to headers
	this->headers = move(headers);
	
	// Set synced header index to synced header index
	this->syncedHeaderIndex = syncedHeaderIndex;
	
	// Set kernels to kernels
	this->kernels = move(kernels);
	
	// Set outputs to outputs
	this->outputs = move(outputs);
	
	// Set rangeproofs to rangeproofs
	this->rangeproofs = move(rangeproofs);
	
	// Set is syncing to false
	isSyncing = false;
	
	// Display text
	Common::displayText("Block height: " + to_string(this->headers.getLeaf(this->syncedHeaderIndex)->getHeight()) + " at " + to_string(chrono::duration_cast<chrono::seconds>(this->headers.getLeaf(this->syncedHeaderIndex)->getTimestamp().time_since_epoch()).count()));
}

// Update sync state
const bool Node::updateSyncState(MerkleMountainRange<Header> &&headers, const uint64_t syncedHeaderIndex, Block &&block) {

	// Set headers to headers
	this->headers = move(headers);
	
	// Return updating sync state
	return updateSyncState(syncedHeaderIndex, move(block));
}

// Update sync state
const bool Node::updateSyncState(const uint64_t syncedHeaderIndex, Block &&block) {

	// Check if a reorg occurred
	if(this->syncedHeaderIndex >= syncedHeaderIndex) {
	
		// Display text
		Common::displayText("Reorg occurred with depth: " + to_string(this->syncedHeaderIndex - syncedHeaderIndex + 1));
	}
	
	// Set synced header index to synced header index
	this->syncedHeaderIndex = syncedHeaderIndex;
	
	// Set result to true
	bool result = true;

	// Try
	try {
		
		// Rewind kernels, outputs, and rangeproofs to the previous synced header
		kernels.rewindToSize(this->headers.getLeaf(this->syncedHeaderIndex - 1)->getKernelMerkleMountainRangeSize());
		outputs.rewindToSize(this->headers.getLeaf(this->syncedHeaderIndex - 1)->getOutputMerkleMountainRangeSize());
		rangeproofs.rewindToSize(this->headers.getLeaf(this->syncedHeaderIndex - 1)->getOutputMerkleMountainRangeSize());

		// Go through all of the block's outputs
		for(Output &output : block.getOutputs()) {
		
			// Check if output already exists
			if(outputs.getLeafByLookupValue(output.getLookupValue().value())) {
			
				// Set result to false
				result = false;
			
				// Throw exception
				throw runtime_error("Output already exists");
			}
		
			// Append output to outputs
			outputs.appendLeaf(move(output));
		}
		
		// Get header at the synced header index
		const Header *header = this->headers.getLeaf(this->syncedHeaderIndex);
		
		// Get unspendable coinbase outputs starting index
		const uint64_t unspendableCoinbaseOutputsStartingIndex = MerkleMountainRange<Header>::getNumberOfLeavesAtSize(this->headers.getLeaf(SaturateMath::subtract(header->getHeight(), Consensus::COINBASE_MATURITY))->getOutputMerkleMountainRangeSize());
		
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
			if(input.getFeatures() == Input::Features::COINBASE) {
			
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
		
		// Go through all of the block's rangeproofs
		for(Rangeproof &rangeproof : block.getRangeproofs()) {
		
			// Append rangeproof to rangeproofs
			rangeproofs.appendLeaf(move(rangeproof));
			
			// Check if pruning rangeproofs
			#ifdef PRUNE_RANGEPROOFS
			
				// Prune rangeproof
				rangeproofs.pruneLeaf(rangeproofs.getNumberOfLeaves() - 1);
			#endif
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
		for(Kernel &kernel : block.getKernels()) {
		
			// TODO NRD check for floonet
		
			// Append kernel to kernels
			kernels.appendLeaf(move(kernel));
			
			// Prune kernel
			kernels.pruneLeaf(kernels.getNumberOfLeaves() - 1);
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
		
		// Display text
		Common::displayText("Block height: " + to_string(this->headers.getLeaf(this->syncedHeaderIndex)->getHeight()) + " at " + to_string(chrono::duration_cast<chrono::seconds>(this->headers.getLeaf(this->syncedHeaderIndex)->getTimestamp().time_since_epoch()).count()));
	}
	
	// Catch errors
	catch(...) {
	
		// Check if updating sync state failed
		if(!result) {
	
			// Decrement synced header index
			--this->syncedHeaderIndex;
			
			// Rewind kernels, outputs, and rangeproofs to the synced header
			kernels.rewindToSize(this->headers.getLeaf(this->syncedHeaderIndex)->getKernelMerkleMountainRangeSize());
			outputs.rewindToSize(this->headers.getLeaf(this->syncedHeaderIndex)->getOutputMerkleMountainRangeSize());
			rangeproofs.rewindToSize(this->headers.getLeaf(this->syncedHeaderIndex)->getOutputMerkleMountainRangeSize());
		}
		
		// Otherwise
		else {
		
			// Set headers to include the genesis block header
			this->headers.clear();
			this->headers.appendLeaf(Consensus::GENESIS_BLOCK_HEADER);
			
			// Set synced header index to the newest known height
			this->syncedHeaderIndex = this->headers.back().getHeight();
			
			// Set kernels to include the genesis block kernel
			kernels.clear();
			kernels.appendLeaf(Consensus::GENESIS_BLOCK_KERNEL);
			
			// Set outputs to include the genesis block output
			outputs.clear();
			outputs.appendLeaf(Consensus::GENESIS_BLOCK_OUTPUT);
			
			// Set rangeproofs to include the genesis block rangeproof
			rangeproofs.clear();
			rangeproofs.appendLeaf(Consensus::GENESIS_BLOCK_RANGEPROOF);
			
			// Set is syncing to false
			isSyncing = false;
			
			// Return true
			return true;
		}
	}
	
	// Loop while headers can be pruned
	while(this->syncedHeaderIndex - this->headers.front().getHeight() > Consensus::DIFFICULTY_ADJUSTMENT_WINDOW && this->syncedHeaderIndex - this->headers.front().getHeight() >= Consensus::COINBASE_MATURITY && this->syncedHeaderIndex - this->headers.front().getHeight() > Consensus::CUT_THROUGH_HORIZON) {
	
		// Prune oldest header
		this->headers.pruneLeaf(this->headers.front().getHeight());
	}
	
	// Check if headers minimum size can be updated
	if(MerkleMountainRange<Header>::getSizeAtNumberOfLeaves(this->headers.front().getHeight() + 1) > this->headers.getMinimumSize()) {
	
		// Set headers minimum size to the first header
		this->headers.setMinimumSize(MerkleMountainRange<Header>::getSizeAtNumberOfLeaves(this->headers.front().getHeight() + 1));
	}
	
	// Check if kernels minimum size can be updates
	if(this->headers.front().getKernelMerkleMountainRangeSize() > kernels.getMinimumSize()) {
	
		// Set kernels minimum size to the first header
		kernels.setMinimumSize(this->headers.front().getKernelMerkleMountainRangeSize());
	}
	
	// Check if outputs minimum size can be updated
	if(this->headers.front().getOutputMerkleMountainRangeSize() > outputs.getMinimumSize()) {
	
		// Set outputs minimum size to the first header
		outputs.setMinimumSize(this->headers.front().getOutputMerkleMountainRangeSize());
	}
	
	// Check if rangeproofs minimum size can be updated
	if(this->headers.front().getOutputMerkleMountainRangeSize() > rangeproofs.getMinimumSize()) {
	
		// Set rangeproofs minimum size to the first header
		rangeproofs.setMinimumSize(this->headers.front().getOutputMerkleMountainRangeSize());
	}
	
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
}

// Remove disconnected peers
void Node::removeDisconnectedPeers() {

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
			
				// Check if peer was syncing
				if(peer.getSyncingState() != Peer::SyncingState::NOT_SYNCING) {
				
					// Set syncing peer disconnected to true
					syncingPeerDisconnected = true;
				}
			
				// Unlock peer read lock
				peerReadLock.unlock();
				
				// Check if peer has an identifier
				if(!peer.getIdentifier().empty()) {
				
					// Display text
					Common::displayText("Disconnected from peer: " + peer.getIdentifier());
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
		
			// Lock for writing
			lock_guard writeLock(lock);
			
			// Set is syncing to false
			isSyncing = false;
		}
	
		// Remove peer and go to next peer
		i = peers.erase(i);
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
			
			// Check if peer is disconnected or perr is connected and healthy and not syncing
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
				
					// Display text
					Common::displayText("Disconnected from peer: " + peer->getIdentifier());
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
		
			// Lock for writing
			lock_guard writeLock(lock);
			
			// Set is syncing to false
			isSyncing = false;
		}

		// Remove peer
		peers.erase(peer);
		
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
		for(const string &dnsSeed : DNS_SEEDS) {
	
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

	// Set first sync to true
	static bool firstSync = true;

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
			
				// Check if peer's total difficulty is higher than the highest total difficulty and its message queue isn't full
				if(peer.getTotalDifficulty() > highestTotalDifficulty && !peer.isMessageQueueFull()) {
				
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
			list<Peer>::size_type peerIndex = 0;
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
			
			// Set peer distribution
			uniform_int_distribution<vector<Peer *>::size_type> peerDistribution(0, syncablePeers.size() - 1);
			
			// Start syncing with a random syncable peer
			syncablePeers[peerDistribution(randomNumberGenerator)]->startSyncing(headers, syncedHeaderIndex);
			
			// Set is syncing to true
			isSyncing = true;
			
			// Check if first sync
			if(firstSync) {
			
				// Set first sync to false
				firstSync = false;
			
				// Display text
				Common::displayText("Syncing");
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
