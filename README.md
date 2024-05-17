# MWC Validation Node

### Description
Validation node for the MimbleWimble Coin network.

### Building
This program can be built with the following commands:
```
make dependencies
make
```

The optional arguments `FLOONET` and `TOR` can be used when compiling this program to compile for floonet and Tor respectively. For example:
```
make FLOONET=1 TOR=1
```

### Running
This program can be ran after it's been built with the following command:
```
make run
```

### Embedding node
This node can be embedded into other applications and it provides a callback interface that an application can use to run functions when specific node events occur. Here's a simple example without any error handling of how to do this:
```
// Header files
#include "./mwc_validation_node.h"

// Main function
int main() {

	// Initialize common (if not using your own signal handler)
	MwcValidationNode::Common::initialize();
	
	// Create node
	MwcValidationNode::Node node;
	
	// Set node's on start syncing callback
	node.setOnStartSyncingCallback([]() -> void {
	
		// Do something when node starts syncing (this happens once when the node start syncing)
	});
	
	// Set node's on synced syncing callback
	node.setOnSyncedCallback([]() -> void {
	
		// Do something when node is synced (this happens once when the node is done syncing if syncing isn't interrupted in this callback)
	});
	
	// Set node's on error callback
	node.setOnErrorCallback([]() -> void {
	
		// Do something when node fails (this happens once if the node fails and cannot recover)
	});
	
	// Set node's on transaction hash set callback
	node.setOnTransactionHashSetCallback([](const MwcValidationNode::MerkleMountainRange<MwcValidationNode::Header> &headers, const MwcValidationNode::Header &transactionHashSetArchiveHeader, const MwcValidationNode::MerkleMountainRange<MwcValidationNode::Kernel> &kernels, const MwcValidationNode::MerkleMountainRange<MwcValidationNode::Output> &outputs, const MwcValidationNode::MerkleMountainRange<MwcValidationNode::Rangeproof> &rangeproofs) -> bool {
	
		// Do something when a transaction hash set is received from a peer (this happens everytime a transaction hash set is obtained)
		
		// Return true if the transaction hash set should be used otherwise return false
		return true;
	});
	
	// Set node's on block callback
	node.setOnBlockCallback([](const MwcValidationNode::Header &header, const MwcValidationNode::Block &block, const uint64_t oldHeight) -> bool {
	
		// Do something when a block is added to the blockchain (this happens everytime a block is added to the blockchain)
		
		// Return true if the block should be kept otherwise return false
		return true;
	});
	
	// Set node's on peer connect callback
	node.setOnPeerConnectCallback([](const string &peerIdentifier) -> void {
	
		// Do something when node connects to a peer (this happens everytime the node connects to a peer)
	});
	
	// Set node's on peer disconnect callback
	node.setOnPeerDisconnectCallback([](const string &peerIdentifier) -> void {
	
		// Do something when node disconnects from a peer (this happens everytime the node disconnects from a peer)
	});
	
	// Set node's on transaction callback
	node.setOnTransactionCallback([](const MwcValidationNode::Transaction &transaction, const unordered_set<const MwcValidationNode::Transaction *> &replacedTransactions) -> void {
	
		// Do something when a transaction is added to the node's mempool (this happens everytime a transaction is added to the node's mempool)
	});
	
	// Start node
	node.start();
	
	// Other things can be done here since the node is running in its own thread
	
	// Wait for node to finish
	node.getThread().join();
	
	// Return success
	return EXIT_SUCCESS;
}
```
