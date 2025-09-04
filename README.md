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
	
	// At this point all node functions are allowed in this thread. The node's state can be restored with node.restore("state_file")
	
	// Start node
	node.start();
	
	// Other things can be done here since the node is running in its own thread. The only node functions allowed in this thread now while the node is running are node.stop(), node.getThread(), and calling the node's destructor. All other node functions must happen in the callback functions
	
	// Stop node
	node.stop();
	
	// Wait for node to stop running
	node.getThread().join();
	
	// The node has stopped running, however it remains connected to any existing peers. Additional node functions that are allowed in this thread now are node.getPeers() and node.disconnect(). All other node functions must happen in the callback functions
	
	// Disconnect from node's peers and wait for the operation to complete
	node.disconnect();
	
	// At this point the node's state won't change and the node can't be started again. All node functions are allowed in this thread now. The node's state can be saved with node.save("state_file")
	
	// Return success
	return EXIT_SUCCESS;
}
```
All node functions throw an runtime exception if they fail. All callback functions may be running in a separate thread so make sure any variables access in them are thread safe. Don't call a node's destructor, node.broadcastTransaction(), or node.broadcastBlock() inside the callback functions.
