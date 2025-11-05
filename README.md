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
	
	// At this point all node functions are allowed in this thread. The node's state can be restored with node.restore("state_file")
	
	// Set node's on start syncing callback
	node.setOnStartSyncingCallback([](MwcValidationNode::Node &node) -> void {
	
		// Do something when the node starts syncing (this happens once when the node starts syncing)
	});
	
	// Set node's on synced syncing callback
	node.setOnSyncedCallback([](MwcValidationNode::Node &node) -> void {
	
		// Do something when the node is synced (this happens once when the node is done syncing if syncing isn't interrupted in this callback)
	});
	
	// Set node's on error callback
	node.setOnErrorCallback([](MwcValidationNode::Node &node) -> void {
	
		// Do something when the node fails (this happens once if the node fails and cannot recover)
	});
	
	// Set node's on transaction hash set callback
	node.setOnTransactionHashSetCallback([](MwcValidationNode::Node &node, const MwcValidationNode::MerkleMountainRange<MwcValidationNode::Header> &headers, const MwcValidationNode::Header &transactionHashSetArchiveHeader, const MwcValidationNode::MerkleMountainRange<MwcValidationNode::Kernel> &kernels, const MwcValidationNode::MerkleMountainRange<MwcValidationNode::Output> &outputs, const MwcValidationNode::MerkleMountainRange<MwcValidationNode::Rangeproof> &rangeproofs, const uint64_t oldHeight) -> bool {
	
		// Do something when a transaction hash set is received from a peer (this happens everytime a transaction hash set is received)
		
		// Return true if the transaction hash set should be used otherwise return false or throw an exception
		return true;
	});
	
	// Set node's on block callback
	node.setOnBlockCallback([](MwcValidationNode::Node &node, const MwcValidationNode::Header &header, const MwcValidationNode::Block &block, const uint64_t oldHeight) -> bool {
	
		// Do something when a block is added to the blockchain (this happens everytime a block is added to the blockchain)
		
		// Return true if the block should be kept otherwise return false or throw an exception
		return true;
	});
	
	// Set node's on peer connect callback
	node.setOnPeerConnectCallback([](MwcValidationNode::Node &node, const string &peerIdentifier) -> void {
	
		// Do something when the node connects to a peer (this happens everytime the node connects to a peer)
	});
	
	// Set node's on peer info callback
	node.setOnPeerInfoCallback([](MwcValidationNode::Node &node, const string &peerIdentifier, const MwcValidationNode::Node::Capabilities capabilities, const string &userAgent, const uint32_t protocolVersion, const uint64_t baseFee, const uint64_t totalDifficulty, const bool isInbound) -> void {
	
		// Do something when a connected peer's info becomes known (this happens once per connected peer when that peer's info first becomes known)
	});
	
	// Set node's on peer update callback
	node.setOnPeerUpdateCallback([](MwcValidationNode::Node &node, const string &peerIdentifier, const uint64_t totalDifficulty, const uint64_t height) -> void {
	
		// Do something when a connected peer's total difficulty changes (this happens everytime a connected peer's total difficulty changes)
	});
	
	// Set node's on peer healthy callback
	node.setOnPeerHealthyCallback([](MwcValidationNode::Node &node, const string &peerIdentifier) -> bool {
	
		// Do something when a connected peer is considered healthy (this happens once per connected peer when the peer sends a valid Message::PEER_ADDRESSES message)
		
		// Return true to stay connected to the peer otherwise return false or throw an exception
		return true;
	});
	
	// Set node's on peer disconnect callback
	node.setOnPeerDisconnectCallback([](MwcValidationNode::Node &node, const string &peerIdentifier) -> void {
	
		// Do something when the node disconnects from a peer (this happens everytime the node disconnects from a peer)
	});
	
	// Set node's on transaction added to mempool callback
	node.setOnTransactionAddedToMempoolCallback([](MwcValidationNode::Node &node, const MwcValidationNode::Transaction &transaction, const unordered_set<const MwcValidationNode::Transaction *> &replacedTransactions) -> void {
	
		// Do something when a transaction is added to the node's mempool (this happens everytime a transaction is added to the node's mempool)
	});
	
	// Set node's on transaction removed from mempool callback
	node.setOnTransactionRemovedFromMempoolCallback([](MwcValidationNode::Node &node, const MwcValidationNode::Transaction &transaction) -> void {
	
		// Do something when a transaction is removed from the node's mempool (this happens everytime a transaction is removed from the node's mempool which can be caused by it being replaced by fee or it being added to a block)
	});
	
	// Set node's on mempool clear callback
	node.setOnMempoolClearCallback([](MwcValidationNode::Node &node) -> void {
	
		// Do something when the node's mempool is cleared (this happens everytime the node's mempool is cleared which can be caused when the node uses a new transaction hash set or when it recovers from an error)
	});
	
	// Start node (you can can set the node's Tor proxy address, Tor proxy port, DNS seed, base fee, listening address, listening port, and desired peer capabilities here)
	node.start();
	
	// Other things can be done here since the node is running in its own thread. The only node functions allowed in this thread now while the node is running are node.stop(), node.getThread(), node.broadcastTransaction(), node.broadcastBlock(), and calling the node's destructor. All other node functions must happen in the callback functions
	
	// Stop node
	node.stop();
	
	// Wait for node to stop running
	node.getThread().join();
	
	// The node has stopped running, however it remains connected to any existing peers. Additional node functions that are allowed in this thread now are node.getPeersBegin(), node.getPeersEnd(), and node.disconnect(). All other node functions must happen in the callback functions
	
	// Disconnect from node's peers and wait for the operation to complete
	node.disconnect();
	
	// At this point the node's state won't change, it's disconnected from all peers, and it can't be started again. All node functions are allowed in this thread now. The node's state can be saved with node.save("state_file")
	
	// Return success
	return EXIT_SUCCESS;
}
```
All node functions throw a runtime exception if they fail. All callback functions may be running in a separate thread so make sure any variables access in them are thread safe. Only one callback function will run at a time and access to the node within the callback functions is thread safe. Don't call a node's destructor, `node.broadcastTransaction()`, or `node.broadcastBlock()` inside the callback functions.

The following flags can be defined before `#include "./mwc_validation_node.h"` to enable or change certain features:
* `#define DISABLE_SIGNAL_HANDLER`: Don't use builtin signal handler for `SIGINT` that stops the node.
* `#define ENABLE_FLOONET`: Uses floonet instead of mainnet.
* `#define ENABLE_TOR`: Uses the Tor SOCKS5 proxy listening at `localhost:9050` for all peer communication. This address can be changed by providing an address and port to the node's `node.start()` function.
* `#define ENABLE_MEMPOOL`: Enables keeping track of transactions in the node's mempool. Mempool related node callback functions and `node.getNextBlock()` can be used with this enabled.
* `#define PRUNE_HEADERS`: Removes headers after they are no longer needed to verify the blockchain.
* `#define PRUNE_KERNELS`: Removes kernels after they are no longer needed to verify the blockchain.
* `#define PRUNE_RANGEPROOFS`: Removes rangeproofs after they are no longer needed to verify the blockchain.
