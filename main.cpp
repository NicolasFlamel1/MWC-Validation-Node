// Header files
#include "./mwc_validation_node.h"
#include <iostream>

using namespace std;


// Classes

// Check if Windows
#ifdef _WIN32

	// Windows socket class
	class WindowsSocket final {

		// Public
		public:
		
			// Constructor
			WindowsSocket();
			
			// Destructor
			~WindowsSocket();
		
		// Private
		private:
		
			// Major version
			static const BYTE MAJOR_VERSION;
			
			// Minor version
			static const BYTE MINOR_VERSION;
	};
#endif


// Constants

// State file name
static const char *STATE_FILE_NAME = "state";

// Check if Windows
#ifdef _WIN32

	// Windows socket major version
	const BYTE WindowsSocket::MAJOR_VERSION = 2;
	
	// Windows socket minor version
	const BYTE WindowsSocket::MINOR_VERSION = 2;
#endif


// Main function
int main() {

	// Try
	try {
	
		// Check if Windows
		#ifdef _WIN32
		
			// Create Windows socket
			const WindowsSocket windowsSocket;
		#endif
		
		// Create node
		MwcValidationNode::Node node;
		
		// Try
		try {
		
			// Set state file to throw exception on error
			ifstream stateFile;
			stateFile.exceptions(ios::badbit | ios::failbit);
			
			// Open state file
			stateFile.open(STATE_FILE_NAME, ios::binary);
			
			// Restore node from state file
			node.restore(stateFile);
			
			// Close state file
			stateFile.close();
		}
		
		// Catch errors
		catch(...) {
		
		}
		
		// Set node's on start syncing callback
		node.setOnStartSyncingCallback([](MwcValidationNode::Node &node) -> void {
		
			// Display message
			cout << "Syncing" << endl;
		});
		
		// Set node's on synced syncing callback
		node.setOnSyncedCallback([](MwcValidationNode::Node &node) -> void {
		
			// Display message
			cout << "Synced" << endl;
		});
		
		// Set node's on transaction hash set callback
		node.setOnTransactionHashSetCallback([](MwcValidationNode::Node &node, const MwcValidationNode::MerkleMountainRange<MwcValidationNode::Header> &headers, const MwcValidationNode::Header &transactionHashSetArchiveHeader, const MwcValidationNode::MerkleMountainRange<MwcValidationNode::Kernel> &kernels, const MwcValidationNode::MerkleMountainRange<MwcValidationNode::Output> &outputs, const MwcValidationNode::MerkleMountainRange<MwcValidationNode::Rangeproof> &rangeproofs, const uint64_t oldHeight) -> bool {
		
			// Check if a reorg occurred
			if(oldHeight >= transactionHashSetArchiveHeader.getHeight()) {
			
				// Display message
				cout << "Reorg occurred with depth: " << (oldHeight - transactionHashSetArchiveHeader.getHeight() + 1) << endl;
			}
			
			// Display message
			cout << "Transaction hash set height: " << transactionHashSetArchiveHeader.getHeight() << " at " << chrono::duration_cast<chrono::seconds>(transactionHashSetArchiveHeader.getTimestamp().time_since_epoch()).count() << endl;
			
			// Return true
			return true;
		});
		
		// Set node's on block callback
		node.setOnBlockCallback([](MwcValidationNode::Node &node, const MwcValidationNode::Header &header, const MwcValidationNode::Block &block, const uint64_t oldHeight) -> bool {
		
			// Check if a reorg occurred
			if(oldHeight >= header.getHeight()) {
			
				// Display message
				cout << "Reorg occurred with depth: " << (oldHeight - header.getHeight() + 1) << endl;
			}
			
			// Display message
			cout << "Block height: " << header.getHeight() << " at " << chrono::duration_cast<chrono::seconds>(header.getTimestamp().time_since_epoch()).count() << endl;
			
			// Return true
			return true;
		});
		
		// Set node's on peer connect callback
		node.setOnPeerConnectCallback([](MwcValidationNode::Node &node, const string &peerIdentifier) -> void {
		
			// Display message
			cout << "Connected to peer: " << peerIdentifier << endl;
		});
		
		// Set node's on peer info callback
		node.setOnPeerInfoCallback([](MwcValidationNode::Node &node, const string &peerIdentifier, const MwcValidationNode::Node::Capabilities capabilities, const string &userAgent, const uint32_t protocolVersion, const uint64_t baseFee, const uint64_t totalDifficulty) -> void {
		
			// Display message
			cout << "Peer " << peerIdentifier << " is " << userAgent << endl;
		});
		
		// Set node's on peer disconnect callback
		node.setOnPeerDisconnectCallback([](MwcValidationNode::Node &node, const string &peerIdentifier) -> void {
		
			// Display message
			cout << "Disconnected from peer: " << peerIdentifier << endl;
		});
		
		// Start node
		node.start();
		
		// Wait for node to finish
		node.getThread().join();
		
		// Disconnect node
		node.disconnect();
		
		// Try
		try {
		
			// Set state file to throw exception on error
			ofstream stateFile;
			stateFile.exceptions(ios::badbit | ios::failbit);
			
			// Open state file
			stateFile.open(STATE_FILE_NAME, ios::binary | ios::trunc);
			
			// Save node to state file
			node.save(stateFile);
			
			// Close state file
			stateFile.close();
		}
		
		// Catch errors
		catch(...) {
		
			// Return failure
			return EXIT_FAILURE;
		}
		
		// Check if an error occurred
		if(MwcValidationNode::Common::errorOccurred()) {
		
			// Return failure
			return EXIT_FAILURE;
		}
	}
	
	// Catch errors
	catch(...) {
	
		// Return failure
		return EXIT_FAILURE;
	}
	
	// Return success
	return EXIT_SUCCESS;
}


// Supporting function implementation

// Check if Windows
#ifdef _WIN32

	// Windows socket constructor
	WindowsSocket::WindowsSocket() {

		// Check if initializing Windows socket failed
		WSADATA windowsSocketData;
		if(WSAStartup(MAKEWORD(WindowsSocket::MAJOR_VERSION, WindowsSocket::MINOR_VERSION), &windowsSocketData)) {
		
			// Throw exception
			throw runtime_error("Initializing Windows socket failed");
		}
	}

	// Windows socket destructor
	WindowsSocket::~WindowsSocket() {

		// Clean up Windows socket
		WSACleanup();
	}
#endif
