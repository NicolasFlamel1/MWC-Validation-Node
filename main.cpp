// Header files
#include "./mwc_validation_node.h"
#include <iostream>
#include <mutex>

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

		// Check if initializing common failed
		if(!MwcValidationNode::Common::initialize()) {
		
			// Return failure
			return EXIT_FAILURE;
		}
		
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
		
		// Create message lock
		mutex messageLock;
		
		// Set node's on start syncing callback
		node.setOnStartSyncingCallback([&messageLock]() -> void {
		
			// Try
			try {
			
				// Lock message lock
				lock_guard lock(messageLock);
				
				// Display message
				cout << "Syncing" << endl;
			}
			
			// Catch errors
			catch(...) {
			
			}
		});
		
		// Set node's on synced syncing callback
		node.setOnSyncedCallback([&messageLock]() -> void {
		
			// Try
			try {
			
				// Lock message lock
				lock_guard lock(messageLock);
				
				// Display message
				cout << "Synced" << endl;
			}
			
			// Catch errors
			catch(...) {
			
			}
		});
		
		// Set node's on block callback
		node.setOnBlockCallback([&messageLock](const MwcValidationNode::Header &header, const MwcValidationNode::Block &block, const uint64_t oldHeight) -> bool {
		
			// Try
			try {
			
				// Lock message lock
				lock_guard lock(messageLock);
				
				// Check if a reorg occurred
				if(oldHeight >= header.getHeight()) {
				
					// Display message
					cout << "Reorg occurred with depth: " << (oldHeight - header.getHeight() + 1) << endl;
				}
				
				// Display message
				cout << "Block height: " << header.getHeight() << " at " << chrono::duration_cast<chrono::seconds>(header.getTimestamp().time_since_epoch()).count() << endl;
			}
			
			// Catch errors
			catch(...) {
			
			}
			
			// Return true
			return true;
		});
		
		// Set node's on peer connect callback
		node.setOnPeerConnectCallback([&messageLock](const string &peerIdentifier) -> void {
		
			// Try
			try {
			
				// Lock message lock
				lock_guard lock(messageLock);
				
				// Display message
				cout << "Connected to peer: " << peerIdentifier << endl;
			}
			
			// Catch errors
			catch(...) {
			
			}
		});
		
		// Set node's on peer disconnect callback
		node.setOnPeerDisconnectCallback([&messageLock](const string &peerIdentifier) -> void {
		
			// Try
			try {
			
				// Lock message lock
				lock_guard lock(messageLock);
				
				// Display message
				cout << "Disconnected from peer: " << peerIdentifier << endl;
			}
			
			// Catch errors
			catch(...) {
			
			}
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
