// Header files
#include "./common.h"
#include <iostream>
#include <mutex>
#include "./node.h"

using namespace std;


// Namespace
using namespace MwcValidationNode;


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
		if(!Common::initialize()) {
		
			// Return failure
			return EXIT_FAILURE;
		}
		
		// Check if Windows
		#ifdef _WIN32
		
			// Create Windows socket
			WindowsSocket windowsSocket;
		#endif
		
		// Create node
		Node node;
		
		// Create message lock
		mutex messageLock;
		
		// Set node's on start syncing callback
		node.setOnStartSyncingCallback([&messageLock]() {
		
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
		node.setOnSyncedCallback([&messageLock]() {
		
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
		
		// Set node's on reorg callback
		node.setOnReorgCallback([&node, &messageLock](const uint64_t newHeight) -> bool {
		
			// Try
			try {
			
				// Lock message lock
				lock_guard lock(messageLock);
				
				// Display message
				cout << "Reorg occurred with depth: " << (node.getHeight() - newHeight + 1) << endl;
			}
			
			// Catch errors
			catch(...) {
			
			}
			
			// Return true;
			return true;
		});
		
		// Set node's on block callback
		node.setOnBlockCallback([&messageLock](const Header &header, const Block &block) -> bool {
		
			// Try
			try {
			
				// Lock message lock
				lock_guard lock(messageLock);
				
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
		node.setOnPeerConnectCallback([&messageLock](const string &peerIdentifier) {
		
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
		node.setOnPeerDisconnectCallback([&messageLock](const string &peerIdentifier) {
		
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
		
		// Check if an error occurred
		if(Common::errorOccurred()) {
		
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
