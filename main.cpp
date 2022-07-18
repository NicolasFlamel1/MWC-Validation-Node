// Header files
#include "./common.h"
#include "./node.h"

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
		
		// Set threads
		const list threads = {
		
			// Node thread
			&node.getThread()
		};
		
		// Go through all threads
		for(thread *currentThread : threads) {
		
			// Check if current thread is running
			if(currentThread->joinable()) {
			
				// Wait for current thread to finish
				currentThread->join();
			}
		}
		
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
