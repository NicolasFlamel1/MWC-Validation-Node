// Header files
#include "./common.h"
#include <climits>
#include <cstring>
#include <fcntl.h>
#include <functional>
#include <unistd.h>
#include <variant>
#include "./consensus.h"
#include "./message.h"
#include "./peer.h"
#include "./saturate_math.h"

// Check if not Windows
#ifndef _WIN32

	// Header files
	#include <poll.h>
#endif

using namespace std;


// Namespace
using namespace MwcValidationNode;


// Constants

// Communication state
enum class Peer::CommunicationState {

	// Hand sent
	HAND_SENT,
	
	// Peer addresses requested
	PEER_ADDRESSES_REQUESTED,
	
	// Peer addresses received
	PEER_ADDRESSES_RECEIVED
};

// Connect timeout
const int Peer::CONNECT_TIMEOUT = 10 * Common::MILLISECONDS_IN_A_SECOND;

// Read timeout
const chrono::seconds Peer::READ_TIMEOUT = 90s;

// Write timeout
const chrono::seconds Peer::WRITE_TIMEOUT = 90s;

// Linger timeout
const decltype(linger::l_linger) Peer::LINGER_TIMEOUT = 5;

// Read and write poll timeout
const int Peer::READ_AND_WRITE_POLL_TIMEOUT = 100;

// Closing write timeout
const decltype(timeval::tv_sec) Peer::CLOSING_WRITE_TIMEOUT = 5;

// Connecting read timeout
const decltype(timeval::tv_sec) Peer::CONNECTING_READ_TIMEOUT = 60;

// Connecting write timeout
const decltype(timeval::tv_sec) Peer::CONNECTING_WRITE_TIMEOUT = 30;

// Peer addresses received required duration
const chrono::minutes Peer::PEER_ADDRESSES_RECEIVED_REQUIRED_DURATION = 2min;

// Get peer addresses interval
const chrono::minutes Peer::GET_PEER_ADDRESSES_INTERVAL = 10min;

// Ping interval
const chrono::seconds Peer::PING_INTERVAL = 10s;

// Communication required timeout
const chrono::minutes Peer::COMMUNICATION_REQUIRED_TIMEOUT = 3min;

// Sync stuck duration
const chrono::hours Peer::SYNC_STUCK_DURATION = 2h;

// Check number of messages interval
const chrono::minutes Peer::CHECK_NUMBER_OF_MESSAGES_INTERVAL = 1min;

// Maximum number of messages sent per interval
const int Peer::MAXIMUM_NUMBER_OF_MESSAGES_SENT_PER_INTERVAL = 500;

// Maximum number of messages received per interval
const int Peer::MAXIMUM_NUMBER_OF_MESSAGES_RECEIVED_PER_INTERVAL = 500;

// Reserved number of messages per interval
const int Peer::RESERVED_NUMBER_OF_MESSAGES_PER_INTERVAL = 20;

// Short block hash length
const size_t Peer::SHORT_BLOCK_HASH_LENGTH = 6;

// Get headers response required duration
const chrono::minutes Peer::GET_HEADERS_RESPONSE_REQUIRED_DURATION = 2min;

// Get transaction hash set response required duration
const chrono::minutes Peer::GET_TRANSACTION_HASH_SET_RESPONSE_REQUIRED_DURATION = 2min;

// Get transaction hash set attachment required duration
const chrono::minutes Peer::GET_TRANSACTION_HASH_SET_ATTACHMENT_REQUIRED_DURATION = 60min;

// Get block response required duration
const chrono::minutes Peer::GET_BLOCK_RESPONSE_REQUIRED_DURATION = 2min;

// Maximum allowed number of reorgs during headers sync
const int Peer::MAXIMUM_ALLOWED_NUMBER_OF_REORGS_DURING_HEADERS_SYNC = 3;

// Maximum allowed number of reorgs during block sync
const int Peer::MAXIMUM_ALLOWED_NUMBER_OF_REORGS_DURING_BLOCK_SYNC = 2;

// Before disconnect delay duration
const chrono::milliseconds Peer::BEFORE_DISCONNECT_DELAY_DURATION = 1ms;


// Supporting function implementation

// Constructor
Peer::Peer(const string &address, Node &node, condition_variable &eventOccurred, const mt19937_64::result_type randomSeed) :

	// Set stop read and write to false
	stopReadAndWrite(false),
	
	// Set connection state to connecting
	connectionState(ConnectionState::CONNECTING),
	
	// Set syncing state to not syncing
	syncingState(SyncingState::NOT_SYNCING),
	
	// Set communication state to hand sent
	communicationState(CommunicationState::HAND_SENT),
	
	// Check if Windows
	#ifdef _WIN32
	
		// Set socket to invalid
		socket(INVALID_SOCKET),
	
	// Otherwise
	#else
	
		// Set socket to invalid
		socket(-1),
	#endif
	
	// Set node to node
	node(node),
	
	// Set event occurred to event occurred
	eventOccurred(eventOccurred),
	
	// Set total difficulty to the genesis block's difficulty
	totalDifficulty(Consensus::GENESIS_BLOCK_HEADER.getTotalDifficulty()),
	
	// Set number of messages sent to zero
	numberOfMessagesSent(0),
	
	// Set number of messages received to zero
	numberOfMessagesReceived(0),
	
	// Create random number generator using the random seed
	randomNumberGenerator(randomSeed),
	
	// Set nonce to a random value
	nonce(randomNumberGenerator()),
	
	// Create main thread
	mainThread(&Peer::connect, this, address)
{
}

// Destructor
Peer::~Peer() {

	// Set stop read and write to true
	stopReadAndWrite.store(true);
	
	// Set error occurred to false
	bool errorOccurred = false;
	
	// Check if main thread is running
	if(mainThread.joinable()) {
	
		// Try
		try {
	
			// Wait for main thread to finish
			mainThread.join();
		}
	
		// Catch errors
		catch(...) {
		
			// Set error occurred to true
			errorOccurred = true;
		
			// Set closing
			Common::setClosing();
			
			// Notify peers that event occurred
			eventOccurred.notify_one();
		}
	}
	
	// Check if Windows
	#ifdef _WIN32
	
		// Check if socket isn't invalid
		if(socket != INVALID_SOCKET) {
	
	// Otherwise
	#else
	
		// Check if socket isn't invalid
		if(socket != -1) {
	#endif
	
		// Set closed to false
		bool closed = false;
	
		// Check if not stopping read and write and not closing
		if(!stopReadAndWrite.load() && !Common::isClosing()) {
		
			// Try
			try {
			
				// Create thread and detach it
				thread([](const int socket) {
				
					// Check if Windows
					#ifdef _WIN32
					
						{
					
					// Otherwise
					#else
				
						// Check if getting the socket's flags was successful
						const int socketFlags = fcntl(socket, F_GETFL);
						
						if(socketFlags != -1) {
					#endif
					
						// Check if Windows
						#ifdef _WIN32
					
							// Check if setting the socket as blocking was successful
							u_long nonBlocking = false;
							if(!ioctlsocket(socket, FIONBIO, &nonBlocking)) {
						
						// Otherwise
						#else
				
							// Check if setting the socket as blocking was successful
							if(fcntl(socket, F_SETFL, socketFlags & ~O_NONBLOCK) != -1) {
						#endif
						
							// Set linger timeout
							const linger lingerTimeout = {
							
								// On
								.l_onoff = true,
								
								// Timeout
								.l_linger = LINGER_TIMEOUT
							};
							
							// Set socket's linger timeout
							setsockopt(socket, SOL_SOCKET, SO_LINGER, reinterpret_cast<const char *>(&lingerTimeout), sizeof(lingerTimeout));
						}
					}
					
					// Check if Windows
					#ifdef _WIN32
					
						// Shutdown socket receive
						shutdown(socket, SD_RECEIVE);
						
						// Close socket
						closesocket(socket);
						
					// Otherwise
					#else
					
						// Shutdown socket receive
						shutdown(socket, SHUT_RD);
						
						// Close socket
						close(socket);
					#endif
				
				}, socket).detach();
				
				// Check if Windows
				#ifdef _WIN32
				
					// Set socket to invalid
					socket = INVALID_SOCKET;
				
				// Otherwise
				#else
				
					// Set socket to invalid
					socket = -1;
				#endif
				
				// Set closed to true
				closed = true;
			}
			
			// Catch errors
			catch(...) {
			
			}
		}
		
		// Check if socket wasn't closed
		if(!closed) {
		
			// Check if an error didn't occur
			if(!errorOccurred) {
			
				// Check if Windows
				#ifdef _WIN32
				
					{
				
				// Otherwise
				#else
			
					// Check if getting the socket's flags was successful
					const int socketFlags = fcntl(socket, F_GETFL);
					
					if(socketFlags != -1) {
				#endif
			
					// Check if Windows
					#ifdef _WIN32
				
						// Check if setting the socket as blocking was successful
						u_long nonBlocking = false;
						if(!ioctlsocket(socket, FIONBIO, &nonBlocking)) {
					
					// Otherwise
					#else
			
						// Check if setting the socket as blocking was successful
						if(fcntl(socket, F_SETFL, socketFlags & ~O_NONBLOCK) != -1) {
					#endif
					
						// Check if write buffer isn't empty
						if(!writeBuffer.empty()) {
						
							// Check if Windows
							#ifdef _WIN32
							
								// Set write timeout
								const DWORD writeTimeout = CLOSING_WRITE_TIMEOUT * Common::MILLISECONDS_IN_A_SECOND;
							
							// Otherwise
							#else
						
								// Set write timeout
								const timeval writeTimeout = {
								
									// Seconds
									.tv_sec = CLOSING_WRITE_TIMEOUT
								};
							#endif
						
							// Check if setting socket's write timeout was successful
							if(!setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char *>(&writeTimeout), sizeof(writeTimeout))) {
						
								// Loop through all bytes to send
								decltype(function(send))::result_type bytesSent;
								do {
								
									// Check if Windows
									#ifdef _WIN32
								
										// Get bytes sent to socket
										bytesSent = send(socket, reinterpret_cast<char *>(writeBuffer.data()), writeBuffer.size(), 0);
									
									// Otherwise
									#else
									
										// Get bytes sent to socket
										bytesSent = send(socket, writeBuffer.data(), writeBuffer.size(), MSG_NOSIGNAL);
									#endif
									
									// Check if bytes were sent
									if(bytesSent > 0) {
									
										// Remove bytes from write buffer
										writeBuffer.erase(writeBuffer.cbegin(), writeBuffer.cbegin() + bytesSent);
									}
									
								} while(bytesSent > 0 && !writeBuffer.empty());
							}
						}
					
						// Set linger timeout
						const linger lingerTimeout = {
						
							// On
							.l_onoff = true,
							
							// Timeout
							.l_linger = LINGER_TIMEOUT
						};
						
						// Set socket's linger timeout
						setsockopt(socket, SOL_SOCKET, SO_LINGER, reinterpret_cast<const char *>(&lingerTimeout), sizeof(lingerTimeout));
					}
				}
			}
			
			// Check if Windows
			#ifdef _WIN32
			
				// Shutdown socket receive
				shutdown(socket, SD_RECEIVE);
				
				// Close socket
				closesocket(socket);
				
				// Set socket to invalid
				socket = INVALID_SOCKET;
				
			// Otherwise
			#else
			
				// Shutdown socket receive
				shutdown(socket, SHUT_RD);
				
				// Close socket
				close(socket);
				
				// Set socket to invalid
				socket = -1;
			#endif
		}
	}
	
	// Check if shake was received
	if(communicationState > CommunicationState::HAND_SENT) {
	
		// Try
		try {
		
			// Lock node for writing
			lock_guard nodeWriteLock(node.getLock());
			
			// Check if self is healthy
			if(node.isPeerHealthy(identifier)) {
			
				// Add self to node's healthy peer
				node.addHealthyPeer(identifier, capabilities);
			}
		}
		
		// Catch errors
		catch(...) {
		
		}
	}
}

// Stop
void Peer::stop() {

	// Set stop read and write to true
	stopReadAndWrite.store(true);
}

// Get thread
thread &Peer::getThread() {

	// Return main thread
	return mainThread;
}

// Get lock
shared_mutex &Peer::getLock() {

	// Return lock
	return lock;
}

// Get connection state
Peer::ConnectionState Peer::getConnectionState() const {

	// Return connection state
	return connectionState;
}

// Get syncing state
Peer::SyncingState Peer::getSyncingState() const {

	// Return syncing state
	return syncingState;
}

// Get identifier
const string &Peer::getIdentifier() const {

	// Return idenfier
	return identifier;
}

// Get total difficulty
uint64_t Peer::getTotalDifficulty() const {

	// Return total difficulty
	return totalDifficulty;
}

// Get protocol version
uint32_t Peer::getProtocolVersion() const {

	// Return protocol version
	return protocolVersion;
}

// Get base fee
uint64_t Peer::getBaseFee() const {

	// Return base fee
	return baseFee;
}

// Is message queue full
bool Peer::isMessageQueueFull() const {

	// Return if messages can't be sent and received
	return numberOfMessagesReceived >= MAXIMUM_NUMBER_OF_MESSAGES_RECEIVED_PER_INTERVAL / 2 - RESERVED_NUMBER_OF_MESSAGES_PER_INTERVAL || numberOfMessagesSent >= MAXIMUM_NUMBER_OF_MESSAGES_SENT_PER_INTERVAL / 2 - RESERVED_NUMBER_OF_MESSAGES_PER_INTERVAL;
}

// Start syncing
void Peer::startSyncing(const MerkleMountainRange<Header> &headers, const uint64_t syncedHeaderIndex) {

	// Set use node headers to true
	useNodeHeaders = true;
	
	// Set synced header index to synced header index
	this->syncedHeaderIndex = syncedHeaderIndex;
	
	// Set number of reorgs during headers sync to zero
	numberOfReorgsDuringHeadersSync = 0;
	
	// Set number of reorgs during block sync to zero
	numberOfReorgsDuringBlockSync = 0;
	
	// Check if next header is known
	if(headers.getLeaf(syncedHeaderIndex + 1)) {
	
		// Set syncing state to requesting block
		syncingState = SyncingState::REQUESTING_BLOCK;
	}
	
	// Otherwise
	else {
	
		// Set syncing state to requesting headers
		syncingState = SyncingState::REQUESTING_HEADERS;
	}
}

// Get headers
MerkleMountainRange<Header> &Peer::getHeaders() {

	// Return headers
	return headers;
}

// Is worker operation running
bool Peer::isWorkerOperationRunning() const {

	// Return if worker operation exists
	return workerOperation.valid();
}

// Send message
void Peer::sendMessage(const vector<uint8_t> &message) {

	// Append message to write buffer
	writeBuffer.insert(writeBuffer.cend(), message.cbegin(), message.cend());
	
	// Check if not at the max number of messages sent
	if(numberOfMessagesSent != INT_MAX) {
	
		// Increment number of messages sent
		++numberOfMessagesSent;
	}
}

// Connect
void Peer::connect(const string &address) {

	// Try
	try {
	
		// Set if address is an Onion service
		const bool isOnionService = address.size() > sizeof(".onion") - sizeof('\0') && address.ends_with(".onion");
		
		// Initialize current address and port
		string currentAddress;
		const char *port = nullptr;
		
		// Check if is Onion service
		if(isOnionService) {
		
			// Check if Tor is enabled
			#ifdef TOR_ENABLE
			
				// Set current address to the address
				currentAddress = address;
			
			// Otherwise
			#else
			
				// Delay
				this_thread::sleep_for(BEFORE_DISCONNECT_DELAY_DURATION);
				
				{
					// Lock for writing
					lock_guard writeLock(lock);
				
					// Set connection state to disconnected
					connectionState = ConnectionState::DISCONNECTED;
				}
				
				// Check if address isn't a DNS seed
				if(!node.getDnsSeeds().contains(address)) {
				
					// Notify peers that event occurred
					eventOccurred.notify_one();
				}
				
				// Return
				return;
			#endif
		}
		
		// Otherwise
		else {
		
			// Get address's port offset
			const string::size_type portOffset = address.rfind(':');
			
			// Set current address to the address without the port
			currentAddress = address.substr(0, portOffset);
			
			// Check if current address is enclosed in brackets
			if(currentAddress.front() == '[' && currentAddress.back() == ']') {
			
				// Remove enclosing brackets from current address
				currentAddress = currentAddress.substr(sizeof('['), currentAddress.size() - sizeof('[') - sizeof(']'));
			}
			
			// Set port to address's port
			port = &address[portOffset + sizeof(':')];
		}
		
		// Set hints
		const addrinfo hints = {
		
			// Port provided
			.ai_flags = AI_NUMERICSERV,
		
			// IPv4 or IPv6
			.ai_family = AF_UNSPEC,
			
			// TCP
			.ai_socktype = SOCK_STREAM,
		};
		
		// Initialize address info
		addrinfo *addressInfo;
		
		// Check if Tor is enabled
		#ifdef TOR_ENABLE
		
			// Check if getting address info for the node's Tor proxy failed
			if(getaddrinfo(node.getTorProxyAddress().c_str(), node.getTorProxyPort().c_str(), &hints, &addressInfo)) {
		
		// Otherwise
		#else
		
			// Check if getting address info for the current address failed
			if(getaddrinfo(currentAddress.c_str(), port, &hints, &addressInfo)) {
		#endif
		
			// Delay
			this_thread::sleep_for(BEFORE_DISCONNECT_DELAY_DURATION);
			
			{
				// Lock for writing
				lock_guard writeLock(lock);
			
				// Set connection state to disconnected
				connectionState = ConnectionState::DISCONNECTED;
			}
			
			// Check if address isn't a DNS seed
			if(!node.getDnsSeeds().contains(address)) {
			
				// Notify peers that event occurred
				eventOccurred.notify_one();
			}
		}
		
		// Otherwise
		else {
		
			// Automatically free address info when done
			const unique_ptr<addrinfo, decltype(&freeaddrinfo)> addressInfoUniquePointer(addressInfo, freeaddrinfo);
			
			// Initialize banned to false;
			bool banned = false;
			
			// Set recently attempted to false
			bool recentlyAttempted = false;
			
			// Set currently used to false
			bool currentlyUsed = false;
			
			// Dont retry
			bool dontRetry = false;
			
			// Set peer connected to false
			bool peerConnected = false;
			
			// Initialize server address
			NetworkAddress serverAddress;
			
			// Initialize client address
			NetworkAddress clientAddress;
			
			// Initialize client Onion Service address
			string clientOnionServiceAddress;
			
			// Set loopback address
			const in_addr inaddr_loopback = {
			
				// Check if Windows
				#ifdef _WIN32
				
					// Union
					.S_un = {
					
						// Address
						.S_addr = htonl(INADDR_LOOPBACK)
					}
				
				// Otherwise
				#else
			
					// Address
					.s_addr = htonl(INADDR_LOOPBACK)
				#endif
			};
			
			// Check if Tor is enabled
			#ifdef TOR_ENABLE
			
				// Initialize current server
				sockaddr_storage currentServer;
			#endif
			
			// Go through all servers for the address while not stopping read and write and not closing
			for(const addrinfo *server = addressInfo; server && !stopReadAndWrite.load() && !Common::isClosing(); server = server->ai_next) {
			
				// Initialize server identifier
				string serverIdentifier;
				
				// Check if is an Onion service
				if(isOnionService) {
				
					// Set server identifier to the current address
					serverIdentifier = currentAddress;
					
					// Set server address's family to Onion service
					serverAddress.family = NetworkAddress::Family::ONION_SERVICE;
					
					// Set server address's address to current address
					serverAddress.address = currentAddress.c_str();
					
					// Set server address's address length to the current address length
					serverAddress.addressLength = currentAddress.size();
				}
				
				// Otherwise
				else {
				
					// Check if Tor is disabled
					#ifndef TOR_ENABLE
			
						// Check server family
						switch(server->ai_family) {
						
							// IPv4
							case AF_INET:
							
								{
									// Get IPv4 info for the server
									const sockaddr_in *ipv4Info = reinterpret_cast<sockaddr_in *>(server->ai_addr);
									
									// Set server address's family to IPv4
									serverAddress.family = NetworkAddress::Family::IPV4;
									
									// Set server address's address to the address
									serverAddress.address = &ipv4Info->sin_addr;
									
									// Set server address's address length to the address length
									serverAddress.addressLength = sizeof(ipv4Info->sin_addr);
									
									// Set server address's port to the port
									serverAddress.port = ipv4Info->sin_port;
									
									// Check if getting the server's IP string was successful
									char ipString[INET_ADDRSTRLEN];
									
									if(inet_ntop(AF_INET, &ipv4Info->sin_addr, ipString, sizeof(ipString))) {
									
										// Set server identifier to the IP string with the port
										serverIdentifier = string(ipString) + ':' + port;
									}
								}
							
								// Break
								break;
							
							// IPv6
							case AF_INET6:
							
								{
									// Get IPv6 info for the server
									const sockaddr_in6 *ipv6Info = reinterpret_cast<sockaddr_in6 *>(server->ai_addr);
									
									// Set server address's family to IPv6
									serverAddress.family = NetworkAddress::Family::IPV6;
									
									// Set server address's address to the address
									serverAddress.address = &ipv6Info->sin6_addr;
									
									// Set server address's address length to the address length
									serverAddress.addressLength = sizeof(ipv6Info->sin6_addr);
									
									// Set server address's port to the port
									serverAddress.port = ipv6Info->sin6_port;
									
									// Check if getting the server's IP string was successful
									char ipString[INET6_ADDRSTRLEN];
									
									if(inet_ntop(AF_INET6, &ipv6Info->sin6_addr, ipString, sizeof(ipString))) {
									
										// Set server identifier to the IP string with the port
										serverIdentifier = '[' + string(ipString) + "]:" + port;
									}
								}
							
								// Break
								break;
						}
					#endif
				}
				
				// Check if getting server identifier was successful
				if(!serverIdentifier.empty()) {
				
					{
						// Lock node for reading
						shared_lock nodeReadLock(node.getLock());
						
						// Check if server is banned
						if(node.isPeerBanned(serverIdentifier)) {
						
							// Unlock node read lock
							nodeReadLock.unlock();
							
							// Set banned to true
							banned = true;
						
							// Go to next server
							continue;
						}
					}
				
					{
					
						// Lock node for writing
						unique_lock nodeWriteLock(node.getLock());
						
						// Check if server was recently connected
						if(node.isPeerCandidateRecentlyAttempted(serverIdentifier)) {
						
							// Unlock node write lock
							nodeWriteLock.unlock();
						
							// Set recently attempted to true
							recentlyAttempted = true;
						
							// Go to next server
							continue;
						}
						
						// Check if server is currently used
						if(node.getCurrentlyUsedPeerCandidates().contains(serverIdentifier)) {
						
							// Unlock node write lock
							nodeWriteLock.unlock();
						
							// Set currently used to true
							currentlyUsed = true;
						
							// Go to next server
							continue;
						}
						
						// Add server to node's recently attempted peer candidates
						node.addRecentlyAttemptedPeerCandidate(serverIdentifier);
						
						// Add server to the node's list of currently used peer candidates
						node.getCurrentlyUsedPeerCandidates().insert(serverIdentifier);
					}
					
					// Set identifier to server identifier
					identifier = move(serverIdentifier);
				}
				
				// Otherwise
				else {
				
					// Check if Tor is disabled
					#ifndef TOR_ENABLE
					
						// Check if no more servers exist
						if(!server->ai_next) {
						
							// Set don't retry to true
							dontRetry = true;
						}
						
						// Go to next server
						continue;
					#endif
				}
					
				// Create socket
				socket = ::socket(server->ai_family, server->ai_socktype, server->ai_protocol);
				
				// Check if Windows
				#ifdef _WIN32
				
					// Check if creating socket was successful
					if(socket != INVALID_SOCKET) {
				
				// Otherwise
				#else
				
					// Check if creating socket was successful
					if(socket != -1) {
				#endif
					
					// Check if Windows
					#ifdef _WIN32
					
						{
					
					// Otherwise
					#else
				
						// Check if getting the socket's flags was successful
						int socketFlags = fcntl(socket, F_GETFL);
						
						if(socketFlags != -1) {
					#endif
					
						// Check if Windows
						#ifdef _WIN32
					
							// Check if setting the socket as non-blocking was successful
							u_long nonBlocking = true;
							if(!ioctlsocket(socket, FIONBIO, &nonBlocking)) {
						
						// Otherwise
						#else
				
							// Check if setting the socket as non-blocking was successful
							if(fcntl(socket, F_SETFL, socketFlags | O_NONBLOCK) != -1) {
						#endif
						
							// Set connected to false
							bool connected = false;
						
							// Connect to server
							int connectStatus = ::connect(socket, server->ai_addr, server->ai_addrlen);
							
							// Check if Windows
							#ifdef _WIN32
							
								// Check if connecting to server was successful started
								if(connectStatus == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) {
							
							// Otherwise
							#else
							
								// Check if connecting to server was successful started
								if(connectStatus == -1 && errno == EINPROGRESS) {
							#endif
							
								// Check if Windows
								#ifdef _WIN32
								
									// Set sockets to monitor socket
									WSAPOLLFD sockets = {
									
										// Socket
										.fd = socket,
										
										// Events
										.events = POLLOUT
									};
									
									// Check if connecting to the server successfully finished
									if(WSAPoll(&sockets, 1, CONNECT_TIMEOUT) > 0) {
								
								// Otherwise
								#else
								
									// Set sockets to monitor socket
									pollfd sockets = {
									
										// Socket
										.fd = socket,
										
										// Events
										.events = POLLOUT
									};
									
									// Check if connecting to the server successfully finished
									if(poll(&sockets, 1, CONNECT_TIMEOUT) > 0) {
								#endif
								
									// Check if not stopping read and write and not closing
									if(!stopReadAndWrite.load() && !Common::isClosing()) {
								
										// Set connected to true
										connected = true;
									}
								}
							}
							
							// Otherwise check if connection was finished
							else if(!connectStatus) {
							
								// Set connected to true
								connected = true;
							}
							
							// Check if connected
							if(connected) {
							
								// Check if getting socket's error status was successful
								int errorStatus;
								socklen_t errorStatusLength = sizeof(errorStatus);
								
								if(!getsockopt(socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&errorStatus), &errorStatusLength)) {
								
									// Check if socket doesn't have any errors
									if(!errorStatus) {
									
										// Set invalid server to false
										bool invalidServer = false;
									
										// Check if Tor is enabled
										#ifdef TOR_ENABLE
										
											// Check if Windows
											#ifdef _WIN32
										
												// Check if setting the socket as blocking failed
												nonBlocking = false;
												if(ioctlsocket(socket, FIONBIO, &nonBlocking)) {
											
											// Otherwise
											#else
									
												// Check if setting the socket as blocking failed
												if(fcntl(socket, F_SETFL, socketFlags & ~O_NONBLOCK) == -1) {
											#endif
											
												// Set invalid server
												invalidServer = true;
											}
											
											// Otherwise
											else {
											
												// Check if Windows
												#ifdef _WIN32
													
													// Set read timeout
													const DWORD readTimeout = CONNECTING_READ_TIMEOUT * Common::MILLISECONDS_IN_A_SECOND;
												
													// Set write timeout
													const DWORD writeTimeout = CONNECTING_WRITE_TIMEOUT * Common::MILLISECONDS_IN_A_SECOND;
												
												// Otherwise
												#else
												
													// Set read timeout
													const timeval readTimeout = {
													
														// Seconds
														.tv_sec = CONNECTING_READ_TIMEOUT
													};
											
													// Set write timeout
													const timeval writeTimeout = {
													
														// Seconds
														.tv_sec = CONNECTING_WRITE_TIMEOUT
													};
												#endif
											
												// Check if setting socket's read and write timeouts failed
												if(setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char *>(&readTimeout), sizeof(readTimeout)) || setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char *>(&writeTimeout), sizeof(writeTimeout))) {
												
													// Set invalid server
													invalidServer = true;
												}
												
												// Otherwise
												else {
											
													// Set authenticate request
													const uint8_t authenticateRequest[] = {0x05, 0x01, 0x00};
													
													// Check if Windows
													#ifdef _WIN32
													
														// Check if sending authenticate request failed
														if(send(socket, reinterpret_cast<const char *>(authenticateRequest), sizeof(authenticateRequest), 0) != sizeof(authenticateRequest)) {
													
													// Otherwise
													#else
													
														// Check if sending authenticate request failed
														if(send(socket, authenticateRequest, sizeof(authenticateRequest), MSG_NOSIGNAL) != sizeof(authenticateRequest)) {
													#endif
													
														// Check if no more servers exist
														if(!server->ai_next) {
														
															// Set retry to true
															dontRetry = true;
														}
														
														// Set invalid server
														invalidServer = true;
													}
													
													// Otherwise check if stopping read and write or closing
													else if(stopReadAndWrite.load() || Common::isClosing()) {
													
														// Set invalid server
														invalidServer = true;
													}
													
													// Otherwise
													else {
													
														// Initialize authenticate response
														uint8_t authenticateResponse[sizeof("\x05\x00") - sizeof('\0')];
														
														// Check if getting authenticate response failed
														if(recv(socket, reinterpret_cast<char *>(authenticateResponse), sizeof(authenticateResponse), 0) != sizeof(authenticateResponse)) {
														
															// Check if no more servers exist
															if(!server->ai_next) {
															
																// Set retry to true
																dontRetry = true;
															}
															
															// Set invalid server
															invalidServer = true;
														}
														
														// Otherwise check if stopping read and write or closing
														else if(stopReadAndWrite.load() || Common::isClosing()) {
														
															// Set invalid server
															invalidServer = true;
														}
														
														// Otherwise check if not authenticated
														else if(authenticateResponse[1]) {
														
															// Check if no more servers exist
															if(!server->ai_next) {
															
																// Set retry to true
																dontRetry = true;
															}
															
															// Set invalid server
															invalidServer = true;
														}
														
														// Otherwise check if current address length is too big
														else if(currentAddress.size() > UINT8_MAX) {
														
															// Check if no more servers exist
															if(!server->ai_next) {
															
																// Set retry to true
																dontRetry = true;
															}
															
															// Set invalid server
															invalidServer = true;
														}
														
														// Otherwise
														else {
														
															// Initialize port as number
															decltype(sockaddr_in::sin_port) portAsNumber;
														
															// Check if is Onion service
															if(isOnionService) {
															
																// Set port as number to HTTP port
																portAsNumber = htons(Common::HTTP_PORT);
															}
															
															// Otherwise
															else {
															
																// Set port as number to the port
																portAsNumber = htons(atoi(port));
															}
															
															// Initialize resolve request
															uint8_t resolveRequest[sizeof("\x05\xF0\x00\x03") - sizeof('\0') + sizeof(uint8_t) + currentAddress.size() + sizeof(portAsNumber)];
															
															// Set resolve request's header
															memcpy(resolveRequest, "\x05\xF0\x00\x03", sizeof("\x05\xF0\x00\x03") - sizeof('\0'));
															
															// Set resolve request's address length to the current address length
															resolveRequest[sizeof("\x05\xF0\x00\x03") - sizeof('\0')] = currentAddress.size();
															
															// Set resolve request's address to the current address
															memcpy(&resolveRequest[sizeof("\x05\xF0\x00\x03") - sizeof('\0') + sizeof(uint8_t)], currentAddress.c_str(), currentAddress.size());
															
															// Set resolve request's port
															memcpy(&resolveRequest[sizeof("\x05\xF0\x00\x03") - sizeof('\0') + sizeof(uint8_t) + currentAddress.size()], &portAsNumber, sizeof(portAsNumber));
															
															// Check if not an Onion service
															if(!isOnionService) {
															
																// Check if Windows
																#ifdef _WIN32
																
																	// Check if sending resolve request failed
																	if(send(socket, reinterpret_cast<char *>(resolveRequest), sizeof(resolveRequest), 0) != static_cast<decltype(function(send))::result_type>(sizeof(resolveRequest))) {
																
																// Otherwise
																#else
																
																	// Check if sending resolve request failed
																	if(send(socket, resolveRequest, sizeof(resolveRequest), MSG_NOSIGNAL) != static_cast<decltype(function(send))::result_type>(sizeof(resolveRequest))) {
																#endif
																
																	// Check if no more servers exist
																	if(!server->ai_next) {
																	
																		// Set retry to true
																		dontRetry = true;
																	}
																	
																	// Set invalid server
																	invalidServer = true;
																}
																
																// Otherwise check if stopping read and write or closing
																else if(stopReadAndWrite.load() || Common::isClosing()) {
																
																	// Set invalid server
																	invalidServer = true;
																}
																
																// Otherwise
																else {
																
																	// Initialize resolve response
																	uint8_t resolveResponse[sizeof("\x05\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00") - sizeof('\0')];
																	
																	// Check if getting resolve response failed
																	const decltype(function(recv))::result_type resolveResponseSize = recv(socket, reinterpret_cast<char *>(resolveResponse), sizeof(resolveResponse), 0);
																	if(resolveResponseSize != sizeof("\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00") - sizeof('\0') && resolveResponseSize != sizeof(resolveResponse)) {
																	
																		// Check if no more servers exist
																		if(!server->ai_next) {
																		
																			// Set retry to true
																			dontRetry = true;
																		}
																		
																		// Set invalid server
																		invalidServer = true;
																	}
																	
																	// Otherwise check if stopping read and write or closing
																	else if(stopReadAndWrite.load() || Common::isClosing()) {
																	
																		// Set invalid server
																		invalidServer = true;
																	}
																	
																	// Otherwise check if not resolved
																	else if(resolveResponse[1]) {
																	
																		// Check if no more servers exist
																		if(!server->ai_next) {
																		
																			// Set retry to true
																			dontRetry = true;
																		}
																		
																		// Set invalid server
																		invalidServer = true;
																	}
																	
																	// Otherwise
																	else {
																		
																		// Check resolve response's address type
																		switch(resolveResponse[3]) {
																		
																			// IPv4
																			case 0x01:
																			
																				// Check if resolve response is valid
																				if(resolveResponseSize == sizeof("\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00") - sizeof('\0')) {
																				
																					// Get IPv4 info for the current server
																					sockaddr_in *ipv4Info = reinterpret_cast<sockaddr_in *>(&currentServer);
																					memcpy(&ipv4Info->sin_addr, &resolveResponse[4], sizeof(ipv4Info->sin_addr));
																					ipv4Info->sin_port = portAsNumber;
																					
																					// Set server address's family to IPv4
																					serverAddress.family = NetworkAddress::Family::IPV4;
																					
																					// Set server address's address to the address
																					serverAddress.address = &ipv4Info->sin_addr;
																					
																					// Set server address's address length to the address length
																					serverAddress.addressLength = sizeof(ipv4Info->sin_addr);
																					
																					// Set server address's port to the port
																					serverAddress.port = ipv4Info->sin_port;
																					
																					// Check if getting the current server's IP string was successful
																					char ipString[INET_ADDRSTRLEN];
																					
																					if(inet_ntop(AF_INET, &ipv4Info->sin_addr, ipString, sizeof(ipString))) {
																					
																						// Set server identifier to the IP string with the port
																						serverIdentifier = string(ipString) + ':' + to_string(ntohs(ipv4Info->sin_port));
																					}
																				}
																				
																				// Break
																				break;
																			
																			// IPv6
																			case 0x04:
																			
																				// Check if resolve response is valid
																				if(resolveResponseSize == sizeof(resolveResponse)) {
																				
																					// Get IPv6 info for the server
																					sockaddr_in6 *ipv6Info = reinterpret_cast<sockaddr_in6 *>(&currentServer);
																					memcpy(&ipv6Info->sin6_addr, &resolveResponse[4], sizeof(ipv6Info->sin6_addr));
																					ipv6Info->sin6_port = portAsNumber;
																					
																					// Set server address's family to IPv6
																					serverAddress.family = NetworkAddress::Family::IPV6;
																					
																					// Set server address's address to the address
																					serverAddress.address = &ipv6Info->sin6_addr;
																					
																					// Set server address's address length to the address length
																					serverAddress.addressLength = sizeof(ipv6Info->sin6_addr);
																					
																					// Set server address's port to the port
																					serverAddress.port = ipv6Info->sin6_port;
																					
																					// Check if getting the current server's IP string was successful
																					char ipString[INET6_ADDRSTRLEN];
																					
																					if(inet_ntop(AF_INET6, &ipv6Info->sin6_addr, ipString, sizeof(ipString))) {
																					
																						// Set server identifier to the IP string with the port
																						serverIdentifier = '[' + string(ipString) + "]:" + to_string(ntohs(ipv6Info->sin6_port));
																					}
																				}
																				
																				// Break
																				break;
																		}
																		
																		// Check if getting server identifier was successful
																		if(!serverIdentifier.empty()) {
																		
																			{
																				// Lock node for reading
																				shared_lock nodeReadLock(node.getLock());
																				
																				// Check if server is banned
																				if(node.isPeerBanned(serverIdentifier)) {
																				
																					// Unlock node read lock
																					nodeReadLock.unlock();
																					
																					// Set banned to true
																					banned = true;
																				
																					// Set invalid server
																					invalidServer = true;
																				}
																			}
																			
																			// Check if server is valid
																			if(!invalidServer) {
																			
																				{
																				
																					// Lock node for writing
																					unique_lock nodeWriteLock(node.getLock());
																					
																					// Check if server was recently connected
																					if(node.isPeerCandidateRecentlyAttempted(serverIdentifier)) {
																					
																						// Unlock node write lock
																						nodeWriteLock.unlock();
																					
																						// Set recently attempted to true
																						recentlyAttempted = true;
																					
																						// Set invalid server
																						invalidServer = true;
																					}
																					
																					// Otherwise check if server is currently used
																					else if(node.getCurrentlyUsedPeerCandidates().contains(serverIdentifier)) {
																					
																						// Unlock node write lock
																						nodeWriteLock.unlock();
																					
																						// Set currently used to true
																						currentlyUsed = true;
																					
																						// Set invalid server
																						invalidServer = true;
																					}
																					
																					// Otherwise
																					else {
																					
																						// Add server to node's recently attempted peer candidates
																						node.addRecentlyAttemptedPeerCandidate(serverIdentifier);
																						
																						// Add server to the node's list of currently used peer candidates
																						node.getCurrentlyUsedPeerCandidates().insert(serverIdentifier);
																					}
																				}
																				
																				// Check if server is valid
																				if(!invalidServer) {
																				
																					// Set identifier to server identifier
																					identifier = move(serverIdentifier);
																					
																					// Check if Windows
																					#ifdef _WIN32
																					
																						// Shutdown socket receive and send
																						shutdown(socket, SD_BOTH);
																						
																						// Check if closing socket failed
																						if(closesocket(socket)) {
																						
																							// Close socket
																							closesocket(socket);
																							
																							// Set socket to invalid
																							socket = INVALID_SOCKET;
																							
																							// Set invalid server
																							invalidServer = true;
																						}
																						
																						// Otherwise
																						else {
																						
																					// Otherwise
																					#else
																					
																						// Shutdown socket receive and send
																						shutdown(socket, SHUT_RDWR);
																						
																						// Check if closing socket failed
																						if(close(socket)) {
																						
																							// Close socket
																							close(socket);
																							
																							// Set socket to invalid
																							socket = -1;
																							
																							// Set invalid server
																							invalidServer = true;
																						}
																						
																						// Otherwise
																						else {
																					#endif
																						
																						// Create socket
																						socket = ::socket(server->ai_family, server->ai_socktype, server->ai_protocol);
																						
																						// Check if Windows
																						#ifdef _WIN32
																						
																							// Check if creating socket was successful
																							if(socket != INVALID_SOCKET) {
																						
																						// Otherwise
																						#else
																						
																							// Check if creating socket was successful
																							if(socket != -1) {
																						#endif
																							
																							// Check if Windows
																							#ifdef _WIN32
																							
																								// Check if true
																								if(true) {
																							
																							// Otherwise
																							#else
																						
																								// Check if getting the socket's flags was successful
																								socketFlags = fcntl(socket, F_GETFL);
																								
																								if(socketFlags != -1) {
																							#endif
																							
																								// Check if Windows
																								#ifdef _WIN32
																							
																									// Check if setting the socket as non-blocking was successful
																									nonBlocking = true;
																									if(!ioctlsocket(socket, FIONBIO, &nonBlocking)) {
																								
																								// Otherwise
																								#else
																						
																									// Check if setting the socket as non-blocking was successful
																									if(fcntl(socket, F_SETFL, socketFlags | O_NONBLOCK) != -1) {
																								#endif
																								
																									// Set connected to false
																									connected = false;
																								
																									// Connect to server
																									connectStatus = ::connect(socket, server->ai_addr, server->ai_addrlen);
																									
																									// Check if Windows
																									#ifdef _WIN32
																									
																										// Check if connecting to server was successful started
																										if(connectStatus == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) {
																									
																									// Otherwise
																									#else
																									
																										// Check if connecting to server was successful started
																										if(connectStatus == -1 && errno == EINPROGRESS) {
																									#endif
																									
																										// Check if Windows
																										#ifdef _WIN32
																										
																											// Set sockets to monitor socket
																											WSAPOLLFD sockets = {
																											
																												// Socket
																												.fd = socket,
																												
																												// Events
																												.events = POLLOUT
																											};
																											
																											// Check if connecting to the server successfully finished
																											if(WSAPoll(&sockets, 1, CONNECT_TIMEOUT) > 0) {
																										
																										// Otherwise
																										#else
																										
																											// Set sockets to monitor socket
																											pollfd sockets = {
																											
																												// Socket
																												.fd = socket,
																												
																												// Events
																												.events = POLLOUT
																											};
																											
																											// Check if connecting to the server successfully finished
																											if(poll(&sockets, 1, CONNECT_TIMEOUT) > 0) {
																										#endif
																										
																											// Check if not stopping read and write and not closing
																											if(!stopReadAndWrite.load() && !Common::isClosing()) {
																										
																												// Set connected to true
																												connected = true;
																											}
																										}
																									}
																									
																									// Otherwise check if connection was finished
																									else if(!connectStatus) {
																									
																										// Set connected to true
																										connected = true;
																									}
																									
																									// Check if connected
																									if(connected) {
																									
																										// Check if getting socket's error status was successful
																										errorStatusLength = sizeof(errorStatus);
																										if(!getsockopt(socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&errorStatus), &errorStatusLength)) {
																										
																											// Check if socket doesn't have any errors
																											if(!errorStatus) {
																											
																												// Check if Windows
																												#ifdef _WIN32
																											
																													// Check if setting the socket as blocking failed
																													nonBlocking = false;
																													if(ioctlsocket(socket, FIONBIO, &nonBlocking)) {
																												
																												// Otherwise
																												#else
																										
																													// Check if setting the socket as blocking failed
																													if(fcntl(socket, F_SETFL, socketFlags & ~O_NONBLOCK) == -1) {
																												#endif
																												
																													// Set invalid server
																													invalidServer = true;
																												}
																												
																												// Otherwise check if setting socket's read and write timeouts failed
																												else if(setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char *>(&readTimeout), sizeof(readTimeout)) || setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char *>(&writeTimeout), sizeof(writeTimeout))) {
																												
																													// Set invalid server
																													invalidServer = true;
																												}
																												
																												// Check if Windows
																												#ifdef _WIN32
																												
																													// Otherwise check if sending authenticate request failed
																													else if(send(socket, reinterpret_cast<const char *>(authenticateRequest), sizeof(authenticateRequest), 0) != sizeof(authenticateRequest)) {
																												
																												// Otherwise
																												#else
																												
																													// Otherwise check if sending authenticate request failed
																													else if(send(socket, authenticateRequest, sizeof(authenticateRequest), MSG_NOSIGNAL) != sizeof(authenticateRequest)) {
																												#endif
																												
																													// Check if no more servers exist
																													if(!server->ai_next) {
																													
																														// Set retry to true
																														dontRetry = true;
																													}
																													
																													// Set invalid server
																													invalidServer = true;
																												}
																												
																												// Otherwise check if stopping read and write or closing
																												else if(stopReadAndWrite.load() || Common::isClosing()) {
																												
																													// Set invalid server
																													invalidServer = true;
																												}
																												
																												// Otherwise check if getting authenticate response failed
																												else if(recv(socket, reinterpret_cast<char *>(authenticateResponse), sizeof(authenticateResponse), 0) != sizeof(authenticateResponse)) {
																												
																													// Check if no more servers exist
																													if(!server->ai_next) {
																													
																														// Set retry to true
																														dontRetry = true;
																													}
																													
																													// Set invalid server
																													invalidServer = true;
																												}
																												
																												// Otherwise check if stopping read and write or closing
																												else if(stopReadAndWrite.load() || Common::isClosing()) {
																												
																													// Set invalid server
																													invalidServer = true;
																												}
																												
																												// Otherwise check if not authenticated
																												else if(authenticateResponse[1]) {
																												
																													// Check if no more servers exist
																													if(!server->ai_next) {
																													
																														// Set retry to true
																														dontRetry = true;
																													}
																													
																													// Set invalid server
																													invalidServer = true;
																												}
																											}
																											
																											// Otherwise
																											else {
																											
																												// Check if no more servers exist
																												if(!server->ai_next) {
																												
																													// Set retry to true
																													dontRetry = true;
																												}
																												
																												// Set invalid server
																												invalidServer = true;
																											}
																										}
																										
																										// Otherwise
																										else {
																										
																											// Set invalid server
																											invalidServer = true;
																										}
																									}
																									
																									// Otherwise
																									else {
																									
																										// Check if no more servers exist
																										if(!server->ai_next) {
																										
																											// Set retry to true
																											dontRetry = true;
																										}
																										
																										// Set invalid server
																										invalidServer = true;
																									}
																								}
																								
																								// Otherwise
																								else {
																								
																									// Set invalid server
																									invalidServer = true;
																								}
																							}
																							
																							// Otherwise
																							else {
																							
																								// Set invalid server
																								invalidServer = true;
																							}
																						}
																						
																						// Otherwise
																						else {
																						
																							// Set invalid server
																							invalidServer = true;
																						}
																					}
																				}
																			}
																		}
																		
																		// Otherwise
																		else {
																		
																			// Check if no more servers exist
																			if(!server->ai_next) {
																			
																				// Set retry to true
																				dontRetry = true;
																			}
																			
																			// Set invalid server
																			invalidServer = true;
																		}
																	}
																}
															}
															
															// Check if server is valid
															if(!invalidServer) {
															
																// Initialize connect request
																uint8_t *connectRequest = resolveRequest;
																connectRequest[1] = 0x01;
																
																// Check if Windows
																#ifdef _WIN32
																
																	// Check if sending connect request failed
																	if(send(socket, reinterpret_cast<char *>(connectRequest), sizeof(resolveRequest), 0) != static_cast<decltype(function(send))::result_type>(sizeof(resolveRequest))) {
																
																// Otherwise
																#else
																
																	// Check if sending connect request failed
																	if(send(socket, connectRequest, sizeof(resolveRequest), MSG_NOSIGNAL) != static_cast<decltype(function(send))::result_type>(sizeof(resolveRequest))) {
																#endif
																
																	// Check if no more servers exist
																	if(!server->ai_next) {
																	
																		// Set retry to true
																		dontRetry = true;
																	}
																	
																	// Set invalid server
																	invalidServer = true;
																}
																
																// Otherwise check if stopping read and write or closing
																else if(stopReadAndWrite.load() || Common::isClosing()) {
																
																	// Set invalid server
																	invalidServer = true;
																}
																
																// Otherwise
																else {
																
																	// Initialize connect response
																	uint8_t connectResponse[sizeof("\x05\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00") - sizeof('\0')];
																	
																	// Check if getting connect response failed
																	const decltype(function(recv))::result_type connectResponseSize = recv(socket, reinterpret_cast<char *>(connectResponse), sizeof(connectResponse), 0);
																	if(connectResponseSize != sizeof("\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00") - sizeof('\0') && connectResponseSize != sizeof(connectResponse)) {
																	
																		// Check if no more servers exist
																		if(!server->ai_next) {
																		
																			// Set retry to true
																			dontRetry = true;
																		}
																		
																		// Set invalid server
																		invalidServer = true;
																	}
																	
																	// Otherwise check if stopping read and write or closing
																	else if(stopReadAndWrite.load() || Common::isClosing()) {
																	
																		// Set invalid server
																		invalidServer = true;
																	}
																	
																	// Otherwise check if not connected
																	else if(connectResponse[1]) {
																	
																		// Check if no more servers exist
																		if(!server->ai_next) {
																		
																			// Set retry to true
																			dontRetry = true;
																		}
																		
																		// Set invalid server
																		invalidServer = true;
																	}
																	
																	// Otherwise
																	else {
																	
																		// Check if Windows
																		#ifdef _WIN32
																	
																			// Check if setting the socket as non-blocking failed
																			nonBlocking = true;
																			if(ioctlsocket(socket, FIONBIO, &nonBlocking)) {
																		
																		// Otherwise
																		#else
																
																			// Check if setting the socket as non-blocking failed
																			if(fcntl(socket, F_SETFL, socketFlags | O_NONBLOCK) == -1) {
																		#endif
																		
																			// Set invalid server
																			invalidServer = true;
																		}
																	}
																}
															}
														}
													}
												}
											}
										#endif
										
										// Check if server is valid
										if(!invalidServer) {
										
											// Set invalid client to false
											bool invalidClient = false;
											
											// Check if is an Onion service
											if(isOnionService) {
											
												// Clear client service address
												clientOnionServiceAddress.clear();
												
												// TODO Create Tor address with checksum and version
												
												// Go through all characters in a Tor address
												for(int i = 0; i < Common::TOR_ADDRESS_LENGTH; ++i) {
												
													// Append random base32 character to the client Onion service address
													clientOnionServiceAddress += Common::BASE32_CHARACTERS[randomNumberGenerator() % sizeof(Common::BASE32_CHARACTERS)];
												}
												
												// Append .onion top-level domain to the client Onion service address
												clientOnionServiceAddress += ".onion";
												
												// Set client address's family to Onion service
												clientAddress.family = NetworkAddress::Family::ONION_SERVICE;
												
												// Set client address's address to the client Onion service address
												clientAddress.address = clientOnionServiceAddress.c_str();
												
												// Set client address's address length to the client Onion service address length
												clientAddress.addressLength = clientOnionServiceAddress.size();
											}
											
											// Otherwise
											else {
										
												// Check if getting client info was successful
												sockaddr_storage clientInfo;
												socklen_t clientInfoLength = sizeof(clientInfo);
												
												if(!getsockname(socket, reinterpret_cast<sockaddr *>(&clientInfo), &clientInfoLength)) {
												
													// Check client info's family
													switch(clientInfo.ss_family) {
													
														// IPv4
														case AF_INET:
														
															{
																// Get IPv4 info for the client
																const sockaddr_in *ipv4Info = reinterpret_cast<sockaddr_in *>(&clientInfo);
																
																// Set client address's family to IPv4
																clientAddress.family = NetworkAddress::Family::IPV4;
																
																// Set client address's address to loopback address
																clientAddress.address = &inaddr_loopback;
																
																// Set client address's address length to the loopback address length
																clientAddress.addressLength = sizeof(inaddr_loopback);
																
																// Set client address's port to the port
																clientAddress.port = ipv4Info->sin_port;
															}
															
															// Break
															break;
														
														// IPv6
														case AF_INET6:
														
															{
																// Get IPv6 info for the client
																const sockaddr_in6 *ipv6Info = reinterpret_cast<sockaddr_in6 *>(&clientInfo);
																
																// Set client address's family to IPv6
																clientAddress.family = NetworkAddress::Family::IPV6;
																
																// Set client address's address to loopback address
																clientAddress.address = &in6addr_loopback;
																
																// Set client address's address length to the loopback address length
																clientAddress.addressLength = sizeof(in6addr_loopback);
																
																// Set client address's port to the port
																clientAddress.port = ipv6Info->sin6_port;
															}
														
															// Break
															break;
														
														// Default
														default:
														
															// Set invalid client
															invalidClient = true;
														
															// Break
															break;
													}
												}
												
												// Otherwise
												else {
												
													// Set invalid client
													invalidClient = true;
												}
											}
											
											// Check if client is valid
											if(!invalidClient) {
											
												// Let node know that a peer connected
												node.peerConnected(identifier);
											
												// Set peer connected to true
												peerConnected = true;
												
												// Break
												break;
											}
										}
									}
									
									// Otherwise check if no more servers exist
									else if(!server->ai_next) {
									
										// Set retry to true
										dontRetry = true;
									}
								}
							}
							
							// Otherwise check if no more servers exist
							else if(!server->ai_next) {
							
								// Set retry to true
								dontRetry = true;
							}
						}
					}
				
					// Check if Windows
					#ifdef _WIN32
					
						// Check if socket exists
						if(socket != INVALID_SOCKET) {
						
							// Shutdown socket receive and send
							shutdown(socket, SD_BOTH);
							
							// Close socket
							closesocket(socket);
							
							// Set socket to invalid
							socket = INVALID_SOCKET;
						}
						
					// Otherwise
					#else
					
						// Check if socket exists
						if(socket != -1) {
						
							// Shutdown socket receive and send
							shutdown(socket, SHUT_RDWR);
							
							// Close socket
							close(socket);
							
							// Set socket to invalid
							socket = -1;
						}
					#endif
				}
				
				// Check if identifier exists
				if(!identifier.empty()) {
				
					// Try
					try {
					
						// Lock node for writing
						lock_guard nodeWriteLock(node.getLock());
						
						// Remove server to the node's list of currently used peer candidates
						node.getCurrentlyUsedPeerCandidates().erase(identifier);
					}
					
					// Catch errors
					catch(...) {
					
						// Break
						break;
					}
					
					// Clear identifier
					identifier.clear();
				}
			}
			
			// Check if connecting was successful
			if(peerConnected) {
			
				// Try
				try {
				
					// Initialize node's total difficulty
					uint64_t nodesTotalDifficulty;
					
					{
						// Lock node for reading
						shared_lock nodeReadLock(node.getLock());
				
						// Set node's total difficulty to node's total difficulty
						nodesTotalDifficulty = node.getTotalDifficulty();
					}
				
					// Create hand message
					const vector handMessage = Message::createHandMessage(nonce, nodesTotalDifficulty, clientAddress, serverAddress, node.getBaseFee());
					
					// Append hand message to write buffer
					writeBuffer.insert(writeBuffer.cend(), handMessage.cbegin(), handMessage.cend());
					
					// Check if not at the max number of messages sent
					if(numberOfMessagesSent != INT_MAX) {
					
						// Increment number of messages sent
						++numberOfMessagesSent;
					}
					
					{
						// Lock for writing
						lock_guard writeLock(lock);
					
						// Set connection state to connected
						connectionState = ConnectionState::CONNECTED;
					}
				}
				
				// Catch errors
				catch(...) {
				
					// Check if Windows
					#ifdef _WIN32
					
						// Shutdown socket receive and send
						shutdown(socket, SD_BOTH);
						
						// Close socket
						closesocket(socket);
						
						// Set socket to invalid
						socket = INVALID_SOCKET;
						
					// Otherwise
					#else
					
						// Shutdown socket receive and send
						shutdown(socket, SHUT_RDWR);
						
						// Close socket
						close(socket);
						
						// Set socket to invalid
						socket = -1;
					#endif
					
					// Free all memory allocated by the write buffer
					vector<uint8_t>().swap(writeBuffer);
					
					// Delay
					this_thread::sleep_for(BEFORE_DISCONNECT_DELAY_DURATION);
					
					{
						// Lock for writing
						lock_guard writeLock(lock);
						
						// Set connection state to disconnected
						connectionState = ConnectionState::DISCONNECTED;
					}
					
					// Notify peers that event occurred
					eventOccurred.notify_one();
					
					// Return
					return;
				}
				
				// Read and write
				readAndWrite();
				
				// Return
				return;
			}
			
			// Otherwise
			else {
			
				// Delay
				this_thread::sleep_for(BEFORE_DISCONNECT_DELAY_DURATION);
				
				{
					// Lock for writing
					lock_guard writeLock(lock);
				
					// Set connection state to disconnected
					connectionState = ConnectionState::DISCONNECTED;
				}
				
				// Check if address isn't a DNS seed or it's not banned, not recently attempted, not currently used, and can be retried
				if(!node.getDnsSeeds().contains(address) || (!banned && !recentlyAttempted && !currentlyUsed && !dontRetry)) {
				
					// Notify peers that event occurred
					eventOccurred.notify_one();
				}
			}
		}
	}
	
	// Catch errors
	catch(...) {
	
		// Delay
		this_thread::sleep_for(BEFORE_DISCONNECT_DELAY_DURATION);
		
		// Try
		try {
	
			// Lock for writing
			lock_guard writeLock(lock);
		
			// Set connection state to disconnected
			connectionState = ConnectionState::DISCONNECTED;
		}
		
		// Catch errors
		catch(...) {
		
			// Set closing
			Common::setClosing();
		}
		
		// Notify peers that event occurred
		eventOccurred.notify_one();
	}
}

// Read and write
void Peer::readAndWrite() {

	// Try
	try {

		// Set current read done and current write done to true
		bool currentReadDone = true;
		bool currentWriteDone = true;

		// Initialize current read start time and current write start time
		chrono::time_point<chrono::steady_clock> currentReadStartTime;
		chrono::time_point<chrono::steady_clock> currentWriteStartTime;
		
		// Set start read and write time to now
		const chrono::time_point startReadAndWriteTime = chrono::steady_clock::now();
		
		// Set last get peer addresses time to now
		chrono::time_point lastGetPeerAddressesTime = chrono::steady_clock::now();
		
		// Set last ping time to now
		lastPingTime = chrono::steady_clock::now();
		
		// Set last read time to now
		chrono::time_point lastReadTime = chrono::steady_clock::now();
		
		// Set last number of messages check time to now
		chrono::time_point lastNumberOfMessagesCheckTime = chrono::steady_clock::now();
		
		// While not stopping read and write and not closing
		while(!stopReadAndWrite.load() && !Common::isClosing()) {
		
			// Check if peer addresses weren't received
			if(communicationState < CommunicationState::PEER_ADDRESSES_RECEIVED) {
			
				// Check if peer addresses were required by now
				if(chrono::steady_clock::now() - startReadAndWriteTime > PEER_ADDRESSES_RECEIVED_REQUIRED_DURATION) {
				
					{
						// Lock node for writing
						lock_guard nodeWriteLock(node.getLock());
						
						// Add self to node's list of banned peers
						node.addBannedPeer(identifier);
					}
					
					// Disconnect
					disconnect();
					
					// Break
					break;
				}
			}
			
			// Check if time to check number of messages
			if(chrono::steady_clock::now() - lastNumberOfMessagesCheckTime >= CHECK_NUMBER_OF_MESSAGES_INTERVAL) {
			
				// Lock for writing
				unique_lock writeLock(lock);
				
				// Check if number of messages received or sent is too high
				if(numberOfMessagesReceived > MAXIMUM_NUMBER_OF_MESSAGES_RECEIVED_PER_INTERVAL || numberOfMessagesSent > MAXIMUM_NUMBER_OF_MESSAGES_SENT_PER_INTERVAL) {
				
					// Unlock write lock
					writeLock.unlock();
					
					{
						// Lock node for writing
						lock_guard nodeWriteLock(node.getLock());
						
						// Add self to node's list of banned peers
						node.addBannedPeer(identifier);
					}
					
					// Disconnect
					disconnect();
					
					// Break
					break;
				}
				
				// Otherwise
				else {
				
					// Set number of messages sent to zero
					numberOfMessagesSent = 0;
				
					// Unlock write lock
					writeLock.unlock();
					
					// Set number of messages received to zero
					numberOfMessagesReceived = 0;
				}
			
				// Set last number of messages check time to now
				lastNumberOfMessagesCheckTime = chrono::steady_clock::now();
			}
		
			// Check if peer addresses were received
			if(communicationState == CommunicationState::PEER_ADDRESSES_RECEIVED) {
			
				// Check if time to get peer addresses
				if(chrono::steady_clock::now() - lastGetPeerAddressesTime >= GET_PEER_ADDRESSES_INTERVAL) {
			
					// Create get peer addresses message
					const vector getPeerAddressesMessage = Message::createGetPeerAddressesMessage(Node::Capabilities::FULL_NODE);
					
					{
						// Lock for writing
						lock_guard writeLock(lock);
						
						// Check if messages can be sent and received
						if(numberOfMessagesReceived < MAXIMUM_NUMBER_OF_MESSAGES_RECEIVED_PER_INTERVAL / 2 && numberOfMessagesSent < MAXIMUM_NUMBER_OF_MESSAGES_SENT_PER_INTERVAL / 2) {
						
							// Append get peer addresses message to write buffer
							writeBuffer.insert(writeBuffer.cend(), getPeerAddressesMessage.cbegin(), getPeerAddressesMessage.cend());
							
							// Increment number of messages sent
							++numberOfMessagesSent;
						}
					}
					
					// Set last get peer addresses time to now
					lastGetPeerAddressesTime = chrono::steady_clock::now();
				}
			}
			
			// Otherwise
			else {
			
				// Set last get peer addresses time to now
				lastGetPeerAddressesTime = chrono::steady_clock::now();
			}
			
			// Check if waiting for a sync response has timed out
			if(currentSyncResponseRequiredTime.has_value() && chrono::steady_clock::now() > currentSyncResponseRequiredTime.value()) {
			
				// Remove the current sync response required time
				currentSyncResponseRequiredTime.reset();
			
				// Set disconnect peer to true
				bool disconnectPeer = true;
			
				{
					// Lock for writing
					unique_lock writeLock(lock);
					
					// Check if syncing state is requested block
					if(syncingState == SyncingState::REQUESTED_BLOCK) {
					
						// Check if not at the max number of reorgs during block sync
						if(numberOfReorgsDuringBlockSync != INT_MAX) {
						
							// Increment number of reorgs during block sync
							++numberOfReorgsDuringBlockSync;
						}
						
						// Check if too many reorgs haven't occurred during the block sync
						if(numberOfReorgsDuringBlockSync < MAXIMUM_ALLOWED_NUMBER_OF_REORGS_DURING_BLOCK_SYNC) {
					
							// Set syncing state to requesting headers
							syncingState = SyncingState::REQUESTING_HEADERS;
							
							// Unlock write lock
							writeLock.unlock();
							
							// Set number of reorgs during headers sync to zero
							numberOfReorgsDuringHeadersSync = 0;
							
							// Set disconnect peer to false
							disconnectPeer = false;
						}
					}
				}
				
				// Check if disconnecting peer
				if(disconnectPeer) {
			
					{
						// Lock node for writing
						lock_guard nodeWriteLock(node.getLock());
						
						// Add self to node's list of banned peers
						node.addBannedPeer(identifier);
					}
					
					// Disconnect
					disconnect();
					
					// Break
					break;
				}
			}
			
			{
			
				// Initialize current syncing state
				SyncingState currentSyncingState;
				
				{
					// Lock for reading
					shared_lock readLock(lock);
					
					// Set current syncing state to the syncing state
					currentSyncingState = syncingState;
				}
				
				// Check if syncing
				if(currentSyncingState != SyncingState::NOT_SYNCING) {
				
					// Set ban to false
					bool ban = false;
					
					// Check current syncing state
					switch(currentSyncingState) {
					
						// Requesting headers
						case SyncingState::REQUESTING_HEADERS:
						
							// Check if using node headers
							if(useNodeHeaders) {
							
								{
									// Lock node for reading
									shared_lock nodeReadLock(node.getLock());
									
									// Set headers to node's headers
									headers = node.getHeaders();
								}
								
								// Set use node headers to false
								useNodeHeaders = false;
							}
						
							// Check if too many reorgs have occurred during the headers sync
							if(numberOfReorgsDuringHeadersSync >= MAXIMUM_ALLOWED_NUMBER_OF_REORGS_DURING_HEADERS_SYNC) {
							
								// Set ban to true
								ban = true;
								
								// Break
								break;
							}
						
							{
								// Create get headers message
								const vector getHeadersMessage = Message::createGetHeadersMessage(getLocatorHeadersBlockHashes());
								
								{
									// Lock for writing
									unique_lock writeLock(lock);
									
									// Check if messages can be sent and received
									if(numberOfMessagesReceived < MAXIMUM_NUMBER_OF_MESSAGES_RECEIVED_PER_INTERVAL / 2 - RESERVED_NUMBER_OF_MESSAGES_PER_INTERVAL && numberOfMessagesSent < MAXIMUM_NUMBER_OF_MESSAGES_SENT_PER_INTERVAL / 2 - RESERVED_NUMBER_OF_MESSAGES_PER_INTERVAL) {
									
										// Append get headers message to write buffer
										writeBuffer.insert(writeBuffer.cend(), getHeadersMessage.cbegin(), getHeadersMessage.cend());
										
										// Increment number of messages sent
										++numberOfMessagesSent;
										
										// Set syncing state to requested headers
										syncingState = SyncingState::REQUESTED_HEADERS;
										
										// Unlock write lock
										writeLock.unlock();
										
										// Set current response required time
										currentSyncResponseRequiredTime = chrono::steady_clock::now() + GET_HEADERS_RESPONSE_REQUIRED_DURATION;
									}
								}
							}
						
							// Break
							break;
						
						// Requesting transaction hash set
						case SyncingState::REQUESTING_TRANSACTION_HASH_SET:
						
							{
								// Get transaction hash set height
								const uint64_t transactionHashSetHeight = SaturateMath::subtract(headers.back().getHeight(), Consensus::STATE_SYNC_HEIGHT_THRESHOLD);
								
								// Get transaction hash set header
								const Header *transactionHashSetHeader = headers.getLeaf(transactionHashSetHeight);
							
								// Create get transaction hash set message
								const vector getTransactionHashSetMessage = Message::createGetTransactionHashSetMessage(transactionHashSetHeader->getHeight(), transactionHashSetHeader->getBlockHash().data());
								
								{
									// Lock for writing
									unique_lock writeLock(lock);
									
									// Check if messages can be sent and received
									if(numberOfMessagesReceived < MAXIMUM_NUMBER_OF_MESSAGES_RECEIVED_PER_INTERVAL / 2 - RESERVED_NUMBER_OF_MESSAGES_PER_INTERVAL && numberOfMessagesSent < MAXIMUM_NUMBER_OF_MESSAGES_SENT_PER_INTERVAL / 2 - RESERVED_NUMBER_OF_MESSAGES_PER_INTERVAL) {
									
										// Append get transaction hash set message to write buffer
										writeBuffer.insert(writeBuffer.cend(), getTransactionHashSetMessage.cbegin(), getTransactionHashSetMessage.cend());
										
										// Increment number of messages sent
										++numberOfMessagesSent;
										
										// Set syncing state to requested transaction hash set
										syncingState = SyncingState::REQUESTED_TRANSACTION_HASH_SET;
										
										// Unlock write lock
										writeLock.unlock();
										
										// Set current response required time
										currentSyncResponseRequiredTime = chrono::steady_clock::now() + GET_TRANSACTION_HASH_SET_RESPONSE_REQUIRED_DURATION;
										
										// Set transaction hash set response received to false
										transactionHashSetResponseReceived = false;
									}
								}
							}
						
							// Break
							break;
						
						// Requesting block
						case SyncingState::REQUESTING_BLOCK:
						
							// Check if too many reorgs have occurred during the block sync
							if(numberOfReorgsDuringBlockSync >= MAXIMUM_ALLOWED_NUMBER_OF_REORGS_DURING_BLOCK_SYNC) {
							
								// Set ban to true
								ban = true;
								
								// Break
								break;
							}
						
							{
								// Initialize block hash
								array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH> blockHash;
								
								// Check if using node headers
								if(useNodeHeaders) {
								
									// Lock node for reading
									shared_lock nodeReadLock(node.getLock());
									
									// Set block hash to the next header's block hash
									blockHash = node.getHeaders().getLeaf(syncedHeaderIndex + 1)->getBlockHash();
								}
								
								// Otherwise
								else {
								
									// Set block hash to the next header's block hash
									blockHash = headers.getLeaf(syncedHeaderIndex + 1)->getBlockHash();
								}
								
								// Create get block message
								const vector getBlockMessage = Message::createGetBlockMessage(blockHash.data());
								
								{
									// Lock for writing
									unique_lock writeLock(lock);
									
									// Check if messages can be sent and received
									if(numberOfMessagesReceived < MAXIMUM_NUMBER_OF_MESSAGES_RECEIVED_PER_INTERVAL / 2 - RESERVED_NUMBER_OF_MESSAGES_PER_INTERVAL && numberOfMessagesSent < MAXIMUM_NUMBER_OF_MESSAGES_SENT_PER_INTERVAL / 2 - RESERVED_NUMBER_OF_MESSAGES_PER_INTERVAL) {
									
										// Append get block message to write buffer
										writeBuffer.insert(writeBuffer.cend(), getBlockMessage.cbegin(), getBlockMessage.cend());
										
										// Increment number of messages sent
										++numberOfMessagesSent;
										
										// Set syncing state to requested block
										syncingState = SyncingState::REQUESTED_BLOCK;
										
										// Unlock write lock
										writeLock.unlock();
										
										// Set current response required time
										currentSyncResponseRequiredTime = chrono::steady_clock::now() + GET_BLOCK_RESPONSE_REQUIRED_DURATION;
									}
								}
							}
						
							// Break
							break;
						
						// Processing transaction hash set or processing block
						case SyncingState::PROCESSING_TRANSACTION_HASH_SET:
						case SyncingState::PROCESSING_BLOCK:
						
							// Check if work operation has finished
							if(workerOperation.valid() && workerOperation.wait_for(0s) == future_status::ready) {
							
								// Check if performing work operation failed
								if(!workerOperation.get()) {
								
									// Set ban to true
									ban = true;
								}
							}
							
							// Break
							break;
						
						// Default
						default:
						
							// Break
							break;
					}
					
					// Check if banning
					if(ban) {
					
						{
							// Lock node for writing
							lock_guard nodeWriteLock(node.getLock());
							
							// Add self to node's list of banned peers
							node.addBannedPeer(identifier);
						}
						
						// Disconnect
						disconnect();
					
						// Break
						break;
					}
				}
			}
			
			// Check if shake was received
			if(communicationState > CommunicationState::HAND_SENT) {
		
				// Check if time to send a ping
				if(chrono::steady_clock::now() - lastPingTime >= PING_INTERVAL) {
				
					// Initialize node's total difficulty and height
					uint64_t nodesTotalDifficulty;
					uint64_t nodesHeight;
				
					{
						// Lock node for reading
						shared_lock nodeReadLock(node.getLock());
						
						// Set node's totoal difficulty to node's total difficulty
						nodesTotalDifficulty = node.getTotalDifficulty();
						
						// Set node's height to node's height
						nodesHeight = node.getHeight();
					}
				
					// Create ping message
					const vector pingMessage = Message::createPingMessage(nodesTotalDifficulty, nodesHeight);
					
					{
						// Lock for writing
						lock_guard writeLock(lock);
						
						// Check if messages can be sent and received
						if(numberOfMessagesReceived < MAXIMUM_NUMBER_OF_MESSAGES_RECEIVED_PER_INTERVAL / 2 && numberOfMessagesSent < MAXIMUM_NUMBER_OF_MESSAGES_SENT_PER_INTERVAL / 2) {
					
							// Append ping message to write buffer
							writeBuffer.insert(writeBuffer.cend(), pingMessage.cbegin(), pingMessage.cend());
							
							// Increment number of messages sent
							++numberOfMessagesSent;
						}
					}
					
					// Set last ping time to now
					lastPingTime = chrono::steady_clock::now();
				}
				
				{
					// Lock node and self for reading
					shared_lock nodeReadLock(node.getLock(), defer_lock);
					shared_lock readLock(lock, defer_lock);
					
					::lock(nodeReadLock, readLock);
					
					// Check if the total difficulty is less than the node's total difficulty
					if(totalDifficulty < node.getTotalDifficulty()) {
					
						// Unlock node and self read locks
						nodeReadLock.unlock();
						readLock.unlock();
					
						// Check if stuck while syncing
						if(chrono::steady_clock::now() - totalDifficultyLastChangedTime > SYNC_STUCK_DURATION) {
						
							{
								// Lock node for writing
								lock_guard nodeWriteLock(node.getLock());
								
								// Add self to node's list of banned peers
								node.addBannedPeer(identifier);
							}
							
							// Disconnect
							disconnect();
							
							// Break
							break;
						}
					}
					
					// Otherwise
					else {
					
						// Set total difficulty last changed time to now
						totalDifficultyLastChangedTime = chrono::steady_clock::now();
					}
				}
			}
			
			// Otherwise
			else {
			
				// Set last ping time to now
				lastPingTime = chrono::steady_clock::now();
			}
			
			// Check if Windows
			#ifdef _WIN32
			
				// Set sockets to monitor read events
				WSAPOLLFD sockets = {
				
					// Socket
					.fd = socket,
					
					// Events
					.events = POLLIN
				};
			
			// Otherwise
			#else
			
				// Set sockets to monitor read events
				pollfd sockets = {
				
					// Socket
					.fd = socket,
					
					// Events
					.events = POLLIN
				};
			#endif
				
			{
				// Lock for reading
				shared_lock readLock(lock);
			
				// Check if write buffer isn't empty
				if(!writeBuffer.empty()) {
				
					// Unlock read lock
					readLock.unlock();
					
					// Set sockets to monitor write events
					sockets.events |= POLLOUT;
					
					// Check if current write is done
					if(currentWriteDone) {
					
						// Set current write done to false
						currentWriteDone = false;
						
						// Set current write start time to now
						currentWriteStartTime = chrono::steady_clock::now();
					}
				}
			}
				
			// Check if Windows
			#ifdef _WIN32
			
				// Wait for read and/or write events on the socket
				const int pollStatus = WSAPoll(&sockets, 1, READ_AND_WRITE_POLL_TIMEOUT);
				
				// Check if detecting read and/or write events on the socket failed
				if(pollStatus == SOCKET_ERROR) {
			
			// Otherwise
			#else
			
				// Wait for read and/or write events on the socket
				const int pollStatus = poll(&sockets, 1, READ_AND_WRITE_POLL_TIMEOUT);
				
				// Check if detecting read and/or write events on the socket failed
				if(pollStatus == -1) {
			#endif
			
				// Disconnect
				disconnect();
				
				// Break
				break;
			}
			
			// Otherwise check if read and/or write events occurred on the socket
			else if(pollStatus > 0) {
			
				// Check if read event occurred on the socket
				if(sockets.revents & POLLIN) {
				
					// Check if current read is done
					if(currentReadDone) {
					
						// Set current read done to false
						currentReadDone = false;
						
						// Set current read start time to now
						currentReadStartTime = chrono::steady_clock::now();
					}
				
					// Loop until all bytes are read
					decltype(function(recv))::result_type bytesRead;
					do {
					
						// Initialize buffer
						uint8_t buffer[UINT8_MAX];
						
						// Read bytes from socket
						bytesRead = recv(socket, reinterpret_cast<char *>(buffer), sizeof(buffer), 0);
						
						// Check if bytes were read
						if(bytesRead > 0) {
						
							// Set current read done to true
							currentReadDone = true;
						
							// Add bytes to read buffer
							readBuffer.insert(readBuffer.cend(), cbegin(buffer), cbegin(buffer) + bytesRead);
						}
						
					} while(bytesRead > 0);
					
					// Check if Windows
					#ifdef _WIN32
					
						// Check if disconnected or an error occurred
						if(!bytesRead || (bytesRead == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK)) {
					
					// Otherwise
					#else
					
						// Check if disconnected or an error occurred
						if(!bytesRead || (bytesRead == -1 && errno != EAGAIN && errno != EWOULDBLOCK)) {
					#endif
					
						// Disconnect
						disconnect();
						
						// Break
						break;
					}
					
					// Check if processing requests and/or responses failed
					if(!processRequestsAndOrResponses()) {
					
						// Disconnect
						disconnect();
						
						// Break
						break;
					}
					
					// Check if current read is done
					if(currentReadDone) {
					
						// Set last read time to now
						lastReadTime = chrono::steady_clock::now();
					}
				}
				
				// Check if write event occurred on the socket
				if(sockets.revents & POLLOUT) {
				
					// Loop through all bytes to send
					decltype(function(send))::result_type bytesSent;
					do {
					
						{
							// Lock for reading
							shared_lock readLock(lock);
						
							// Check if Windows
							#ifdef _WIN32
							
								// Get bytes sent to socket
								bytesSent = send(socket, reinterpret_cast<char *>(writeBuffer.data()), writeBuffer.size(), 0);
								
							// Otherwise
							#else
							
								// Get bytes sent to socket
								bytesSent = send(socket, writeBuffer.data(), writeBuffer.size(), MSG_NOSIGNAL);
							#endif
						}
						
						// Check if bytes were sent
						if(bytesSent > 0) {
						
							// Set current write done to true
							currentWriteDone = true;
							
							{
								// Lock for writing
								lock_guard writeLock(lock);
						
								// Remove bytes from write buffer
								writeBuffer.erase(writeBuffer.cbegin(), writeBuffer.cbegin() + bytesSent);
								
								// Check if write buffer is empty
								if(writeBuffer.empty()) {
								
									// Free all memory allocated by the write buffer
									vector<uint8_t>().swap(writeBuffer);
								
									// break
									break;
								}
							}
						}
					} while(bytesSent > 0);
					
					// Check if Windows
					#ifdef _WIN32
					
						// Check if an error occurred
						if(bytesSent == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK) {
					
					// Otherwise
					#else
					
						// Check if an error occurred
						if(bytesSent == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
					#endif
					
						// Disconnect
						disconnect();
						
						// Break
						break;
					}
				}
			}
			
			// Check if a read or write timeout occurred
			if((!currentReadDone && chrono::steady_clock::now() - currentReadStartTime >= READ_TIMEOUT) || (!currentWriteDone && chrono::steady_clock::now() - currentWriteStartTime >= WRITE_TIMEOUT)) {
			
				// Disconnect
				disconnect();
				
				// Break
				break;
			}
			
			// Check if not communicating
			if(chrono::steady_clock::now() - lastReadTime >= COMMUNICATION_REQUIRED_TIMEOUT) {
			
				// Disconnect
				disconnect();
				
				// Break
				break;
			}
		}
	}
	
	// Catch errors
	catch(...) {
	
		// Disconnect
		disconnect();
	}
	
	// Check if worker operation exists
	if(workerOperation.valid()) {
	
		// Set stop read and write to true
		stopReadAndWrite.store(true);
	
		// Try
		try {
	
			// Wait for worker operation to finish
			workerOperation.get();
		}
		
		// Catch errors
		catch(...) {
		
			// Set closing
			Common::setClosing();
			
			// Notify peers that event occurred
			eventOccurred.notify_one();
		}
	}
}

// Disconnect
void Peer::disconnect() {

	// Check if worker operation exists
	if(workerOperation.valid()) {
	
		// Try
		try {
	
			// Check if performing work operation failed
			if(!workerOperation.get()) {
			
				// Try
				try {
			
					// Lock node for writing
					lock_guard nodeWriteLock(node.getLock());
					
					// Add self to node's list of banned peers
					node.addBannedPeer(identifier);
				}
				
				// Catch errors
				catch(...) {
				
				}
			}
		}
		
		// Catch errors
		catch(...) {
		
			// Set closing
			Common::setClosing();
		}
	}
	
	// Set closed to false
	bool closed = false;

	// Try
	try {
	
		// Create thread and detach it
		thread([](const int socket) {
		
			// Check if Windows
			#ifdef _WIN32
			
				{
			
			// Otherwise
			#else
		
				// Check if getting the socket's flags was successful
				const int socketFlags = fcntl(socket, F_GETFL);
				
				if(socketFlags != -1) {
			#endif
		
				// Check if Windows
				#ifdef _WIN32
			
					// Check if setting the socket as blocking was successful
					u_long nonBlocking = false;
					if(!ioctlsocket(socket, FIONBIO, &nonBlocking)) {
				
				// Otherwise
				#else
		
					// Check if setting the socket as blocking was successful
					if(fcntl(socket, F_SETFL, socketFlags & ~O_NONBLOCK) != -1) {
				#endif
				
					// Set linger timeout
					const linger lingerTimeout = {
					
						// On
						.l_onoff = true,
						
						// Timeout
						.l_linger = LINGER_TIMEOUT
					};
					
					// Set socket's linger timeout
					setsockopt(socket, SOL_SOCKET, SO_LINGER, reinterpret_cast<const char *>(&lingerTimeout), sizeof(lingerTimeout));
				}
			}
			
			// Check if Windows
			#ifdef _WIN32
			
				// Shutdown socket receive
				shutdown(socket, SD_RECEIVE);
				
				// Close socket
				closesocket(socket);
				
			// Otherwise
			#else
			
				// Shutdown socket receive
				shutdown(socket, SHUT_RD);
				
				// Close socket
				close(socket);
			#endif
		
		}, socket).detach();
		
		// Check if Windows
		#ifdef _WIN32
		
			// Set socket to invalid
			socket = INVALID_SOCKET;
		
		// Otherwise
		#else
		
			// Set socket to invalid
			socket = -1;
		#endif
		
		// Set closed to true
		closed = true;
	}
	
	// Catch errors
	catch(...) {
	
	}
	
	// Check if socket wasn't closed
	if(!closed) {
	
		// Check if Windows
		#ifdef _WIN32
		
			// Shutdown socket receive
			shutdown(socket, SD_RECEIVE);
			
			// Close socket
			closesocket(socket);
			
			// Set socket to invalid
			socket = INVALID_SOCKET;
			
		// Otherwise
		#else
		
			// Shutdown socket receive
			shutdown(socket, SHUT_RD);
			
			// Close socket
			close(socket);
			
			// Set socket to invalid
			socket = -1;
		#endif
	}
	
	// Free all memory allocated by the read buffer
	vector<uint8_t>().swap(readBuffer);
	
	// Delay
	this_thread::sleep_for(BEFORE_DISCONNECT_DELAY_DURATION);
	
	// Try
	try {
	
		// Lock for writing
		lock_guard writeLock(lock);
		
		// Free all memory allocated by the write buffer
		vector<uint8_t>().swap(writeBuffer);
		
		// Set connection state to disconnected
		connectionState = ConnectionState::DISCONNECTED;
	}
	
	// Catch errors
	catch(...) {
	
		// Set closing
		Common::setClosing();
	}
	
	// Check if shake was received
	if(communicationState > CommunicationState::HAND_SENT) {
	
		// Try
		try {
			// Lock node for writing
			lock_guard nodeWriteLock(node.getLock());
			
			// Check if self is healthy
			if(node.isPeerHealthy(identifier)) {
			
				// Add self to node's healthy peer
				node.addHealthyPeer(identifier, capabilities);
			}
		}
		
		// Catch errors
		catch(...) {
		
		}
	}
	
	// Notify peers that event occurred
	eventOccurred.notify_one();
}

// Process requests and/or responses
bool Peer::processRequestsAndOrResponses() {

	// Go through all requests and responses
	while(true) {
	
		// Check if request or response doesn't contain a message header
		if(readBuffer.size() < Message::MESSAGE_HEADER_LENGTH) {
		
			// Break
			break;
		}
		
		// Initialize message header
		tuple<Message::Type, vector<uint8_t>::size_type> messageHeader;
		
		// Try
		try {
		
			// Read message header
			messageHeader = Message::readMessageHeader(readBuffer);
		}
		
		// Catch errors
		catch(...) {
		
			{
				// Lock node for writing
				lock_guard nodeWriteLock(node.getLock());
				
				// Add self to node's list of banned peers
				node.addBannedPeer(identifier);
			}
			
			// Return false
			return false;
		}
		
		// Get message type and payload length from message header
		const Message::Type &messageType = get<0>(messageHeader);
		const vector<uint8_t>::size_type &messagePayloadLength = get<1>(messageHeader);
		
		// Check if request or response doesn't contain a payload
		if(readBuffer.size() < Message::MESSAGE_HEADER_LENGTH + messagePayloadLength) {
		
			// Break
			break;
		}
		
		// Set ban to false
		bool ban = false;
		
		// Set response or request erased to false
		bool responseOrRequestErased = false;
		
		// Set message attachment length to zero
		vector<uint8_t>::size_type messageAttachmentLength = 0;
		
		// Set increment number of messages received to true
		bool incrementNumberOfMessagesReceived = true;
		
		// Check message's type
		switch(messageType) {
		
			// Error response
			case Message::Type::ERROR_RESPONSE:
			
				// Return false
				return false;
			
				// Break
				break;
		
			// Hand
			case Message::Type::HAND:
			
				// Set ban to true
				ban = true;
				
				// Break
				break;
		
			// Shake
			case Message::Type::SHAKE:
			
				// Check if expecting shake response
				if(communicationState == CommunicationState::HAND_SENT) {
				
					// Initialize shake components
					tuple<Node::Capabilities, uint64_t, string, uint32_t, uint64_t> shakeComponents;
					
					// Try
					try {
					
						// Read shake message
						shakeComponents = Message::readShakeMessage(readBuffer);
					}
		
					// Catch errors
					catch(...) {
					
						// Set ban to true
						ban = true;
						
						// Break
						break;
					}
					
					// Get shake capabilities, total difficulty, user agent, protocol version, and base fee from shake components
					const Node::Capabilities &shakeCapabilities = get<0>(shakeComponents);
					const uint64_t &shakeTotalDifficulty = get<1>(shakeComponents);
					const string &shakeUserAgent = get<2>(shakeComponents);
					const uint32_t &shakeProtocolVersion = get<3>(shakeComponents);
					const uint64_t &shakeBaseFee = get<4>(shakeComponents);
					
					// Create get peer addresses message
					const vector getPeerAddressesMessage = Message::createGetPeerAddressesMessage(Node::Capabilities::FULL_NODE);
					
					{
						// Lock for writing
						lock_guard writeLock(lock);
					
						// Set capabilities to shake's capabilities
						capabilities = shakeCapabilities;
						
						// Set total difficulty to shake's total difficulty
						totalDifficulty = shakeTotalDifficulty;
						
						// Set user agent to shake's user agent
						userAgent = shakeUserAgent;
						
						// Set protocol version to shake's protocol version
						protocolVersion = shakeProtocolVersion;
						
						// Set base fee to shake's base fee
						baseFee = shakeBaseFee;
						
						// Append get peer addresses messages to write buffer
						writeBuffer.insert(writeBuffer.cend(), getPeerAddressesMessage.cbegin(), getPeerAddressesMessage.cend());
						
						// Check if not at the max number of messages sent
						if(numberOfMessagesSent != INT_MAX) {
						
							// Increment number of messages sent
							++numberOfMessagesSent;
						}
					}
					
					// Set last ping time to now
					lastPingTime = chrono::steady_clock::now();
					
					// Set total difficulty last changed time to now
					totalDifficultyLastChangedTime = chrono::steady_clock::now();
					
					// Set communication state to peer addresses requested
					communicationState = CommunicationState::PEER_ADDRESSES_REQUESTED;
				}
				
				// Otherwise
				else {
				
					// Set ban to true
					ban = true;
				}
				
				// Break;
				break;
			
			// Ping
			case Message::Type::PING:
			
				// Check if shake was received
				if(communicationState > CommunicationState::HAND_SENT) {
				
					// Initialize current total difficulty
					uint64_t currentTotalDifficulty;
					
					// Try
					try {
					
						// Read ping message
						currentTotalDifficulty = Message::readPingMessage(readBuffer);
					}
		
					// Catch errors
					catch(...) {
					
						// Set ban to true
						ban = true;
						
						// Break
						break;
					}
					
					// Initialize node's total difficulty and height
					uint64_t nodesTotalDifficulty;
					uint64_t nodesHeight;
				
					{
						// Lock node for reading
						shared_lock nodeReadLock(node.getLock());
						
						// Set node's total difficulty to node's total difficulty
						nodesTotalDifficulty = node.getTotalDifficulty();
						
						// Set node's height to node's height
						nodesHeight = node.getHeight();
					}
					
					// Create pong message
					const vector pongMessage = Message::createPongMessage(nodesTotalDifficulty, nodesHeight);
					
					// Initialize total difficulty changed
					bool totalDifficultyChanged;
					
					{
						// Lock for writing
						lock_guard writeLock(lock);
						
						// Set total difficulty changed to if the total difficulty changed
						totalDifficultyChanged = totalDifficulty != currentTotalDifficulty;
				
						// Set total difficulty to the current total difficulty
						totalDifficulty = currentTotalDifficulty;
						
						// Check if messages can be sent
						if(numberOfMessagesSent < MAXIMUM_NUMBER_OF_MESSAGES_SENT_PER_INTERVAL / 2) {
						
							// Append pong message to write buffer
							writeBuffer.insert(writeBuffer.cend(), pongMessage.cbegin(), pongMessage.cend());
							
							// Increment number of messages sent
							++numberOfMessagesSent;
						}
					}
					
					// Set last ping time to now
					lastPingTime = chrono::steady_clock::now();
					
					// Check if total difficulty changed
					if(totalDifficultyChanged) {
					
						// Set total difficulty last changed time to now
						totalDifficultyLastChangedTime = chrono::steady_clock::now();
					
						// Notify peers that event occurred
						eventOccurred.notify_one();
					}
				}
				
				// Otherwise
				else {
				
					// Set ban to true
					ban = true;
				}
			
				// Break
				break;
			
			// Pong
			case Message::Type::PONG:
			
				// Check if shake was received
				if(communicationState > CommunicationState::HAND_SENT) {
				
					// Initialize current total difficulty
					uint64_t currentTotalDifficulty;
					
					// Try
					try {
					
						// Read pong message
						currentTotalDifficulty = Message::readPongMessage(readBuffer);
					}
		
					// Catch errors
					catch(...) {
					
						// Set ban to true
						ban = true;
						
						// Break
						break;
					}
					
					// Initialize total difficulty changed
					bool totalDifficultyChanged;
					
					{
						// Lock for writing
						lock_guard writeLock(lock);
						
						// Set total difficulty changed to if the total difficulty changed
						totalDifficultyChanged = totalDifficulty != currentTotalDifficulty;
				
						// Set total difficulty to the current total difficulty
						totalDifficulty = currentTotalDifficulty;
					}
					
					// Set last ping time to now
					lastPingTime = chrono::steady_clock::now();
					
					// Check if total difficulty changed
					if(totalDifficultyChanged) {
					
						// Set total difficulty last changed time to now
						totalDifficultyLastChangedTime = chrono::steady_clock::now();
					
						// Notify peers that event occurred
						eventOccurred.notify_one();
					}
				}
				
				// Otherwise
				else {
				
					// Set ban to true
					ban = true;
				}
			
				// Break
				break;
			
			// Get peer addresses
			case Message::Type::GET_PEER_ADDRESSES:
			
				// Check if shake was received
				if(communicationState > CommunicationState::HAND_SENT) {
				
					// Initialize desired capabilities
					Node::Capabilities desiredCapabilities;
					
					// Try
					try {
					
						// Read get peer addresses message
						desiredCapabilities = Message::readGetPeerAddressesMessage(readBuffer);
					}
		
					// Catch errors
					catch(...) {
					
						// Set ban to true
						ban = true;
						
						// Break
						break;
					}
					
					// Initialize network addresses
					vector<NetworkAddress> networkAddresses;
					
					// Initialize addresses
					list<variant<in_addr, in6_addr, string>> addresses;
			
					{
						// Lock node for reading
						shared_lock nodeReadLock(node.getLock());
						
						// Go through all of the node's healthy peers
						for(const auto &healthyPeer : node.getHealthyPeers()) {
						
							// Check if peer is healthy
							if(node.isPeerHealthy(healthyPeer.first)) {
						
								// Check if Tor is enabled
								#ifdef TOR_ENABLE
							
									// Check if healthy peer has the desired capabilities
									if((healthyPeer.second.second & (desiredCapabilities & ~Node::Capabilities::TOR_ADDRESS)) == (desiredCapabilities & ~Node::Capabilities::TOR_ADDRESS)) {
								
								// Otherwise
								#else
								
									// Check if healthy peer has the desired capabilities
									if((healthyPeer.second.second & desiredCapabilities) == desiredCapabilities) {
								#endif
							
									// Initialize network address
									NetworkAddress networkAddress;
								
									// Get port offset in the healthy peer
									const string::size_type portOffset = healthyPeer.first.rfind(':');
									
									// Check if healthy peer is an IP address and port
									if(portOffset != string::npos) {
									
										// Get IP address from the healthy peer
										string ipAddress = healthyPeer.first.substr(0, portOffset);
										
										// Set is IPv4 to true
										bool isIpv4 = true;
										
										// Check if IP address is enclosed in brackets
										if(ipAddress.front() == '[' && ipAddress.back() == ']') {
										
											// Remove enclosing brackets from IP address
											ipAddress = ipAddress.substr(sizeof('['), ipAddress.size() - sizeof('[') - sizeof(']'));
											
											// Set is IPv4 to false
											isIpv4 = false;
										}
										
										// Set port from the healthy peer
										const char *port = &healthyPeer.first[portOffset + sizeof(':')];
										
										// Check if is IPv4
										if(isIpv4) {
										
											// Append IPv4 address to list and get it
											addresses.push_back(in_addr());
											in_addr &ipv4Address = get<in_addr>(addresses.back());
											
											// Check if parsing ip address was successful
											if(inet_pton(AF_INET, ipAddress.c_str(), &ipv4Address) == 1) {
											
												// Set network address's family to IPv4
												networkAddress.family = NetworkAddress::Family::IPV4;
												
												// Set network address's address to the IPv4 address
												networkAddress.address = &ipv4Address;
												
												// Set network address's address length to the IPv4 address length
												networkAddress.addressLength = sizeof(ipv4Address);
												
												// Set network address's port to the port
												networkAddress.port = htons(atoi(port));
											}
											
											// Otherwise
											else {
											
												// Go to next healthy peer
												continue;
											}
										}
										
										// Otherwise
										else {
										
											// Append IPv6 address to list and get it
											addresses.push_back(in6_addr());
											in6_addr &ipv6Address = get<in6_addr>(addresses.back());
											
											// Check if parsing ip address was successful
											if(inet_pton(AF_INET6, ipAddress.c_str(), &ipv6Address) == 1) {
											
												// Set network address's family to IPv6
												networkAddress.family = NetworkAddress::Family::IPV6;
												
												// Set network address's address to the IPv6 address
												networkAddress.address = &ipv6Address;
												
												// Set network address's address length to the IPv6 address length
												networkAddress.addressLength = sizeof(ipv6Address);
												
												// Set network address's port to the port
												networkAddress.port = htons(atoi(port));
											}
											
											// Otherwise
											else {
											
												// Go to next healthy peer
												continue;
											}
										}
									}
									
									// Check if Tor is enabled
									#ifdef TOR_ENABLE
								
										// Otherwise check if capabilities includes Tor address
										else if(capabilities & Node::Capabilities::TOR_ADDRESS) {
										
											// Append Tor address to list and get it
											addresses.push_back(healthyPeer.first);
											const string &torAddress = get<string>(addresses.back());
										
											// Set network address's family to Onion service
											networkAddress.family = NetworkAddress::Family::ONION_SERVICE;
											
											// Set network address's address to the Tor address
											networkAddress.address = torAddress.c_str();
											
											// Set network address's address length to the Tor address length
											networkAddress.addressLength = torAddress.size();
										}
									#endif
									
									// Otherwise
									else {
									
										// Go to next healthy peer
										continue;
									}
									
									// Append network address to list
									networkAddresses.push_back(move(networkAddress));
								}
							}
						}
					}
					
					// Randomize network addresses order
					shuffle(networkAddresses.begin(), networkAddresses.end(), randomNumberGenerator);
					
					// Check if too many network addresses exist
					if(networkAddresses.size() > Message::MAXIMUM_NUMBER_OF_PEER_ADDRESSES) {
					
						// Remove extra network addresses
						networkAddresses.erase(networkAddresses.cbegin() + Message::MAXIMUM_NUMBER_OF_PEER_ADDRESSES, networkAddresses.cend());
					}
					
					// Create peer addresses message
					const vector peerAddressesMessage = Message::createPeerAddressesMessage(networkAddresses);
					
					{
						// Lock for writing
						lock_guard writeLock(lock);
						
						// Check if messages can be sent
						if(numberOfMessagesSent < MAXIMUM_NUMBER_OF_MESSAGES_SENT_PER_INTERVAL / 2) {
						
							// Append peer addresses message to write buffer
							writeBuffer.insert(writeBuffer.cend(), peerAddressesMessage.cbegin(), peerAddressesMessage.cend());
							
							// Increment number of messages sent
							++numberOfMessagesSent;
						}
					}
				}
				
				// Otherwise
				else {
				
					// Set ban to true
					ban = true;
				}
			
				// Break
				break;
			
			// Peer addresses
			case Message::Type::PEER_ADDRESSES:
			
				// Check if peer addresses were requested
				if(communicationState >= CommunicationState::PEER_ADDRESSES_REQUESTED) {
				
					// Initialize peer addresses
					list<NetworkAddress> peerAddresses;
					
					// Try
					try {
					
						// Read peer addresses message
						peerAddresses = Message::readPeerAddressesMessage(readBuffer);
					}
		
					// Catch errors
					catch(...) {
					
						// Set ban to true
						ban = true;
						
						// Break
						break;
					}
					
					// Initialize new peer address received to false
					bool newPeerAddressReceived = false;
					
					// Go through all peer addresses
					for(const NetworkAddress &peerAddress : peerAddresses) {
					
						// Check peer address's family
						switch(peerAddress.family) {
						
							// IPv4
							case NetworkAddress::Family::IPV4:
							
								{
									// Check if getting the peer address's IP string was successful
									char ipString[INET_ADDRSTRLEN];
									
									if(inet_ntop(AF_INET, peerAddress.address, ipString, sizeof(ipString))) {
									
										// Create peer candidate
										string peerCandidate = string(ipString) + ':' + to_string(ntohs(peerAddress.port));
									
										// Lock node for writing
										lock_guard nodeWriteLock(node.getLock());
										
										// Check if peer candidate isn't already an unused peer candidate
										if(!node.isUnusedPeerCandidateValid(peerCandidate)) {
										
											// Set new peer address received
											newPeerAddressReceived = true;
										}
									
										// Add peer candidate to node's unused peer candidates
										node.addUnusedPeerCandidate(move(peerCandidate));
									}
								}
								
								// Break
								break;
							
							// IPv6
							case NetworkAddress::Family::IPV6:
							
								{
									// Check if getting the peer address's IP string was successful
									char ipString[INET6_ADDRSTRLEN];
									
									if(inet_ntop(AF_INET6, peerAddress.address, ipString, sizeof(ipString))) {
									
										// Create peer candidate
										string peerCandidate = '[' + string(ipString) + "]:" + to_string(ntohs(peerAddress.port));
									
										// Lock node for writing
										lock_guard nodeWriteLock(node.getLock());
										
										// Check if peer candidate isn't already an unused peer candidate
										if(!node.isUnusedPeerCandidateValid(peerCandidate)) {
										
											// Set new peer address received
											newPeerAddressReceived = true;
										}
									
										// Add peer candidate to node's unused peer candidates
										node.addUnusedPeerCandidate(move(peerCandidate));
									}
								}
								
								// Break
								break;
							
							// Check if Tor is enabled
							#ifdef TOR_ENABLE
							
								// Onion service
								case NetworkAddress::Family::ONION_SERVICE:
								
									{
										// Create peer candidate
										string peerCandidate(reinterpret_cast<const char *>(peerAddress.address), reinterpret_cast<const char *>(peerAddress.address) + peerAddress.addressLength);
									
										// Lock node for writing
										lock_guard nodeWriteLock(node.getLock());
										
										// Check if peer candidate isn't already an unused peer candidate
										if(!node.isUnusedPeerCandidateValid(peerCandidate)) {
										
											// Set new peer address received
											newPeerAddressReceived = true;
										}
									
										// Add peer candidate to node's unused peer candidates
										node.addUnusedPeerCandidate(move(peerCandidate));
									}
									
									// Break
									break;
							#endif
							
							// Default
							default:
							
								// Break
								break;
						}
					}
					
					// Check if a new peer address was received
					if(newPeerAddressReceived) {
					
						// Notify peers that event occurred
						eventOccurred.notify_one();
					}
					
					// Check if expecting peer addresses response
					if(communicationState == CommunicationState::PEER_ADDRESSES_REQUESTED) {
					
						// Set communication state to peer addresses received
						communicationState = CommunicationState::PEER_ADDRESSES_RECEIVED;
						
						{
							// Lock node for writing
							lock_guard nodeWriteLock(node.getLock());
							
							// Add self to node's healthy peer
							node.addHealthyPeer(identifier, capabilities);
						}
						
						// Check if Tor is enabled
						#ifdef TOR_ENABLE
						
							// Check if capabilities isn't a full node
							if((capabilities & (Node::Capabilities::FULL_NODE & ~Node::Capabilities::TOR_ADDRESS)) != (Node::Capabilities::FULL_NODE & ~Node::Capabilities::TOR_ADDRESS)) {
						
						// Otherwise
						#else
						
							// Check if capabilities isn't a full node
							if((capabilities & Node::Capabilities::FULL_NODE) != Node::Capabilities::FULL_NODE) {
						#endif
						
							// Return false
							return false;
						}
						
						{
							// Lock for writing
							lock_guard writeLock(lock);
							
							// Set connection state to connected and healthy
							connectionState = ConnectionState::CONNECTED_AND_HEALTHY;
						}
						
						// Notify peers that event occurred
						eventOccurred.notify_one();
					}
				}
				
				// Otherwise
				else {
				
					// Set ban to true
					ban = true;
				}
			
				// Break
				break;
			
			// Get headers
			case Message::Type::GET_HEADERS:
			
				// Check if shake was received
				if(communicationState > CommunicationState::HAND_SENT) {
					
					// Create error message
					const vector errorMessage = Message::createErrorMessage();
					
					{
						// Lock for writing
						lock_guard writeLock(lock);
						
						// Check if messages can be sent
						if(numberOfMessagesSent < MAXIMUM_NUMBER_OF_MESSAGES_SENT_PER_INTERVAL / 2) {
						
							// Append error message to write buffer
							writeBuffer.insert(writeBuffer.cend(), errorMessage.cbegin(), errorMessage.cend());
							
							// Increment number of messages sent
							++numberOfMessagesSent;
						}
					}
				}
				
				// Otherwise
				else {
				
					// Set ban to true
					ban = true;
				}
			
				// Break
				break;
			
			// Header
			case Message::Type::HEADER:
			
				// Check if shake was received
				if(communicationState > CommunicationState::HAND_SENT) {
				
					// Initialize header
					optional<Header> header;
					
					// Try
					try {
					
						// Read header message
						header = Message::readHeaderMessage(readBuffer);
					}
		
					// Catch errors
					catch(...) {
					
						// Set ban to true
						ban = true;
						
						// Break
						break;
					}
					
					// Initialize total difficulty changed and total difficulty increased
					bool totalDifficultyChanged;
					bool totalDifficultyIncreased;
					
					{
						// Lock for writing
						lock_guard writeLock(lock);
						
						// Set total difficulty changed to if the total difficulty changed
						totalDifficultyChanged = totalDifficulty != header.value().getTotalDifficulty();
						
						// Set total difficulty increased to if the total difficulty increased
						totalDifficultyIncreased = totalDifficulty < header.value().getTotalDifficulty();
				
						// Set total difficulty to the header's total difficulty
						totalDifficulty = header.value().getTotalDifficulty();
					}
					
					// Set last ping time to now
					lastPingTime = chrono::steady_clock::now();
					
					// Check if total difficulty changed
					if(totalDifficultyChanged) {
					
						// Set total difficulty last changed time to now
						totalDifficultyLastChangedTime = chrono::steady_clock::now();
					
						// Notify peers that event occurred
						eventOccurred.notify_one();
					}
					
					// Check if total difficulty increased
					if(totalDifficultyIncreased) {
					
						// Set increment number of messages received to false
						incrementNumberOfMessagesReceived = false;
					}
				}
				
				// Otherwise
				else {
				
					// Set ban to true
					ban = true;
				}
			
				// Break
				break;
			
			// Headers
			case Message::Type::HEADERS:
			
				// Check if shake was received
				if(communicationState > CommunicationState::HAND_SENT) {
				
					// Lock for reading
					shared_lock readLock(lock);
				
					// Check if headers were requested
					if(syncingState == SyncingState::REQUESTED_HEADERS) {
					
						// Unlock read lock
						readLock.unlock();
						
						// Remove the current sync response required time
						currentSyncResponseRequiredTime.reset();
				
						// Initialize headers
						list<Header> headers;
						
						// Try
						try {
						
							// Read headers message
							headers = Message::readHeadersMessage(readBuffer);
						}
			
						// Catch errors
						catch(...) {
						
							// Set ban to true
							ban = true;
							
							// Break
							break;
						}
						
						// Get number of headers
						const list<Header>::size_type numberOfHeaders = headers.size();
						
						// Get newest header height
						const uint64_t newestHeaderHeight = numberOfHeaders ? headers.back().getHeight() : Consensus::GENESIS_BLOCK_HEADER.getHeight();
						
						// Check if processing headers failed
						if(!processHeaders(move(headers))) {
						
							// Set ban to true
							ban = true;
							
							// Break
							break;
						}
						
						// Check if more headers exist
						if(numberOfHeaders == Message::MAXIMUM_NUMBER_OF_HEADERS || (numberOfHeaders && this->headers.back().getHeight() != newestHeaderHeight)) {
						
							// Lock for writing
							lock_guard writeLock(lock);
							
							// Set syncing state to requesting headers
							syncingState = SyncingState::REQUESTING_HEADERS;
						}
						
						// Otherwise
						else {
						
							// Lock for reading
							readLock.lock();
							
							// Check if peer didn't send all its headers
							if(this->headers.back().getTotalDifficulty() < totalDifficulty) {
							
								// Unlock read lock
								readLock.unlock();
								
								// Set ban to true
								ban = true;
								
								// Break
								break;
							}
							
							// Unlock read lock
							readLock.unlock();
						
							{
								// Lock node for reading
								shared_lock nodeReadLock(node.getLock());
								
								// Check if newest header doesn't have a higher total difficulty than the node
								if(this->headers.back().getTotalDifficulty() <= node.getTotalDifficulty()) {
								
									// Unlock node read lock
									nodeReadLock.unlock();
									
									// Set ban to true
									ban = true;
									
									// Break
									break;
								}
							}
							
							// Check if no blocks can be requested
							if(this->headers.back().getHeight() == syncedHeaderIndex) {
							
								// Set ban to true
								ban = true;
								
								// Break
								break;
							}
							
							// Check if transaction hash set is needed
							if(this->headers.back().getHeight() - syncedHeaderIndex > Consensus::CUT_THROUGH_HORIZON) {
							
								// Get transaction hash set height
								const uint64_t transactionHashSetHeight = SaturateMath::subtract(this->headers.back().getHeight(), Consensus::STATE_SYNC_HEIGHT_THRESHOLD);
								
								// Check if header at the transaction hash set height is known
								if(this->headers.getLeaf(transactionHashSetHeight)) {
								
									// Set number of reorgs during headers sync to zero
									numberOfReorgsDuringHeadersSync = 0;
								
									{
										// Lock for writing
										lock_guard writeLock(lock);
									
										// Set syncing state to requesting transaction hash sewt
										syncingState = SyncingState::REQUESTING_TRANSACTION_HASH_SET;
									}
								}
								
								// Otherwise
								else {
								
									// Remove all headers
									this->headers.clear();
									
									// Add genesis block header to list of known headers
									this->headers.appendLeaf(Consensus::GENESIS_BLOCK_HEADER);
									
									// Set synced header index to the newest known header
									syncedHeaderIndex = this->headers.back().getHeight();
									
									// Check if not at the max number of reorgs during headers sync
									if(numberOfReorgsDuringHeadersSync != INT_MAX) {
									
										// Increment number of reorgs during headers sync
										++numberOfReorgsDuringHeadersSync;
									}
									
									{
										// Lock for writing
										lock_guard writeLock(lock);
										
										// Set syncing state to requesting headers
										syncingState = SyncingState::REQUESTING_HEADERS;
									}
								}
							}
							
							// Otherwise
							else {
							
								// Set number of reorgs during headers sync to zero
								numberOfReorgsDuringHeadersSync = 0;
								
								{
									// Lock for writing
									lock_guard writeLock(lock);
									
									// Set syncing state to requesting block
									syncingState = SyncingState::REQUESTING_BLOCK;
								}
							}
						}
					}
					
					// Otherwise
					else {
					
						// Unlock read lock
						readLock.unlock();
						
						// Set ban to true
						ban = true;
					}
				}
				
				// Otherwise
				else {
				
					// Set ban to true
					ban = true;
				}
			
				// Break
				break;
			
			// Get block
			case Message::Type::GET_BLOCK:
			
				// Check if shake was received
				if(communicationState > CommunicationState::HAND_SENT) {
					
					// Create error message
					const vector errorMessage = Message::createErrorMessage();
					
					{
						// Lock for writing
						lock_guard writeLock(lock);
						
						// Check if messages can be sent
						if(numberOfMessagesSent < MAXIMUM_NUMBER_OF_MESSAGES_SENT_PER_INTERVAL / 2) {
						
							// Append error message to write buffer
							writeBuffer.insert(writeBuffer.cend(), errorMessage.cbegin(), errorMessage.cend());
							
							// Increment number of messages sent
							++numberOfMessagesSent;
						}
					}
				}
				
				// Otherwise
				else {
				
					// Set ban to true
					ban = true;
				}
			
				// Break
				break;
			
			// Block
			case Message::Type::BLOCK:
			
				// Check if shake was received
				if(communicationState > CommunicationState::HAND_SENT) {
				
					// Lock for reading
					shared_lock readLock(lock);
				
					// Check if block was requested
					if(syncingState == SyncingState::REQUESTED_BLOCK) {
					
						// Unlock read lock
						readLock.unlock();
						
						// Remove the current sync response required time
						currentSyncResponseRequiredTime.reset();
						
						// Set number of reorgs during block sync to zero
						numberOfReorgsDuringBlockSync = 0;
						
						// Move read buffer and empty it
						vector<uint8_t> buffer;
						readBuffer.swap(buffer);
						
						// Set response or request erased to true
						responseOrRequestErased = true;
						
						// Check if more requests or responses exist
						if(buffer.size() > Message::MESSAGE_HEADER_LENGTH + messagePayloadLength) {
						
							// Append requests or responses to the read buffer
							readBuffer.insert(readBuffer.cend(), buffer.cbegin() + Message::MESSAGE_HEADER_LENGTH + messagePayloadLength, buffer.cend());
						}
						
						{
							// Lock for writing
							lock_guard writeLock(lock);
							
							// Set syncing state to processing block
							syncingState = SyncingState::PROCESSING_BLOCK;
						}
						
						// Create worker operation to process the block
						workerOperation = async(launch::async, &Peer::processBlock, this, move(buffer));
					}
					
					// Otherwise
					else {
					
						// Unlock read lock
						readLock.unlock();
						
						// Set ban to true
						ban = true;
					}
				}
				
				// Otherwise
				else {
				
					// Set ban to true
					ban = true;
				}
			
				// Break
				break;
			
			// Get compact block
			case Message::Type::GET_COMPACT_BLOCK:
			
				// Check if shake was received
				if(communicationState > CommunicationState::HAND_SENT) {
					
					// Create error message
					const vector errorMessage = Message::createErrorMessage();
					
					{
						// Lock for writing
						lock_guard writeLock(lock);
						
						// Check if messages can be sent
						if(numberOfMessagesSent < MAXIMUM_NUMBER_OF_MESSAGES_SENT_PER_INTERVAL / 2) {
						
							// Append error message to write buffer
							writeBuffer.insert(writeBuffer.cend(), errorMessage.cbegin(), errorMessage.cend());
							
							// Increment number of messages sent
							++numberOfMessagesSent;
						}
					}
				}
				
				// Otherwise
				else {
				
					// Set ban to true
					ban = true;
				}
			
				// Break
				break;
			
			// Compact block
			case Message::Type::COMPACT_BLOCK:
			
				// Check if shake was received
				if(communicationState > CommunicationState::HAND_SENT) {
				
					// Initialize header
					optional<Header> header;
					
					// Try
					try {
					
						// Read compact block message
						header = Message::readCompactBlockMessage(readBuffer);
					}
		
					// Catch errors
					catch(...) {
					
						// Set ban to true
						ban = true;
						
						// Break
						break;
					}
					
					// Initialize total difficulty changed and total difficulty increased
					bool totalDifficultyChanged;
					bool totalDifficultyIncreased;
					
					{
						// Lock for writing
						lock_guard writeLock(lock);
						
						// Set total difficulty changed to if the total difficulty changed
						totalDifficultyChanged = totalDifficulty != header.value().getTotalDifficulty();
						
						// Set total difficulty increased to if the total difficulty increased
						totalDifficultyIncreased = totalDifficulty < header.value().getTotalDifficulty();
				
						// Set total difficulty to the header's total difficulty
						totalDifficulty = header.value().getTotalDifficulty();
					}
					
					// Set last ping time to now
					lastPingTime = chrono::steady_clock::now();
					
					// Check if total difficulty changed
					if(totalDifficultyChanged) {
					
						// Set total difficulty last changed time to now
						totalDifficultyLastChangedTime = chrono::steady_clock::now();
					
						// Notify peers that event occurred
						eventOccurred.notify_one();
					}
					
					// Check if total difficulty increased
					if(totalDifficultyIncreased) {
					
						// Set increment number of messages received to false
						incrementNumberOfMessagesReceived = false;
					}
				}
				
				// Otherwise
				else {
				
					// Set ban to true
					ban = true;
				}
			
				// Break
				break;
			
			// Stem transaction
			case Message::Type::STEM_TRANSACTION:
			
				// Check if shake was received
				if(communicationState > CommunicationState::HAND_SENT) {
				
					// Initialize stem transaction message
					vector<uint8_t> stemTransactionMessage;
					
					// Try
					try {
					
						// Read stem transaction message
						stemTransactionMessage = Message::readStemTransactionMessage(readBuffer, protocolVersion);
					}
		
					// Catch errors
					catch(...) {
					
						// Set ban to true
						ban = true;
						
						// Break
						break;
					}
					
					{
						// Lock for writing
						lock_guard writeLock(lock);
						
						// Append stem transaction message to write buffer
						writeBuffer.insert(writeBuffer.cend(), stemTransactionMessage.cbegin(), stemTransactionMessage.cend());
					}
					
					// Set increment number of messages received to false
					incrementNumberOfMessagesReceived = false;
				}
				
				// Otherwise
				else {
				
					// Set ban to true
					ban = true;
				}
			
				// Break
				break;
			
			// Transaction
			case Message::Type::TRANSACTION:
			
				// Check if shake was received
				if(communicationState > CommunicationState::HAND_SENT) {
				
					// Initialize transaction
					optional<Transaction> transaction;
					
					// Try
					try {
					
						// Read transaction message
						transaction = Message::readTransactionMessage(readBuffer, protocolVersion);
					}
		
					// Catch errors
					catch(...) {
					
						// Set ban to true
						ban = true;
						
						// Break
						break;
					}
					
					// Check if protocol version is at least four and the transaction's fees are less than the node's required fees
					if(protocolVersion >= 4 && transaction.value().getFees() < transaction.value().getRequiredFees(node.getBaseFee())) {
					
						// Set ban to true
						ban = true;
						
						// Break
						break;
					}
					
					// Try
					try {
					
						// Add transaction to node's mempool
						node.addToMempool(move(transaction.value()));
					}
					
					// Catch errors
					catch(...) {
					
					}
					
					// Set increment number of messages received to false
					incrementNumberOfMessagesReceived = false;
				}
				
				// Otherwise
				else {
				
					// Set ban to true
					ban = true;
				}
			
				// Break
				break;
			
			// Transaction hash set request
			case Message::Type::TRANSACTION_HASH_SET_REQUEST:
			
				// Check if shake was received
				if(communicationState > CommunicationState::HAND_SENT) {
					
					// Create error message
					const vector errorMessage = Message::createErrorMessage();
					
					{
						// Lock for writing
						lock_guard writeLock(lock);
						
						// Check if messages can be sent
						if(numberOfMessagesSent < MAXIMUM_NUMBER_OF_MESSAGES_SENT_PER_INTERVAL / 2) {
						
							// Append error message to write buffer
							writeBuffer.insert(writeBuffer.cend(), errorMessage.cbegin(), errorMessage.cend());
							
							// Increment number of messages sent
							++numberOfMessagesSent;
						}
					}
				}
				
				// Otherwise
				else {
				
					// Set ban to true
					ban = true;
				}
				
				// Break
				break;
			
			// Transaction hash set archive
			case Message::Type::TRANSACTION_HASH_SET_ARCHIVE:
			
				// Check if shake was received
				if(communicationState > CommunicationState::HAND_SENT) {
				
					// Lock for reading
					shared_lock readLock(lock);
				
					// Check if transaction hash set was requested
					if(syncingState == SyncingState::REQUESTED_TRANSACTION_HASH_SET) {
					
						// Unlock read lock
						readLock.unlock();
						
						// Check if transaction has set response hasn't been received
						if(!transactionHashSetResponseReceived) {
						
							// Set transaction hash set response received to true
							transactionHashSetResponseReceived = true;
							
							// Set current response required time
							currentSyncResponseRequiredTime = chrono::steady_clock::now() + GET_TRANSACTION_HASH_SET_ATTACHMENT_REQUIRED_DURATION;
						}
						
						// Initialize transaction hash set archive components
						tuple<array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH>, uint64_t, uint64_t> transactionHashSetArchiveComponents;
					
						// Try
						try {
						
							// Read transaction hash set archive message
							transactionHashSetArchiveComponents = Message::readTransactionHashSetArchiveMessage(readBuffer);
						}
			
						// Catch errors
						catch(...) {
						
							// Set ban to true
							ban = true;
							
							// Break
							break;
						}
						
						// Get transaction hash set archive block hash, height, and attachment length from transaction hash set archive components
						const array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH> &transactionHashSetArchiveBlockHash = get<0>(transactionHashSetArchiveComponents);
						const uint64_t &transactionHashSetArchiveHeight = get<1>(transactionHashSetArchiveComponents);
						const vector<uint8_t>::size_type &transactionHashSetArchiveAttachmentLength = get<2>(transactionHashSetArchiveComponents);
						
						// Get header at the transaction hash set archive height
						const Header *header = headers.getLeaf(transactionHashSetArchiveHeight);
					
						// Check if header isn't known
						if(!header) {
						
							// Set ban to true
							ban = true;
							
							// Break
							break;
						}
						
						// Check if header's block hash is different
						if(memcmp(header->getBlockHash().data(), transactionHashSetArchiveBlockHash.data(), transactionHashSetArchiveBlockHash.size())) {
						
							// Set ban to true
							ban = true;
							
							// Break
							break;
						}
						
						// Check if transaction hash set is under the horizon
						if(headers.back().getHeight() - transactionHashSetArchiveHeight > Consensus::CUT_THROUGH_HORIZON) {
						
							// Set ban to true
							ban = true;
							
							// Break
							break;
						}
						
						// Check if transaction hash set archive attachment length is too big
						if(transactionHashSetArchiveAttachmentLength > numeric_limits<vector<uint8_t>::size_type>::max() - Message::MESSAGE_HEADER_LENGTH - messagePayloadLength) {
						
							// Set ban to true
							ban = true;
							
							// Break
							break;
						}
						
						// Set message attachment length to the transaction hash set attachment length
						messageAttachmentLength = transactionHashSetArchiveAttachmentLength;
						
						// Check if request contains the transaction hash set archive attachment
						if(readBuffer.size() >= Message::MESSAGE_HEADER_LENGTH + messagePayloadLength + transactionHashSetArchiveAttachmentLength) {
						
							// Remove the current sync response required time
							currentSyncResponseRequiredTime.reset();
							
							// Move read buffer and empty it
							vector<uint8_t> buffer;
							readBuffer.swap(buffer);
							
							// Set response or request erased to true
							responseOrRequestErased = true;
							
							// Check if more requests or responses exist
							if(buffer.size() > Message::MESSAGE_HEADER_LENGTH + messagePayloadLength + messageAttachmentLength) {
							
								// Append requests or responses to the read buffer
								readBuffer.insert(readBuffer.cend(), buffer.cbegin() + Message::MESSAGE_HEADER_LENGTH + messagePayloadLength + messageAttachmentLength, buffer.cend());
							}
							
							{
								// Lock for writing
								lock_guard writeLock(lock);
								
								// Set syncing state to processing transaction hash set
								syncingState = SyncingState::PROCESSING_TRANSACTION_HASH_SET;
							}
							
							// Create worker operation to process the transaction hash set archive
							workerOperation = async(launch::async, &Peer::processTransactionHashSetArchive, this, move(buffer), Message::MESSAGE_HEADER_LENGTH + messagePayloadLength, transactionHashSetArchiveAttachmentLength, header);
						}
					}
					
					// Otherwise
					else {
					
						// Unlock read lock
						readLock.unlock();
						
						// Set ban to true
						ban = true;
					}
				}
				
				// Otherwise
				else {
				
					// Set ban to true
					ban = true;
				}
			
				// Break
				break;
			
			// Ban reason
			case Message::Type::BAN_REASON:
			
				// Return false
				return false;
			
				// Break
				break;
			
			// Get transaction
			case Message::Type::GET_TRANSACTION:
			
				// Check if shake was received
				if(communicationState > CommunicationState::HAND_SENT) {
					
					// Create error message
					const vector errorMessage = Message::createErrorMessage();
					
					{
						// Lock for writing
						lock_guard writeLock(lock);
						
						// Check if messages can be sent
						if(numberOfMessagesSent < MAXIMUM_NUMBER_OF_MESSAGES_SENT_PER_INTERVAL / 2) {
						
							// Append error message to write buffer
							writeBuffer.insert(writeBuffer.cend(), errorMessage.cbegin(), errorMessage.cend());
							
							// Increment number of messages sent
							++numberOfMessagesSent;
						}
					}
				}
				
				// Otherwise
				else {
				
					// Set ban to true
					ban = true;
				}
			
				// Break
				break;
			
			// Transaction kernel
			case Message::Type::TRANSACTION_KERNEL:
			
				// Check if shake was received
				if(communicationState > CommunicationState::HAND_SENT) {
				
					// Try
					try {
					
						// Read transaction kernel message
						Message::readTransactionKernelMessage(readBuffer);
					}
		
					// Catch errors
					catch(...) {
					
						// Set ban to true
						ban = true;
					}
				}
				
				// Otherwise
				else {
				
					// Set ban to true
					ban = true;
				}
			
				// Break
				break;
			
			// Tor address
			case Message::Type::TOR_ADDRESS:
			
				// Check if shake was received
				if(communicationState > CommunicationState::HAND_SENT) {
				
					// Try
					try {
					
						// Read Tor address message
						Message::readTorAddressMessage(readBuffer);
					}
		
					// Catch errors
					catch(...) {
					
						// Set ban to true
						ban = true;
					}
				}
				
				// Otherwise
				else {
				
					// Set ban to true
					ban = true;
				}
			
				// Break
				break;
			
			// Default
			default:
			
				// Check if shake wasn't received
				if(communicationState == CommunicationState::HAND_SENT) {
				
					// Set ban to true
					ban = true;
				}
				
				// Break
				break;
		}
		
		// Check if banning
		if(ban) {
		
			{
				// Lock node for writing
				lock_guard nodeWriteLock(node.getLock());
				
				// Add self to node's list of banned peers
				node.addBannedPeer(identifier);
			}
			
			// Return false
			return false;
		}
		
		// Check if response or request wasn't erased
		if(!responseOrRequestErased) {
		
			// Check if request or response doesn't contain the payload and the attachment
			if(readBuffer.size() < Message::MESSAGE_HEADER_LENGTH + messagePayloadLength + messageAttachmentLength) {
			
				// Break
				break;
			}
			
			// Remove request or response from read buffer
			readBuffer.erase(readBuffer.cbegin(), readBuffer.cbegin() + Message::MESSAGE_HEADER_LENGTH + messagePayloadLength + messageAttachmentLength);
			
			// Check if read buffer is empty
			if(readBuffer.empty()) {
			
				// Free all memory allocated by the read buffer
				vector<uint8_t>().swap(readBuffer);
			}
		}
		
		// Check if incrementing number of messages received and not at the max number of messages received
		if(incrementNumberOfMessagesReceived && numberOfMessagesReceived != INT_MAX) {
		
			// Increment number of messages received
			++numberOfMessagesReceived;
		}
	}
	
	// Return true
	return true;
}

// Get locator headers block hashes
list<array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH>> Peer::getLocatorHeadersBlockHashes() const {

	// Initialize locator headers block hashes
	list<array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH>> locatorHeadersBlockHashes;
	
	// Loop through recent heights
	for(uint64_t height = headers.back().getHeight(); height > 0 && locatorHeadersBlockHashes.size() < static_cast<list<array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH>>::size_type>(Message::MAXIMUM_NUMBER_OF_BLOCK_HASHES - 1); height = SaturateMath::subtract(height, static_cast<uint64_t>(1) << locatorHeadersBlockHashes.size())) {
	
		// Check if header at height is known
		const Header *header = headers.getLeaf(height);
		if(header) {
		
			// Append header's block hash to the list
			locatorHeadersBlockHashes.push_back(header->getBlockHash());
		}
		
		// Otherwise
		else {
		
			// Break
			break;
		}
	}
	
	// Append genesis block header's block hash to the list
	locatorHeadersBlockHashes.push_back(Consensus::GENESIS_BLOCK_HEADER.getBlockHash());
	
	// Return locator headers block hashes
	return locatorHeadersBlockHashes;
}

// Process headers
bool Peer::processHeaders(list<Header> &&headers) {
	
	// Set first header to true
	bool firstHeader = true;
	
	// Initialize previous header height
	uint64_t previousHeaderHeight;
	
	// Go through all headers
	for(Header &header : headers) {
	
		// Check if first header
		if(firstHeader) {
		
			// Set first header to false
			firstHeader = false;
		
			// Check if previous header is newer than all known headers
			if(header.getHeight() - 1 > this->headers.back().getHeight()) {
			
				// Return false
				return false;
			}
		}
		
		// Otherwise
		else {
		
			// Check if header doesn't come after the previous header
			if(previousHeaderHeight == UINT64_MAX || header.getHeight() != previousHeaderHeight + 1) {
			
				// Return false
				return false;
			}
		}
		
		// Set previous header height to the header's height
		previousHeaderHeight = header.getHeight();

		// Check if header is known
		if(this->headers.getLeaf(header.getHeight())) {
		
			// Get known header
			const Header *knownHeader = this->headers.getLeaf(header.getHeight());
			
			// Check if header is the same as the known header
			if(header == *knownHeader) {
				
				// Remove all known headers past the header
				this->headers.rewindToNumberOfLeaves(header.getHeight() + 1);
				
				// Set synced header index to the newest known header if less than its self
				syncedHeaderIndex = min(this->headers.back().getHeight(), syncedHeaderIndex);
				
				// Check if not at the max number of reorgs during headers sync
				if(numberOfReorgsDuringHeadersSync != INT_MAX) {
				
					// Increment number of reorgs during headers sync
					++numberOfReorgsDuringHeadersSync;
				}
				
				// Go to the next header
				continue;
			}
		}
		
		// Check if previous header is older than all known headers
		if(header.getHeight() - 1 < this->headers.front().getHeight()) {
		
			// Remove all headers
			this->headers.clear();
			
			// Add genesis block header to list of known headers
			this->headers.appendLeaf(Consensus::GENESIS_BLOCK_HEADER);
			
			// Set synced header index to the newest known header
			syncedHeaderIndex = this->headers.back().getHeight();
			
			// Check if not at the max number of reorgs during headers sync
			if(numberOfReorgsDuringHeadersSync != INT_MAX) {
			
				// Increment number of reorgs during headers sync
				++numberOfReorgsDuringHeadersSync;
			}
		}
		
		// Check if previous header is newer than all known headers
		if(header.getHeight() - 1 > this->headers.back().getHeight()) {
		
			// Go to the next header
			continue;
		}
		
		// Get previous header
		const Header *previousHeader = this->headers.getLeaf(header.getHeight() - 1);
		
		// Get previous header's root
		const array root = this->headers.getRootAtNumberOfLeaves(previousHeader->getHeight() + 1);
		
		// Get previous header's block hash
		const array blockHash = previousHeader->getBlockHash();
		
		// Check if header's previous header isn't the known previous header
		if(memcmp(header.getPreviousHeaderRoot(), root.data(), root.size()) || memcmp(header.getPreviousBlockHash(), blockHash.data(), blockHash.size())) {
		
			// Check if previous block is the genesis block
			if(previousHeader->getHeight() == Consensus::GENESIS_BLOCK_HEADER.getHeight()) {
			
				// Return false
				return false;
			}
			
			// Try
			try {
		
				// Remove all known headers at the previous header
				this->headers.rewindToNumberOfLeaves(previousHeader->getHeight());
			}
			
			// Catch errors
			catch(...) {
			
				// Remove all headers
				this->headers.clear();
				
				// Add genesis block header to list of known headers
				this->headers.appendLeaf(Consensus::GENESIS_BLOCK_HEADER);
			}
			
			// Set synced header index to the newest known header if less than its self
			syncedHeaderIndex = min(this->headers.back().getHeight(), syncedHeaderIndex);
			
			// Check if not at the max number of reorgs during headers sync
			if(numberOfReorgsDuringHeadersSync != INT_MAX) {
			
				// Increment number of reorgs during headers sync
				++numberOfReorgsDuringHeadersSync;
			}
			
			// Go to the next header
			continue;
		}
		
		// Check if header doesn't come after the previous header
		if(header.getHeight() != previousHeader->getHeight() + 1 || header.getTimestamp() <= previousHeader->getTimestamp() || header.getTotalDifficulty() <= previousHeader->getTotalDifficulty()) {
		
			// Return false
			return false;
		}
		
		// Get number of outputs
		const uint64_t numberOfOutputs = SaturateMath::subtract(MerkleMountainRange<Output>::getNumberOfLeavesAtSize(header.getOutputMerkleMountainRangeSize()), MerkleMountainRange<Output>::getNumberOfLeavesAtSize(previousHeader->getOutputMerkleMountainRangeSize()));
		
		// Get number of kernels
		const uint64_t numberOfKernels = SaturateMath::subtract(MerkleMountainRange<Kernel>::getNumberOfLeavesAtSize(header.getKernelMerkleMountainRangeSize()), MerkleMountainRange<Kernel>::getNumberOfLeavesAtSize(previousHeader->getKernelMerkleMountainRangeSize()));
		
		// Check if number of outputs or number of kernels is invalid
		if(!numberOfOutputs || !numberOfKernels) {
		
			// Return false
			return false;
		}
		
		// Get weight for the number of outputs and kernels
		const uint64_t weight = Consensus::getBlockWeight(0, numberOfOutputs, numberOfKernels);
		
		// Check if weight is invalid
		if(weight > Consensus::MAXIMUM_BLOCK_WEIGHT) {
		
			// Return false
			return false;
		}
		
		// Get difficulty
		const uint64_t difficulty = header.getTotalDifficulty() - previousHeader->getTotalDifficulty();
		
		// Check if header's difficulty is less than the difficulty
		if(Consensus::getHeaderDifficulty(header) < difficulty) {
		
			// Return false
			return false;
		}
		
		// Check if not enough headers are known to verify the header's difficulty or verify coinbase maturity
		if(this->headers.front().getHeight() != Consensus::GENESIS_BLOCK_HEADER.getHeight() && (previousHeader->getHeight() - this->headers.front().getHeight() < Consensus::DIFFICULTY_ADJUSTMENT_WINDOW || header.getHeight() - this->headers.front().getHeight() < Consensus::COINBASE_MATURITY)) {
		
			// Remove all headers
			this->headers.clear();
			
			// Add genesis block header to list of known headers
			this->headers.appendLeaf(Consensus::GENESIS_BLOCK_HEADER);
			
			// Set synced header index to the newest known header
			syncedHeaderIndex = this->headers.back().getHeight();
			
			// Check if not at the max number of reorgs during headers sync
			if(numberOfReorgsDuringHeadersSync != INT_MAX) {
			
				// Increment number of reorgs during headers sync
				++numberOfReorgsDuringHeadersSync;
			}
			
			// Go to the next header
			continue;
		}
		
		// Initialize secondary scaling sum to zero
		uint64_t secondaryScalingSum = 0;
		
		// Initialize difficulty sum to zero
		uint64_t difficultySum = 0;
		
		// Initialize number of C29 headers to zero
		uint64_t numberOfC29Headers = 0;
		
		// Go through all previous headers in the difficulty adjustment window
		for(uint64_t i = 0; i < Consensus::DIFFICULTY_ADJUSTMENT_WINDOW; ++i) {
		
			// Add header's secondary scaling to the sum
			secondaryScalingSum += (i <= previousHeader->getHeight()) ? this->headers.getLeaf(previousHeader->getHeight() - i)->getSecondaryScaling() : Consensus::GENESIS_BLOCK_HEADER.getSecondaryScaling();
			
			// Check if previous header exists
			if(i <= previousHeader->getHeight()) {
			
				// Check if header before the previous header exists
				if(i + 1 <= previousHeader->getHeight()) {
				
					// Add header's difficulty to the difficulty sum
					difficultySum += this->headers.getLeaf(previousHeader->getHeight() - i)->getTotalDifficulty() - this->headers.getLeaf(previousHeader->getHeight() - (i + 1))->getTotalDifficulty();
				}
				
				// Otherwise
				else {
				
					// Add header's difficulty to the difficulty sum
					difficultySum += this->headers.getLeaf(previousHeader->getHeight() - i)->getTotalDifficulty();
				}
			}
			
			// Otherwise
			else {
			
				// Add header's difficulty to the difficulty sum
				difficultySum += previousHeader->getTotalDifficulty() - (previousHeader->getHeight() ? this->headers.getLeaf(previousHeader->getHeight() - 1)->getTotalDifficulty() : 0);
			}
			
			// Check if header uses C29 proof of work
			if(((i <= previousHeader->getHeight()) ? this->headers.getLeaf(previousHeader->getHeight() - i)->getEdgeBits() : Consensus::GENESIS_BLOCK_HEADER.getEdgeBits()) == Consensus::C29_EDGE_BITS) {
			
				// Increment the number of C29 headers
				++numberOfC29Headers;
			}
		}
		
		// Get target C29 ratio
		const uint64_t targetC29Ratio = Consensus::getC29ProofOfWorkRatio(header.getHeight());
		
		// Get target number of C29 headers
		const uint64_t targetNumberOfC29Headers = Consensus::DIFFICULTY_ADJUSTMENT_WINDOW * targetC29Ratio;
		
		// Get C29 headers adjustment
		const uint64_t c29HeadersAdjustment = Common::clamp(Common::damp(numberOfC29Headers * 100, targetNumberOfC29Headers, Consensus::C29_HEADERS_ADJUSTMENT_DAMP_FACTOR), targetNumberOfC29Headers, Consensus::C29_HEADERS_ADJUSTMENT_CLAMP_FACTOR);
		
		// Get target secondary scaling
		const uint32_t targetSecondaryScaling = max(secondaryScalingSum * targetC29Ratio / max(static_cast<uint64_t>(1), c29HeadersAdjustment), static_cast<uint64_t>(Consensus::MINIMUM_SECONDARY_SCALING));
		
		// Check if secondary scaling isn't correct
		if(header.getSecondaryScaling() != targetSecondaryScaling) {
		
			// Return false
			return false;
		}
		
		// Set number of missing headers
		const uint64_t numberOfMissingHeaders = (previousHeader->getHeight() < Consensus::DIFFICULTY_ADJUSTMENT_WINDOW) ? Consensus::DIFFICULTY_ADJUSTMENT_WINDOW - previousHeader->getHeight() : 0;
		
		// Get last timestamp delta
		const chrono::seconds lastTimestampDelta = (previousHeader->getHeight() != Consensus::GENESIS_BLOCK_HEADER.getHeight()) ? chrono::duration_cast<chrono::seconds>(previousHeader->getTimestamp() - this->headers.getLeaf(previousHeader->getHeight() - 1)->getTimestamp()) : Consensus::BLOCK_TIME;
		
		// Initialize window start timestamp
		chrono::time_point<chrono::system_clock> windowStartTimestamp;
		
		// Check if headers are missing from the window
		if(numberOfMissingHeaders) {
		
			// Check if window start timestamp won't underflow
			if(lastTimestampDelta * numberOfMissingHeaders <= chrono::duration_cast<chrono::seconds>(Consensus::GENESIS_BLOCK_HEADER.getTimestamp().time_since_epoch())) {
			
				// Set window start timestamp to the timestamp of the first missing block in the window
				windowStartTimestamp = Consensus::GENESIS_BLOCK_HEADER.getTimestamp() - lastTimestampDelta * numberOfMissingHeaders;
			}
			
			// Otherwise
			else {
			
				// Set window start timestamp to zero
				windowStartTimestamp = chrono::time_point<chrono::system_clock>(chrono::seconds(0));
			}
		}
		
		// Otherwise
		else {
		
			// Set window start timestamp to the timestamp of the first header in the window
			windowStartTimestamp = this->headers.getLeaf(previousHeader->getHeight() - Consensus::DIFFICULTY_ADJUSTMENT_WINDOW)->getTimestamp();
		}
		
		// Get window duration
		const chrono::seconds windowDuration = chrono::duration_cast<chrono::seconds>(previousHeader->getTimestamp() - windowStartTimestamp);
		
		// Get window duration adjustment
		const uint64_t windowDurationAdjustment = Common::clamp(Common::damp(windowDuration.count(), Consensus::DIFFICULTY_ADJUSTMENT_WINDOW * Consensus::BLOCK_TIME.count(), Consensus::WINDOW_DURATION_ADJUSTMENT_DAMP_FACTOR), Consensus::DIFFICULTY_ADJUSTMENT_WINDOW * Consensus::BLOCK_TIME.count(), Consensus::WINDOW_DURATION_ADJUSTMENT_CLAMP_FACTOR);
		
		// Get target difficulty
		const uint64_t targetDifficulty = max(Consensus::MINIMUM_DIFFICULTY, difficultySum * Consensus::BLOCK_TIME.count() / windowDurationAdjustment);
		
		// Check if difficulty isn't correct
		if(difficulty != targetDifficulty) {
		
			// Return false
			return false;
		}
		
		// Check if header is known
		if(this->headers.getLeaf(header.getHeight())) {
		
			// Get known header
			const Header *knownHeader = this->headers.getLeaf(header.getHeight());
			
			// Check if header isn't the same as the known header
			if(header != *knownHeader) {
			
				// Remove all known headers at the header
				this->headers.rewindToNumberOfLeaves(header.getHeight());
				
				// Set synced header index to the newest known header if less than its self
				syncedHeaderIndex = min(this->headers.back().getHeight(), syncedHeaderIndex);
				
				// Add header to the list of known headers
				this->headers.appendLeaf(move(header));
			}
			
			// Otherwise
			else {
			
				// Remove all known headers past the header
				this->headers.rewindToNumberOfLeaves(header.getHeight() + 1);
				
				// Set synced header index to the newest known header if less than its self
				syncedHeaderIndex = min(this->headers.back().getHeight(), syncedHeaderIndex);
			}
			
			// Check if not at the max number of reorgs during headers sync
			if(numberOfReorgsDuringHeadersSync != INT_MAX) {
			
				// Increment number of reorgs during headers sync
				++numberOfReorgsDuringHeadersSync;
			}
		}
		
		// Otherwise
		else {
		
			// Add header to the list of known headers
			this->headers.appendLeaf(move(header));
		}
	}
	
	// Return true
	return true;
}

// Process transaction hash set archive
bool Peer::processTransactionHashSetArchive(vector<uint8_t> &&buffer, const vector<uint8_t>::size_type transactionHashSetArchiveAttachmentIndex, const vector<uint8_t>::size_type transactionHashSetArchiveAttachmentLength, const Header *transactionHashSetArchiveHeader) {

	// Check if creating source from the transaction hash set archive attactment failed
	unique_ptr<zip_source_t, decltype(&zip_source_free)> source(zip_source_buffer_create(&buffer[transactionHashSetArchiveAttachmentIndex], transactionHashSetArchiveAttachmentLength, 0, nullptr), zip_source_free);
	if(!source) {
	
		// Return false
		return false;
	}
	
	// Check if stopping read and write or is closing
	if(stopReadAndWrite.load() || Common::isClosing()) {
	
		// Return true
		return true;
	}
	
	// Check if opening source as a ZIP archive failed
	unique_ptr<zip_t, decltype(&zip_discard)> zip(zip_open_from_source(source.get(), ZIP_CHECKCONS | ZIP_RDONLY, nullptr), zip_discard);
	if(!zip) {
	
		// Return false
		return false;	
	}
	
	// Release source
	source.release();
	
	// Check if stopping read and write or is closing
	if(stopReadAndWrite.load() || Common::isClosing()) {
	
		// Return true
		return true;
	}
	
	// Initialize kernels
	MerkleMountainRange<Kernel> kernels;
	
	// Try
	try {
	
		// Read kernels from the ZIP archive
		kernels = MerkleMountainRange<Kernel>::createFromZip(zip.get(), protocolVersion, "kernel/pmmr_data.bin", "kernel/pmmr_hash.bin");
		
		// Check if stopping read and write or is closing
		if(stopReadAndWrite.load() || Common::isClosing()) {
		
			// Return true
			return true;
		}
		
		// Rewind kernels to the transaction hash set archive header
		kernels.rewindToSize(transactionHashSetArchiveHeader->getKernelMerkleMountainRangeSize());
		
		// mwc-node doesn't check existing kernels' coinbase maturity, lock height, and NRD header version
	}
	
	// Catch errors
	catch(...) {
	
		// Return false
		return false;
	}
	
	// Check if stopping read and write or is closing
	if(stopReadAndWrite.load() || Common::isClosing()) {
	
		// Return true
		return true;
	}
	
	// Go through all headers from the transaction hash set archive header to the genesis block header while not stopping read and write and not closing
	for(uint64_t i = transactionHashSetArchiveHeader->getHeight(); i > 0 && !stopReadAndWrite.load() && !Common::isClosing(); --i) {
	
		// Check if header isn't pruned
		const Header *header = headers.getLeaf(i);
		if(header) {
		
			// Check if header's kernel root is invalid
			const array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH> kernelRoot = kernels.getRootAtSize(header->getKernelMerkleMountainRangeSize());
			if(memcmp(header->getKernelRoot(), kernelRoot.data(), kernelRoot.size())) {
			
				// Return false
				return false;
			}
		}
		
		// Otherwise
		else {
		
			// Break
			break;
		}
	}
	
	// Check if stopping read and write or is closing
	if(stopReadAndWrite.load() || Common::isClosing()) {
	
		// Return true
		return true;
	}
	
	// TODO NRD check for floonet
	
	// Get short block hash from the transaction hash set archive header's block hash
	const string shortBlockHash = Common::toHexString(transactionHashSetArchiveHeader->getBlockHash().data(), SHORT_BLOCK_HASH_LENGTH);

	// Initialize outputs and rangeproofs
	MerkleMountainRange<Output> outputs;
	MerkleMountainRange<Rangeproof> rangeproofs;
	
	// Try
	try {
	
		// Read outputs from the ZIP archive
		outputs = MerkleMountainRange<Output>::createFromZip(zip.get(), protocolVersion, "output/pmmr_data.bin", "output/pmmr_hash.bin", "output/pmmr_prun.bin", ("output/pmmr_leaf.bin." + shortBlockHash).c_str());
		
		// Check if stopping read and write or is closing
		if(stopReadAndWrite.load() || Common::isClosing()) {
		
			// Return true
			return true;
		}
		
		// Rewind outputs to the transaction hash set archive header
		outputs.rewindToSize(transactionHashSetArchiveHeader->getOutputMerkleMountainRangeSize());
		
		// Check if stopping read and write or is closing
		if(stopReadAndWrite.load() || Common::isClosing()) {
		
			// Return true
			return true;
		}
		
		// Read rangeproofs from the ZIP archive
		rangeproofs = MerkleMountainRange<Rangeproof>::createFromZip(zip.get(), protocolVersion, "rangeproof/pmmr_data.bin", "rangeproof/pmmr_hash.bin", "rangeproof/pmmr_prun.bin", ("rangeproof/pmmr_leaf.bin." + shortBlockHash).c_str());
		
		// Check if stopping read and write or is closing
		if(stopReadAndWrite.load() || Common::isClosing()) {
		
			// Return true
			return true;
		}
		
		// Rewind rangeproofs to the transaction hash set archive header
		rangeproofs.rewindToSize(transactionHashSetArchiveHeader->getOutputMerkleMountainRangeSize());
	}
	
	// Catch errors
	catch(...) {
	
		// Return false
		return false;
	}
	
	// Check if stopping read and write or is closing
	if(stopReadAndWrite.load() || Common::isClosing()) {
	
		// Return true
		return true;
	}
	
	// Check if transaction hash set archive header's output root is invalid
	const array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH> outputRoot = outputs.getRootAtSize(outputs.getSize());
	if(memcmp(transactionHashSetArchiveHeader->getOutputRoot(), outputRoot.data(), outputRoot.size())) {
	
		// Return false
		return false;
	}
	
	// Check if stopping read and write or is closing
	if(stopReadAndWrite.load() || Common::isClosing()) {
	
		// Return true
		return true;
	}
	
	// Check if transaction hash set archive header's rangeproof root is invalid
	const array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH> rangeproofRoot = rangeproofs.getRootAtSize(rangeproofs.getSize());
	if(memcmp(transactionHashSetArchiveHeader->getRangeproofRoot(), rangeproofRoot.data(), rangeproofRoot.size())) {
	
		// Return false
		return false;
	}
	
	// Check if stopping read and write or is closing
	if(stopReadAndWrite.load() || Common::isClosing()) {
	
		// Return true
		return true;
	}
	
	// Go through all outputs while not stopping read and write and not closing
	for(uint64_t i = 0; i < outputs.getNumberOfLeaves() && !stopReadAndWrite.load() && !Common::isClosing(); ++i) {
	
		// Get output and rangeproof
		const Output *output = outputs.getLeaf(i);
		const Rangeproof *rangeproof = rangeproofs.getLeaf(i);
	
		// Check if output doesn't have a rangeproof or rangeproof doesn't have an output
		if(static_cast<bool>(output) != static_cast<bool>(rangeproof)) {
		
			// Return false
			return false;
		}
		
		// Check if output exists
		if(output) {
		
			// Check if rangeproof is invalid
			if(!secp256k1_bulletproof_rangeproof_verify(Crypto::getSecp256k1Context(), Crypto::getSecp256k1ScratchSpace(), Crypto::getSecp256k1Generators(), rangeproof->getProof(), rangeproof->getLength(), nullptr, &output->getCommitment(), 1, sizeof(uint64_t) * Common::BITS_IN_A_BYTE, &secp256k1_generator_const_h, nullptr, 0)) {
			
				// Return false
				return false;
			}
		}
	}
	
	// Check if stopping read and write or is closing
	if(stopReadAndWrite.load() || Common::isClosing()) {
	
		// Return true
		return true;
	}
	
	// Set outputs and rangeproofs minimum size to the transaction hash set archive header
	outputs.setMinimumSize(transactionHashSetArchiveHeader->getOutputMerkleMountainRangeSize());
	rangeproofs.setMinimumSize(transactionHashSetArchiveHeader->getOutputMerkleMountainRangeSize());
	
	// Check if stopping read and write or is closing
	if(stopReadAndWrite.load() || Common::isClosing()) {
	
		// Return true
		return true;
	}
	
	// Free memory
	Common::freeMemory();
	
	// Check if stopping read and write or is closing
	if(stopReadAndWrite.load() || Common::isClosing()) {
	
		// Return true
		return true;
	}
	
	// Check if verifying kernel sums failed
	if(!Crypto::verifyKernelSums(*transactionHashSetArchiveHeader, kernels, outputs)) {
	
		// Return false
		return false;
	}
	
	// Check if stopping read and write or is closing
	if(stopReadAndWrite.load() || Common::isClosing()) {
	
		// Return true
		return true;
	}
	
	{
		// Lock node and self for writing
		unique_lock nodeWriteLock(node.getLock(), defer_lock);
		unique_lock writeLock(lock, defer_lock);
		
		::lock(nodeWriteLock, writeLock);
		
		// Check if not disconnected
		if(connectionState != ConnectionState::DISCONNECTED) {
		
			// Set node's sync state
			node.setSyncState(move(headers), *transactionHashSetArchiveHeader, move(kernels), move(outputs), move(rangeproofs));
			
			// Set syncing state to not syncing
			syncingState = SyncingState::NOT_SYNCING;
			
			// Unlock node write lock
			nodeWriteLock.unlock();
			
			// Unlock write lock
			writeLock.unlock();
			
			// Notify peers that event occurred
			eventOccurred.notify_one();
		}
	}
	
	// Return true
	return true;
}

// Process block
bool Peer::processBlock(vector<uint8_t > &&buffer) {

	// Initialize block components
	optional<tuple<Header, Block>> blockComponents;
	
	// Try
	try {
	
		// Read block message
		blockComponents = Message::readBlockMessage(buffer, protocolVersion);
	}

	// Catch errors
	catch(...) {
	
		// Return false
		return false;
	}
	
	// Check if stopping read and write or is closing
	if(stopReadAndWrite.load() || Common::isClosing()) {
	
		// Return true
		return true;
	}
	
	// Get header and block from block components
	const Header &header = get<0>(blockComponents.value());
	Block &block = get<1>(blockComponents.value());
	
	// Initialize requested header
	optional<Header> requestedHeader;
	
	// Check if using node headers
	if(useNodeHeaders) {
	
		// Lock node for reading
		shared_lock nodeReadLock(node.getLock());
		
		// Set requested header to the next header
		requestedHeader = *node.getHeaders().getLeaf(syncedHeaderIndex + 1);
	}
	
	// Otherwise
	else {
	
		// Set requested header to the next header
		requestedHeader = *headers.getLeaf(syncedHeaderIndex + 1);
	}
	
	// Check if header doesn't match the requested header
	if(header != requestedHeader.value()) {
	
		// Return false
		return false;
	}
	
	// Check if stopping read and write or is closing
	if(stopReadAndWrite.load() || Common::isClosing()) {
	
		// Return true
		return true;
	}

	// Initialize input commitments
	vector<const secp256k1_pedersen_commitment *> inputCommitments;
	
	// Go through all of the block's inputs while not stopping read and write and not closing
	for(list<Input>::const_iterator i = block.getInputs().cbegin(); i != block.getInputs().cend() && !stopReadAndWrite.load() && !Common::isClosing(); ++i) {
	
		// Get input
		const Input &input = *i;
	
		// Append input's commitment to list of input commitments
		inputCommitments.push_back(&input.getCommitment());
	}
	
	// Check if stopping read and write or is closing
	if(stopReadAndWrite.load() || Common::isClosing()) {
	
		// Return true
		return true;
	}
	
	// Initialize coinbase output commitments
	vector<const secp256k1_pedersen_commitment *> coinbaseOutputCommitments;
	
	// Initialize output commitments
	vector<const secp256k1_pedersen_commitment *> outputCommitments;
	
	// Go through all of the block's outputs while not stopping read and write and not closing
	for(list<Output>::const_iterator i = block.getOutputs().cbegin(); i != block.getOutputs().cend() && !stopReadAndWrite.load() && !Common::isClosing(); ++i) {
	
		// Get output
		const Output &output = *i;
	
		// Check if output has coinbase features
		if(output.getFeatures() == Output::Features::COINBASE) {
		
			// Append output's commitment to list of coinbase output commitments
			coinbaseOutputCommitments.push_back(&output.getCommitment());
		}
		
		// Append output's commitment to list of output commitments
		outputCommitments.push_back(&output.getCommitment());
	}
	
	// Check if stopping read and write or is closing
	if(stopReadAndWrite.load() || Common::isClosing()) {
	
		// Return true
		return true;
	}
	
	// Check if coinbase outputs don't exist
	if(coinbaseOutputCommitments.empty()) {
	
		// Return false
		return false;
	}
	
	// Set fees to zero
	uint64_t fees = 0;
	
	// Initialize coinbase kernel excesses
	vector<const secp256k1_pedersen_commitment *> coinbaseKernelExcesses;
	
	// Initialize kernel excesses
	vector<const secp256k1_pedersen_commitment *> kernelExcesses;
	
	// Go through all of the block's kernels while not stopping read and write and not closing
	for(list<Kernel>::const_iterator i = block.getKernels().cbegin(); i != block.getKernels().cend() && !stopReadAndWrite.load() && !Common::isClosing(); ++i) {
	
		// Get Kernel
		const Kernel &kernel = *i;
	
		// Add kernel's fee to the fees
		fees = SaturateMath::add(fees, kernel.getFee());
		
		// Check if kernel has coinbase features
		if(kernel.getFeatures() == Kernel::Features::COINBASE) {
		
			// Append kernel's excess to list of coinbase kernel excesses
			coinbaseKernelExcesses.push_back(&kernel.getExcess());
		}
		
		// Append kernel's excess to list of kernel excesses
		kernelExcesses.push_back(&kernel.getExcess());
	}
	
	// Check if stopping read and write or is closing
	if(stopReadAndWrite.load() || Common::isClosing()) {
	
		// Return true
		return true;
	}
	
	// Check if coinbase kernels don't exist
	if(coinbaseKernelExcesses.empty()) {
	
		// Return false
		return false;
	}

	// Get coinbase reward at header's height
	const uint64_t coinbaseReward = Consensus::getCoinbaseReward(header.getHeight());
	
	// Get reward as the sum of the coinbase reward and the fees
	const uint64_t reward = SaturateMath::add(coinbaseReward, fees);
	
	// Check if getting commitment for the reward failed
	secp256k1_pedersen_commitment rewardCommitment;
	const uint8_t zeroBlindingFactor[Crypto::SECP256K1_PRIVATE_KEY_LENGTH] = {};
	if(!secp256k1_pedersen_commit(secp256k1_context_no_precomp, &rewardCommitment, zeroBlindingFactor, reward, &secp256k1_generator_const_h, &secp256k1_generator_const_g)) {
	
		// Return false
		return false;
	}
	
	// Check if stopping read and write or is closing
	if(stopReadAndWrite.load() || Common::isClosing()) {
	
		// Return true
		return true;
	}
	
	// Set input coinbase commitments
	const secp256k1_pedersen_commitment *inputCoinbaseCommitments[] = {
	
		// Reward commitment
		&rewardCommitment
	};
	
	// Check if getting coinbase commitments sum failed
	secp256k1_pedersen_commitment coinbaseCommitmentsSum;
	if(!secp256k1_pedersen_commit_sum(secp256k1_context_no_precomp, &coinbaseCommitmentsSum, coinbaseOutputCommitments.data(), coinbaseOutputCommitments.size(), inputCoinbaseCommitments, 1)) {
	
		// Return false
		return false;
	}
	
	// Check if stopping read and write or is closing
	if(stopReadAndWrite.load() || Common::isClosing()) {
	
		// Return true
		return true;
	}
	
	// Check if serializing the coinbase commitments sum failed
	uint8_t serializedCoinbaseCommitmentsSum[Crypto::COMMITMENT_LENGTH];
	if(!secp256k1_pedersen_commitment_serialize(secp256k1_context_no_precomp, serializedCoinbaseCommitmentsSum, &coinbaseCommitmentsSum)) {
	
		// Return false
		return false;
	}
	
	// Check if stopping read and write or is closing
	if(stopReadAndWrite.load() || Common::isClosing()) {
	
		// Return true
		return true;
	}
	
	// Check if getting coinbase kernel excesses sum failed
	secp256k1_pedersen_commitment coinbaseKernelExcessesSum;
	const secp256k1_pedersen_commitment *noExcesses[] = {};
	if(!secp256k1_pedersen_commit_sum(secp256k1_context_no_precomp, &coinbaseKernelExcessesSum, coinbaseKernelExcesses.data(), coinbaseKernelExcesses.size(), noExcesses, 0)) {
	
		// Return false
		return false;
	}
	
	// Check if stopping read and write or is closing
	if(stopReadAndWrite.load() || Common::isClosing()) {
	
		// Return true
		return true;
	}
	
	// Check if serializing the coinbase kernel excesses sum failed
	uint8_t serializedCoinbaseKernelExcessesSum[Crypto::COMMITMENT_LENGTH];
	if(!secp256k1_pedersen_commitment_serialize(secp256k1_context_no_precomp, serializedCoinbaseKernelExcessesSum, &coinbaseKernelExcessesSum)) {
	
		// Return false
		return false;
	}
	
	// Check if stopping read and write or is closing
	if(stopReadAndWrite.load() || Common::isClosing()) {
	
		// Return true
		return true;
	}
	
	// Check if serialized coinbase commitments sum doesn't equal the serialized coinbase kernel excesses sum
	if(memcmp(serializedCoinbaseCommitmentsSum, serializedCoinbaseKernelExcessesSum, sizeof(serializedCoinbaseKernelExcessesSum))) {
	
		// Return false
		return false;
	}
	
	// Check if stopping read and write or is closing
	if(stopReadAndWrite.load() || Common::isClosing()) {
	
		// Return true
		return true;
	}
	
	// Initialize previous header
	optional<Header> previousHeader;
	
	// Check if using node headers
	if(useNodeHeaders) {
	
		// Lock node for reading
		shared_lock nodeReadLock(node.getLock());
		
		// Set previous header to the previous header
		previousHeader = *node.getHeaders().getLeaf(header.getHeight() - 1);
	}
	
	// Otherwise
	else {
	
		// Set previous header to the previous header
		previousHeader = *headers.getLeaf(header.getHeight() - 1);
	}
	
	// Initialize block kernel offset commitment
	secp256k1_pedersen_commitment blockKernelOffsetCommitment;
	
	// Check if header's total kernel offset isn't the same as the previous header's total kernel offset
	if(memcmp(header.getTotalKernelOffset(), previousHeader.value().getTotalKernelOffset(), Crypto::SECP256K1_PRIVATE_KEY_LENGTH)) {
	
		// Check if stopping read and write or is closing
		if(stopReadAndWrite.load() || Common::isClosing()) {
		
			// Return true
			return true;
		}
		
		// Check if header's total kernel offset isn't zero
		if(any_of(header.getTotalKernelOffset(), header.getTotalKernelOffset() + Crypto::SECP256K1_PRIVATE_KEY_LENGTH, [](const uint8_t value) {
	
			// Return if value isn't zero
			return value;
		
		})) {
	
			// Set total kernel offsets
			const uint8_t *totalKernelOffsets[] = {
			
				// Header's total kernel offset
				header.getTotalKernelOffset(),
				
				// Previous header's total kernel offset
				previousHeader.value().getTotalKernelOffset()
			};
			
			// Check if getting block kernel offset failed
			uint8_t blockKernelOffset[Crypto::SECP256K1_PRIVATE_KEY_LENGTH];
			if(!secp256k1_pedersen_blind_sum(secp256k1_context_no_precomp, blockKernelOffset, totalKernelOffsets, any_of(previousHeader.value().getTotalKernelOffset(), previousHeader.value().getTotalKernelOffset() + Crypto::SECP256K1_PRIVATE_KEY_LENGTH, [](const uint8_t value) {
		
				// Return if value isn't zero
				return value;
			
			}) ? 2 : 1, 1)) {
			
				// Return false
				return false;
			}
			
			// Check if stopping read and write or is closing
			if(stopReadAndWrite.load() || Common::isClosing()) {
			
				// Return true
				return true;
			}
			
			// Check if block kernel offset is invalid
			if(!secp256k1_ec_seckey_verify(secp256k1_context_no_precomp, blockKernelOffset)) {
			
				// Return false
				return false;
			}
			
			// Check if stopping read and write or is closing
			if(stopReadAndWrite.load() || Common::isClosing()) {
			
				// Return true
				return true;
			}
			
			// Check if getting commitment for the block kernel offset failed
			if(!secp256k1_pedersen_commit(secp256k1_context_no_precomp, &blockKernelOffsetCommitment, blockKernelOffset, 0, &secp256k1_generator_const_h, &secp256k1_generator_const_g)) {
			
				// Return false
				return false;
			}
			
			// Check if stopping read and write or is closing
			if(stopReadAndWrite.load() || Common::isClosing()) {
			
				// Return true
				return true;
			}
			
			// Append block kernel offset commitment to the list of kernel excesses
			kernelExcesses.push_back(&blockKernelOffsetCommitment);
		}
		
		// Otherwise check if the previous header's total kernel offset isn't zero
		else if(any_of(previousHeader.value().getTotalKernelOffset(), previousHeader.value().getTotalKernelOffset() + Crypto::SECP256K1_PRIVATE_KEY_LENGTH, [](const uint8_t value) {
		
			// Return if value isn't zero
			return value;
		
		})) {
		
			// Set total kernel offsets
			const uint8_t *totalKernelOffsets[] = {
				
				// Previous header's total kernel offset
				previousHeader.value().getTotalKernelOffset()
			};
			
			// Check if getting block kernel offset failed
			uint8_t blockKernelOffset[Crypto::SECP256K1_PRIVATE_KEY_LENGTH];
			if(!secp256k1_pedersen_blind_sum(secp256k1_context_no_precomp, blockKernelOffset, totalKernelOffsets, 1, 0)) {
			
				// Return false
				return false;
			}
			
			// Check if stopping read and write or is closing
			if(stopReadAndWrite.load() || Common::isClosing()) {
			
				// Return true
				return true;
			}
			
			// Check if block kernel offset is invalid
			if(!secp256k1_ec_seckey_verify(secp256k1_context_no_precomp, blockKernelOffset)) {
			
				// Return false
				return false;
			}
			
			// Check if stopping read and write or is closing
			if(stopReadAndWrite.load() || Common::isClosing()) {
			
				// Return true
				return true;
			}
			
			// Check if getting commitment for the block kernel offset failed
			if(!secp256k1_pedersen_commit(secp256k1_context_no_precomp, &blockKernelOffsetCommitment, blockKernelOffset, 0, &secp256k1_generator_const_h, &secp256k1_generator_const_g)) {
			
				// Return false
				return false;
			}
			
			// Check if stopping read and write or is closing
			if(stopReadAndWrite.load() || Common::isClosing()) {
			
				// Return true
				return true;
			}
			
			// Append block kernel offset commitment to the list of kernel excesses
			kernelExcesses.push_back(&blockKernelOffsetCommitment);
		}
	}
	
	// Check if stopping read and write or is closing
	if(stopReadAndWrite.load() || Common::isClosing()) {
	
		// Return true
		return true;
	}
	
	// Check if getting kernel excesses sum failed
	secp256k1_pedersen_commitment kernelExcessesSum;
	if(!secp256k1_pedersen_commit_sum(secp256k1_context_no_precomp, &kernelExcessesSum, kernelExcesses.data(), kernelExcesses.size(), noExcesses, 0)) {
	
		// Return false
		return false;
	}
	
	// Check if stopping read and write or is closing
	if(stopReadAndWrite.load() || Common::isClosing()) {
	
		// Return true
		return true;
	}
	
	// Check if serializing the kernel excesses sum failed
	uint8_t serializedKernelExcessesSum[Crypto::COMMITMENT_LENGTH];
	if(!secp256k1_pedersen_commitment_serialize(secp256k1_context_no_precomp, serializedKernelExcessesSum, &kernelExcessesSum)) {
	
		// Return false
		return false;
	}
	
	// Check if stopping read and write or is closing
	if(stopReadAndWrite.load() || Common::isClosing()) {
	
		// Return true
		return true;
	}
	
	// Initialize coinbase reward commitment
	secp256k1_pedersen_commitment coinbaseRewardCommitment;
	
	// Check if coinbase reward isn't zero
	if(coinbaseReward) {
	
		// Check if getting commitment for the coinbase reward failed
		if(!secp256k1_pedersen_commit(secp256k1_context_no_precomp, &coinbaseRewardCommitment, zeroBlindingFactor, coinbaseReward, &secp256k1_generator_const_h, &secp256k1_generator_const_g)) {
		
			// Return false
			return false;
		}
		
		// Check if stopping read and write or is closing
		if(stopReadAndWrite.load() || Common::isClosing()) {
		
			// Return true
			return true;
		}
		
		// Append coinbase reward commitment to list of input commitments
		inputCommitments.push_back(&coinbaseRewardCommitment);
	}
	
	// Check if getting UTXO commitments sum failed
	secp256k1_pedersen_commitment utxoCommitmentsSum;
	if(!secp256k1_pedersen_commit_sum(secp256k1_context_no_precomp, &utxoCommitmentsSum, outputCommitments.data(), outputCommitments.size(), inputCommitments.data(), inputCommitments.size())) {
	
		// Return false
		return false;
	}
	
	// Check if stopping read and write or is closing
	if(stopReadAndWrite.load() || Common::isClosing()) {
	
		// Return true
		return true;
	}
	
	// Check if serializing the UTXO commitments sum failed
	uint8_t serializedUtxoCommitmentsSum[Crypto::COMMITMENT_LENGTH];
	if(!secp256k1_pedersen_commitment_serialize(secp256k1_context_no_precomp, serializedUtxoCommitmentsSum, &utxoCommitmentsSum)) {
	
		// Return false
		return false;
	}
	
	// Check if stopping read and write or is closing
	if(stopReadAndWrite.load() || Common::isClosing()) {
	
		// Return true
		return true;
	}
	
	// Check if serialized UTXO commitments sum doesn't equal the serialized kernel excesses sum
	if(memcmp(serializedUtxoCommitmentsSum, serializedKernelExcessesSum, sizeof(serializedKernelExcessesSum))) {
	
		// Return false
		return false;
	}
	
	// Check if stopping read and write or is closing
	if(stopReadAndWrite.load() || Common::isClosing()) {
	
		// Return true
		return true;
	}
	
	{
		// Lock node and self for writing
		unique_lock nodeWriteLock(node.getLock(), defer_lock);
		unique_lock writeLock(lock, defer_lock);
		
		::lock(nodeWriteLock, writeLock);
		
		// Check if not disconnected
		if(connectionState != ConnectionState::DISCONNECTED) {
		
			// Check if using node headers
			if(useNodeHeaders) {
			
				// Check if updating node's sync state failed
				if(!node.updateSyncState(syncedHeaderIndex + 1, block)) {
				
					// Return false
					return false;
				}
			}
			
			// Otherwise
			else {
			
				// Check if updating node's sync state failed
				if(!node.updateSyncState(move(headers), syncedHeaderIndex + 1, block)) {
				
					// Return false
					return false;
				}
			}
			
			// Set syncing state to not syncing
			syncingState = SyncingState::NOT_SYNCING;
			
			// Unlock node write lock
			nodeWriteLock.unlock();
			
			// Unlock write lock
			writeLock.unlock();
			
			// Notify peers that event occurred
			eventOccurred.notify_one();
		}
	}
	
	// Return true
	return true;
}
