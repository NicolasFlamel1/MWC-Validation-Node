// Header guard
#ifndef MWC_VALIDATION_NODE_HEADER_H
#define MWC_VALIDATION_NODE_HEADER_H


// Header files
#include "./common.h"
#include <chrono>
#include "./crypto.h"
#include "./merkle_mountain_range_leaf.h"

using namespace std;


// Namespace
namespace MwcValidationNode {


// Structures

// Header structure
class Header final : public MerkleMountainRangeLeaf<Header> {

	// Public
	public:
	
		// Constructor
		explicit Header(const uint16_t version, const uint64_t height, const chrono::time_point<chrono::system_clock> &timestamp, const uint8_t previousBlockHash[Crypto::BLAKE2B_HASH_LENGTH], const uint8_t previousHeaderRoot[Crypto::BLAKE2B_HASH_LENGTH], const uint8_t outputRoot[Crypto::BLAKE2B_HASH_LENGTH], const uint8_t rangeproofRoot[Crypto::BLAKE2B_HASH_LENGTH], const uint8_t kernelRoot[Crypto::BLAKE2B_HASH_LENGTH], const uint8_t totalKernelOffset[Crypto::SECP256K1_PRIVATE_KEY_LENGTH], const uint64_t outputMerkleMountainRangeSize, const uint64_t kernelMerkleMountainRangeSize, const uint64_t totalDifficulty, const uint32_t secondaryScaling, const uint64_t nonce, const uint8_t edgeBits, const uint64_t proofNonces[Crypto::CUCKOO_CYCLE_NUMBER_OF_PROOF_NONCES]);
	
		// Serialize
		virtual vector<uint8_t> serialize() const override final;
		
		// Save
		virtual void save(ofstream &file) const override final;
		
		// Equality operator
		bool operator==(const Header &other) const;
		
		// Inequality operator
		bool operator!=(const Header &other) const;
		
		// Get version
		uint16_t getVersion() const;
		
		// Get height
		uint64_t getHeight() const;
		
		// Get timestamp
		const chrono::time_point<chrono::system_clock> &getTimestamp() const;
		
		// Get previous block hash
		const uint8_t *getPreviousBlockHash() const;
		
		// Get previous header root
		const uint8_t *getPreviousHeaderRoot() const;
		
		// Get output root
		const uint8_t *getOutputRoot() const;
		
		// Get rangeproof root
		const uint8_t *getRangeproofRoot() const;
		
		// Get kernel root
		const uint8_t *getKernelRoot() const;
		
		// Get total kernel offset
		const uint8_t *getTotalKernelOffset() const;
		
		// Get output Merkle mountain range size
		uint64_t getOutputMerkleMountainRangeSize() const;
		
		// Get kernel Merkle mountain range size
		uint64_t getKernelMerkleMountainRangeSize() const;
		
		// Get total difficulty
		uint64_t getTotalDifficulty() const;
		
		// Get secondary scaling
		uint32_t getSecondaryScaling() const;
		
		// Get nonce
		uint64_t getNonce() const;
		
		// Get edge bits
		uint8_t getEdgeBits() const;
		
		// Get proof nonces
		const uint64_t *getProofNonces() const;
		
		// Get block hash
		array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH> getBlockHash() const;
		
		// Restore
		static Header restore(ifstream &file);
		
		// Save sum
		static void saveSum(const int &sum, ofstream &file);
		
		// Restore sum
		static void restoreSum(int &sum, ifstream &file);
	
	// Private
	private:
	
		// Constructor
		explicit Header(ifstream &file);
		
		// Future number of blocks threshold
		static const uint64_t FUTURE_NUMBER_OF_BLOCKS_THRESHOLD;
	
		// Get proof nonces bytes
		vector<uint8_t> getProofNoncesBytes() const;

		// Version
		uint16_t version;
		
		// Height
		uint64_t height;
		
		// Timestamp
		chrono::time_point<chrono::system_clock> timestamp;
		
		// Previous block hash
		uint8_t previousBlockHash[Crypto::BLAKE2B_HASH_LENGTH];
		
		// Previous header root
		uint8_t previousHeaderRoot[Crypto::BLAKE2B_HASH_LENGTH];
		
		// Output root
		uint8_t outputRoot[Crypto::BLAKE2B_HASH_LENGTH];
		
		// Rangeproof root
		uint8_t rangeproofRoot[Crypto::BLAKE2B_HASH_LENGTH];
		
		// Kernel root
		uint8_t kernelRoot[Crypto::BLAKE2B_HASH_LENGTH];
		
		// Total kernel offset
		uint8_t totalKernelOffset[Crypto::SECP256K1_PRIVATE_KEY_LENGTH];
		
		// Output Merkle mountain range size
		uint64_t outputMerkleMountainRangeSize;
		
		// Kernel Merkle mountain range size
		uint64_t kernelMerkleMountainRangeSize;
		
		// Total difficulty
		uint64_t totalDifficulty;
		
		// Secondary scaling
		uint32_t secondaryScaling;
		
		// Nonce
		uint64_t nonce;
		
		// Edge bits
		uint8_t edgeBits;
		
		// Proof nonces
		uint64_t proofNonces[Crypto::CUCKOO_CYCLE_NUMBER_OF_PROOF_NONCES];
};


}


#endif
