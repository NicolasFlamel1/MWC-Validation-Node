// Header files
#include "./common.h"
#include <bit>
#include "blake2.h"
#include "./consensus.h"
#include "./proof_of_work.h"

using namespace std;


// Namespace
using namespace MwcValidationNode;


// Constants

// SipHash block bits
const uint64_t ProofOfWork::SIPHASH_BLOCK_BITS = 6;

// SipHash block length
const size_t ProofOfWork::SIPHASH_BLOCK_LENGTH = static_cast<uint64_t>(1) << ProofOfWork::SIPHASH_BLOCK_BITS;

// SipHash block mask
const uint64_t ProofOfWork::SIPHASH_BLOCK_MASK = ProofOfWork::SIPHASH_BLOCK_LENGTH - 1;

// SipHash default rotation
const uint8_t ProofOfWork::SIPHASH_DEFAULT_ROTATION = 21;

// C29 SipHash rotation
const uint8_t ProofOfWork::C29_SIPHASH_ROTATION = 25;


// Supporting function implementation

// Has valid proof of work
bool ProofOfWork::hasValidProofOfWork(const Header &header) {

	// Get hash from the header
	const array hash = getProofOfWorkHash(header);
	
	// Initialize SipHash keys
	uint64_t sipHashKeys[SIPHASH_KEYS_LENGTH];
	
	// Go through all SipHash keys
	for(size_t i = 0; i < sizeof(sipHashKeys) / sizeof(sipHashKeys[0]); ++i) {
	
		// Set SipHash key
		sipHashKeys[i] = Common::littleEndianToHostByteOrder(*reinterpret_cast<const uint64_t *>(&hash[i * sizeof(uint64_t)]));
	}

	// Set number of edge bits
	const uint64_t numberOfEdges = static_cast<uint64_t>(1) << header.getEdgeBits();
	
	// Set edge mask
	const uint64_t edgeMask = numberOfEdges - 1;
	
	// Check if header uses C29 edge bits
	if(header.getEdgeBits() == Consensus::C29_EDGE_BITS) {
	
		// Set number of nodes
		const uint64_t numberOfNodes = static_cast<uint64_t>(1) << (header.getEdgeBits() - 1);
		
		// Set node mask
		const uint64_t nodeMask = numberOfNodes - 1;
		
		// Initialize UVs
		uint64_t uvs[2 * Crypto::CUCKOO_CYCLE_NUMBER_OF_PROOF_NONCES] = {};
		
		// Initialize ndir
		uint64_t ndir[2] = {};
		
		// Set XORs
		uint64_t xor0 = 0;
		uint64_t xor1 = 0;
		
		// Go through all of the header's proof nonces
		for(uint64_t i = 0; i < Crypto::CUCKOO_CYCLE_NUMBER_OF_PROOF_NONCES; ++i) {
		
			// Get dir
			const uint64_t dir = header.getProofNonces()[i] & 1;
			
			// Check if edges aren't balanced
			if(ndir[dir] >= Crypto::CUCKOO_CYCLE_NUMBER_OF_PROOF_NONCES / 2) {
			
				// Return false
				return false;
			}
			
			// Check if edges are too big
			if(header.getProofNonces()[i] > edgeMask) {
			
				// Return false
				return false;
			}
			
			// Check if edges are not ascending
			if(i && header.getProofNonces()[i] <= header.getProofNonces()[i - 1]) {
			
				// Return false
				return false;
			}
			
			// Get edge
			const uint64_t edge = sipHashBlock(sipHashKeys, header.getProofNonces()[i], C29_SIPHASH_ROTATION);
			
			// Get index
			const uint64_t index = 4 * ndir[dir] + 2 * dir;
			
			// Set UVs
			uvs[index] = edge & nodeMask;
			uvs[index + 1] = (edge >> 32) & nodeMask;
			
			// Update XORs
			xor0 ^= uvs[index];
			xor1 ^= uvs[index + 1];
			
			// Increment ndir
			++ndir[dir];
		}
		
		// Check if endpoints don't match up
		if(xor0 | xor1) {
		
			// Return false
			return false;
		}
		
		// Set length to zero
		uint64_t length = 0;
		
		// Loop
		uint64_t i = 0;
		do {
		
			// Follow cycle
			uint64_t j = i;
			
			for(uint64_t k = (i % 4) ^ 2; k < 2 * Crypto::CUCKOO_CYCLE_NUMBER_OF_PROOF_NONCES; k += 4) {
			
				// Check if UVs match
				if(uvs[k] == uvs[i]) {
				
					// Check if branch in cycle
					if(j != i) {
					
						// Return false
						return false;
					}
					
					// Update value
					j = k;
				}
			}
			
			// Check if cycle dead ends
			if(j == i) {
			
				// Return false
				return false;
			}
			
			// Update index
			i = j ^ 1;
			
			// Increment length
			++length;
			
		} while(i);
		
		// Check if cycle is too short
		if(length != Crypto::CUCKOO_CYCLE_NUMBER_OF_PROOF_NONCES) {
		
			// Return false
			return false;
		}
	}

	// Otherwise check if header at least C31 edge bits
	else if(header.getEdgeBits() >= Consensus::C31_EDGE_BITS) {
	
		// Set number of nodes
		const uint64_t numberOfNodes = static_cast<uint64_t>(1) << header.getEdgeBits();
		
		// Set node mask
		const uint64_t nodeMask = numberOfNodes - 1;
		
		// Initialize UVs
		uint64_t uvs[2 * Crypto::CUCKOO_CYCLE_NUMBER_OF_PROOF_NONCES] = {};
		
		// Set XORs
		uint64_t xor0 = (Crypto::CUCKOO_CYCLE_NUMBER_OF_PROOF_NONCES / 2) & 1;
		uint64_t xor1 = xor0;
		
		// Go through all of the header's proof nonces
		for(uint64_t i = 0; i < Crypto::CUCKOO_CYCLE_NUMBER_OF_PROOF_NONCES; ++i) {
		
			// Check if edges are too big
			if(header.getProofNonces()[i] > edgeMask) {
			
				// Return false
				return false;
			}
			
			// Check if edges are not ascending
			if(i && header.getProofNonces()[i] <= header.getProofNonces()[i - 1]) {
			
				// Return false
				return false;
			}
			
			// Set UVs
			uvs[2 * i] = sipNode(sipHashKeys, header.getProofNonces()[i], 0) & nodeMask;
			uvs[2 * i + 1] = sipNode(sipHashKeys, header.getProofNonces()[i], 1) & nodeMask;
			
			// Update XORs
			xor0 ^= uvs[2 * i];
			xor1 ^= uvs[2 * i + 1];
		}
		
		// Check if endpoints don't match up
		if(xor0 | xor1) {
		
			// Return false
			return false;
		}
		
		// Set length to zero
		uint64_t length = 0;
		
		// Loop
		uint64_t i = 0;
		do {
		
			// Follow cycle
			uint64_t j = i;
			
			for(uint64_t k = (j + 2) % (2 * Crypto::CUCKOO_CYCLE_NUMBER_OF_PROOF_NONCES); k != i; k = (k + 2) % (2 * Crypto::CUCKOO_CYCLE_NUMBER_OF_PROOF_NONCES)) {
			
				// Check if UVs match
				if(uvs[k] >> 1 == uvs[i] >> 1) {
				
					// Check if branch in cycle
					if(j != i) {
					
						// Return false
						return false;
					}
					
					// Update value
					j = k;
				}
			}
			
			// Check if cycle dead ends
			if(j == i || uvs[j] == uvs[i]) {
			
				// Return false
				return false;
			}
			
			// Update index
			i = j ^ 1;
			
			// Increment length
			++length;
			
		} while(i);
		
		// Check if cycle is too short
		if(length != Crypto::CUCKOO_CYCLE_NUMBER_OF_PROOF_NONCES) {
		
			// Return false
			return false;
		}
	}
	
	// Otherwise
	else {
	
		// Return false
		return false;
	}

	// Return true
	return true;
}

// SipHash-2-4 constructor
ProofOfWork::SipHash24::SipHash24(const uint64_t sipHashKeys[SIPHASH_KEYS_LENGTH]) {

	// Go through all values
	for(size_t i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
	
		// Set value to SipHash key
		values[i] = sipHashKeys[i];
	}
}

// SipHash-2-4 hash
void ProofOfWork::SipHash24::hash(const uint64_t nonce, const uint8_t rotation) {

	// Perform hash on values
	values[3] ^= nonce;
	
	for(int i = 0; i < 2; ++i) {
		round(rotation);
	}
	
	values[0] ^= nonce;
	values[2] ^= UINT8_MAX;
	
	for(int i = 0; i < 4; ++i) {
		round(rotation);
	}
}

// SipHash-2-4 digest
uint64_t ProofOfWork::SipHash24::digest() const {

	// Set digest to zero
	uint64_t digest = 0;
	
	// Go through all values
	for(size_t i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
	
		// Update digest
		digest ^= values[i];
	}
	
	// Return digest
	return digest;
}

// SipHash-2-4 round
void ProofOfWork::SipHash24::round(const uint8_t rotation) {

	// Perform round on values
	values[0] += values[1];
	values[2] += values[3];
	
	values[1] = rotl(values[1], 13);
	values[3] = rotl(values[3], 16);
	
	values[1] ^= values[0];
	values[3] ^= values[2];
	
	values[0] = rotl(values[0], 32);
	
	values[2] += values[1];
	values[0] += values[3];
	
	values[1] = rotl(values[1], 17);
	values[3] = rotl(values[3], rotation);
	
	values[1] ^= values[2];
	values[3] ^= values[0];
	
	values[2] = rotl(values[2], 32);
}

// Get proof of work hash
array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH> ProofOfWork::getProofOfWorkHash(const Header &header) {

	// Initialize data
	vector<uint8_t> data;
	
	// Append header's version to data
	Common::writeUint16(data, header.getVersion());
	
	// Append header's height to data
	Common::writeUint64(data, header.getHeight());
	
	// Append header's timestamp to data
	Common::writeInt64(data, chrono::duration_cast<chrono::seconds>(header.getTimestamp().time_since_epoch()).count());
	
	// Append header's previous block hash to data
	data.insert(data.cend(), header.getPreviousBlockHash(), header.getPreviousBlockHash() + Crypto::BLAKE2B_HASH_LENGTH);
	
	// Append header's previous header root to data
	data.insert(data.cend(), header.getPreviousHeaderRoot(), header.getPreviousHeaderRoot() + Crypto::BLAKE2B_HASH_LENGTH);
	
	// Append header's previous output to data
	data.insert(data.cend(), header.getOutputRoot(), header.getOutputRoot() + Crypto::BLAKE2B_HASH_LENGTH);
	
	// Append header's rangeproof root to data
	data.insert(data.cend(), header.getRangeproofRoot(), header.getRangeproofRoot() + Crypto::BLAKE2B_HASH_LENGTH);
	
	// Append header's kernel root to data
	data.insert(data.cend(), header.getKernelRoot(), header.getKernelRoot() + Crypto::BLAKE2B_HASH_LENGTH);
	
	// Append header's total kernel offset to data
	data.insert(data.cend(), header.getTotalKernelOffset(), header.getTotalKernelOffset() + Crypto::SECP256K1_PRIVATE_KEY_LENGTH);
	
	// Append header's output Merkle mountain range size to data
	Common::writeUint64(data, header.getOutputMerkleMountainRangeSize());
	
	// Append header's kernel Merkle mountain range size to data
	Common::writeUint64(data, header.getKernelMerkleMountainRangeSize());
	
	// Append header's total difficulty to data
	Common::writeUint64(data, header.getTotalDifficulty());
	
	// Append header's secondary scaling to data
	Common::writeUint32(data, header.getSecondaryScaling());
	
	// Append header's nonce to data
	Common::writeUint64(data, header.getNonce());
	
	// Check if getting hash of data failed
	array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH> hash;
	
	if(blake2b(hash.data(), hash.size(), data.data(), data.size(), nullptr, 0)) {
	
		// Throw error
		throw runtime_error("Getting hash of data failed");
	}
	
	// Return hash
	return hash;
}

// SipHash block
uint64_t ProofOfWork::sipHashBlock(const uint64_t sipHashKeys[SIPHASH_KEYS_LENGTH], const uint64_t nonce, const uint8_t rotation) {

	// Set starting nonce
	const uint64_t startingNonce = nonce & ~SIPHASH_BLOCK_MASK;
	
	// Initialize nonce hashes
	uint64_t nonceHashes[SIPHASH_BLOCK_LENGTH];
	
	// Create SipHash-2-4 from SipHash keys
	SipHash24 sipHash24(sipHashKeys);
	
	// Go through all nonce hashes
	for(size_t i = 0; i < sizeof(nonceHashes) / sizeof(nonceHashes[0]); ++i) {
	
		// Hash SipHash-2-4
		sipHash24.hash(startingNonce + i, rotation);
		
		// Set nonce has to the SipHash-2-4 digest
		nonceHashes[i] = sipHash24.digest();
	}
	
	// Set index
	const uint64_t index = nonce & SIPHASH_BLOCK_MASK;
	
	// Set block to the nonce hash at the index
	uint64_t block = nonceHashes[index];
	
	// Go through all nonce hashes from the index
	for(uint64_t i = (index == SIPHASH_BLOCK_MASK) ? index + 1 : SIPHASH_BLOCK_MASK; i < sizeof(nonceHashes) / sizeof(nonceHashes[0]); ++i) {
	
		// Update the block with the nonce hash
		block ^= nonceHashes[i];
	}
	
	// Return the block
	return block;
}

// SipNode
uint64_t ProofOfWork::sipNode(const uint64_t sipHashKeys[SIPHASH_KEYS_LENGTH], const uint64_t edge, const uint64_t uorv) {

	// Create SipHash-2-4 from SipHash keys
	SipHash24 sipHash24(sipHashKeys);
	
	// Hash SipHash-2-4
	sipHash24.hash(2 * edge + uorv, SIPHASH_DEFAULT_ROTATION);
	
	// Return SipHash-2-4 digest
	return sipHash24.digest();
}
