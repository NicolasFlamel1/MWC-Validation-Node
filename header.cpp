// Header files
#include"./common.h"
#include <cstring>
#include "blake2.h"
#include "./consensus.h"
#include "./header.h"
#include "./merkle_mountain_range.h"
#include "./proof_of_work.h"
#include "./saturate_math.h"

using namespace std;


// Constants


// Future number of blocks threshold
const uint64_t Header::FUTURE_NUMBER_OF_BLOCKS_THRESHOLD = 12;


// Supporting function implementation

// Constructor
Header::Header(const uint16_t version, const uint64_t height, const chrono::time_point<chrono::system_clock> &timestamp, const uint8_t previousBlockHash[Crypto::BLAKE2B_HASH_LENGTH], const uint8_t previousHeaderRoot[Crypto::BLAKE2B_HASH_LENGTH], const uint8_t outputRoot[Crypto::BLAKE2B_HASH_LENGTH], const uint8_t rangeproofRoot[Crypto::BLAKE2B_HASH_LENGTH], const uint8_t kernelRoot[Crypto::BLAKE2B_HASH_LENGTH], const uint8_t totalKernelOffset[Crypto::SECP256K1_PRIVATE_KEY_LENGTH], const uint64_t outputMerkleMountainRangeSize, const uint64_t kernelMerkleMountainRangeSize, const uint64_t totalDifficulty, const uint32_t secondaryScaling, const uint64_t nonce, const uint8_t edgeBits, const uint64_t proofNonces[Crypto::CUCKOO_CYCLE_NUMBER_OF_PROOF_NONCES]) :

	// Set version to version
	version(version),
	
	// Set height to height
	height(height),
	
	// Set timestamp to timestamp
	timestamp(timestamp),
	
	// Set output Merkle mountain range size to output Merkle mountain range size
	outputMerkleMountainRangeSize(outputMerkleMountainRangeSize),
	
	// Set kernel Merkle mountain range size to kernel Merkle mountain range size
	kernelMerkleMountainRangeSize(kernelMerkleMountainRangeSize),
	
	// Set total difficulty to total difficulty
	totalDifficulty(totalDifficulty),
	
	// Set secondary scaling to secondary scaling
	secondaryScaling(secondaryScaling),
	
	// Set nonce to nonce
	nonce(nonce),
	
	// Set edge bits to edge bits
	edgeBits(edgeBits)
{

	// Check if version is invalid
	if(Consensus::getHeaderVersion(height) != version) {
	
		// Throw exception
		throw runtime_error("Version is invalid");
	}
	
	// Check if timestamp is too far in the future
	if(timestamp > chrono::system_clock::now() + FUTURE_NUMBER_OF_BLOCKS_THRESHOLD * Consensus::BLOCK_TIME) {
	
		// Throw exception
		throw runtime_error("Timestamp is too far in the future");
	}
	
	// Check if total kernel offset is invalid
	if(any_of(totalKernelOffset, totalKernelOffset + Crypto::SECP256K1_PRIVATE_KEY_LENGTH, [](const uint8_t value) {
	
		// Return if value isn't zero
		return value;
	
	}) && !secp256k1_ec_seckey_verify(secp256k1_context_no_precomp, totalKernelOffset)) {
	
		// Throw exception
		throw runtime_error("Total kernel offset is invalid");
	}
	
	// Check if output Merkle mountain range size is invalid
	if(!MerkleMountainRange<Output>::isSizeValid(outputMerkleMountainRangeSize)) {
	
		// Throw exception
		throw runtime_error("Output Merkle mountain range size is invalid");
	}
	
	// Check if kernel Merkle mountain range size is invalid
	if(!MerkleMountainRange<Kernel>::isSizeValid(kernelMerkleMountainRangeSize)) {
	
		// Throw exception
		throw runtime_error("Kernel Merkle mountain range size is invalid");
	}
	
	// Get global weight with the number of outputs and kernels
	const uint64_t globalWeight = Consensus::getBlockWeight(0, MerkleMountainRange<Output>::getNumberOfLeavesAtSize(outputMerkleMountainRangeSize), MerkleMountainRange<Kernel>::getNumberOfLeavesAtSize(kernelMerkleMountainRangeSize));
	
	// Check if global weight at the height is invalid
	if(globalWeight > SaturateMath::multiply(Consensus::MAXIMUM_BLOCK_WEIGHT, SaturateMath::add(height, 1))) {
	
		// Throw exception
		throw runtime_error("Global weight at the height is invalid");
	}
	
	// Check if total difficulty is invalid
	if(totalDifficulty < Consensus::GENESIS_BLOCK_HEADER.totalDifficulty) {
	
		// Throw exception
		throw runtime_error("Total difficulty is invalid");
	}
	
	// Check if edge bits are invalid
	if(!edgeBits || edgeBits > Consensus::MAXIMUM_EDGE_BITS) {
	
		// Throw exception
		throw runtime_error("Edge bits are invalid");
	}

	// Set previous block hash to previous block hash
	memcpy(this->previousBlockHash, previousBlockHash, sizeof(this->previousBlockHash));
	
	// Set previous header root to previous header root
	memcpy(this->previousHeaderRoot, previousHeaderRoot, sizeof(this->previousHeaderRoot));
	
	// Set output root to output root
	memcpy(this->outputRoot, outputRoot, sizeof(this->outputRoot));
	
	// Set rangeproof root to rangeproof root
	memcpy(this->rangeproofRoot, rangeproofRoot, sizeof(this->rangeproofRoot));
	
	// Set kernel root to kernel root
	memcpy(this->kernelRoot, kernelRoot, sizeof(this->kernelRoot));
	
	// Set total kernel offset to total kernel offset
	memcpy(this->totalKernelOffset, totalKernelOffset, sizeof(this->totalKernelOffset));

	// Set proof nonces to proof nonces
	memcpy(this->proofNonces, proofNonces, sizeof(this->proofNonces));
	
	// Check if proof of work is invalid
	if(height != Consensus::GENESIS_BLOCK_HEADER.height && !ProofOfWork::hasValidProofOfWork(*this)) {
	
		// Throw exception
		throw runtime_error("Proof of work is invalid");
	}
	
	// Check if block hash is banned
	if(Consensus::isBlockHashBanned(getBlockHash().data())) {
	
		// Throw error
		throw runtime_error("Block hash is banned");
	}
	
	// Check if header doesn't match the genesis block header
	if(height == Consensus::GENESIS_BLOCK_HEADER.height && *this != Consensus::GENESIS_BLOCK_HEADER) {
	
		// Throw exception
		throw runtime_error("Header doesn't match the genesis block header");
	}
}

// Serialize
const vector<uint8_t> Header::serialize() const {

	// Return serialized header
	return getProofNoncesBytes();
}

// Equality operator
const bool Header::operator==(const Header &other) const {

	// Check if versions differ
	if(version != other.version) {
	
		// Return false
		return false;
	}
	
	// Check if heights differ
	if(height != other.height) {
	
		// Return false
		return false;
	}
	
	// Check if timestamps differ
	if(timestamp != other.timestamp) {
	
		// Return false
		return false;
	}
	
	// Check if previous block hashes differ
	if(memcmp(previousBlockHash, other.previousBlockHash, sizeof(other.previousBlockHash))) {
	
		// Return false
		return false;
	}
	
	// Check if previous header roots differ
	if(memcmp(previousHeaderRoot, other.previousHeaderRoot, sizeof(other.previousHeaderRoot))) {
	
		// Return false
		return false;
	}
	
	// Check if output roots differ
	if(memcmp(outputRoot, other.outputRoot, sizeof(other.outputRoot))) {
	
		// Return false
		return false;
	}
	
	// Check if rangeproof roots differ
	if(memcmp(rangeproofRoot, other.rangeproofRoot, sizeof(other.rangeproofRoot))) {
	
		// Return false
		return false;
	}
	
	// Check if kernel roots differ
	if(memcmp(kernelRoot, other.kernelRoot, sizeof(other.kernelRoot))) {
	
		// Return false
		return false;
	}
	
	// Check if total kernel offset differ
	if(memcmp(totalKernelOffset, other.totalKernelOffset, sizeof(other.totalKernelOffset))) {
	
		// Return false
		return false;
	}
	
	// Check if output Merkle mountain range sizes differ
	if(outputMerkleMountainRangeSize != other.outputMerkleMountainRangeSize) {
	
		// Return false
		return false;
	}
	
	// Check if kernel Merkle mountain range sizes differ
	if(kernelMerkleMountainRangeSize != other.kernelMerkleMountainRangeSize) {
	
		// Return false
		return false;
	}
	
	// Check if total difficulties differ
	if(totalDifficulty != other.totalDifficulty) {
	
		// Return false
		return false;
	}
	
	// Check if secondary scalings differ
	if(secondaryScaling != other.secondaryScaling) {
	
		// Return false
		return false;
	}
	
	// Check if nonces differ
	if(nonce != other.nonce) {
	
		// Return false
		return false;
	}
	
	// Check if edge bits differ
	if(edgeBits != other.edgeBits) {
	
		// Return false
		return false;
	}
	
	// Check if proof nonces differ
	if(memcmp(proofNonces, other.proofNonces, sizeof(other.proofNonces))) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Inequality operator
const bool Header::operator!=(const Header &other) const {

	// Return if headers aren't equal
	return !(*this == other);
}

// Get version
const uint16_t Header::getVersion() const {

	// Return version
	return version;
}

// Get height
const uint64_t Header::getHeight() const {

	// Return height
	return height;
}

// Get timestamp
const chrono::time_point<chrono::system_clock> &Header::getTimestamp() const {

	// Return timestamp
	return timestamp;
}

// Get previous block hash
const uint8_t *Header::getPreviousBlockHash() const {

	// Return previous block hash
	return previousBlockHash;
}

// Get previous header root
const uint8_t *Header::getPreviousHeaderRoot() const {

	// Return previous header root
	return previousHeaderRoot;
}

// Get output root
const uint8_t *Header::getOutputRoot() const {

	// Return output root
	return outputRoot;
}

// Get rangeproof root
const uint8_t *Header::getRangeproofRoot() const {

	// Return rangeproof root
	return rangeproofRoot;
}

// Get kernel root
const uint8_t *Header::getKernelRoot() const {

	// Return kernel root
	return kernelRoot;
}

// Get total kernel offset
const uint8_t *Header::getTotalKernelOffset() const {

	// Return total kernel offset
	return totalKernelOffset;
}

// Get output Merkle mountain range size
const uint64_t Header::getOutputMerkleMountainRangeSize() const {

	// Return output Merkle mountain range size
	return outputMerkleMountainRangeSize;
}

// Get kernel Merkle mountain range size
const uint64_t Header::getKernelMerkleMountainRangeSize() const {

	// Return kernel Merkle mountain range size
	return kernelMerkleMountainRangeSize;
}

// Get total difficulty
const uint64_t Header::getTotalDifficulty() const {

	// Return total difficulty
	return totalDifficulty;
}

// Get secondary scaling
const uint32_t Header::getSecondaryScaling() const {

	// Return secondary scaling
	return secondaryScaling;
}

// Get nonce
const uint64_t Header::getNonce() const {

	// Return nonce
	return nonce;
}

// Get edge bits
const uint8_t Header::getEdgeBits() const {

	// Return edge bits
	return edgeBits;
}

// Get proof nonces
const uint64_t *Header::getProofNonces() const {

	// Return proof nonces
	return proofNonces;
}

// Get block hash
const array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH> Header::getBlockHash() const {

	// Initialize block hash
	array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH> blockHash;
	
	// Get proof nonces bytes
	const vector<uint8_t> proofNoncesBytes = getProofNoncesBytes();
	
	// Check if getting block hash failed
	if(blake2b(blockHash.data(), blockHash.size(), proofNoncesBytes.data(), proofNoncesBytes.size(), nullptr, 0)) {
	
		// Throw error
		throw runtime_error("Getting block hash failed");
	}
	
	// Return block hash
	return blockHash;
}

// Get proof nonces bytes
const vector<uint8_t> Header::getProofNoncesBytes() const {

	// Set number of proof nonces bytes
	const uint64_t numberOfProofNoncesBytes = Common::numberOfBytesRequired(edgeBits * (sizeof(proofNonces) / sizeof(proofNonces[0])));
	
	// Initialize proof nonces bytes
	vector<uint8_t> proofNoncesBytes(numberOfProofNoncesBytes);
	
	// Go through all proof nonces
	for(size_t i = 0; i < sizeof(proofNonces) / sizeof(proofNonces[0]); ++i) {
	
		// Get proof nonce
		const uint64_t &proofNonce = proofNonces[i];
	
		// Go through all edge bits
		for(uint8_t j = 0; j < edgeBits; ++j) {
		
			// Check if bit is set in the proof nonce
			if(proofNonce & (static_cast<uint64_t>(1) << j)) {
			
				// Set bit position
				const uint64_t bitPosition = i * edgeBits + j;
				
				// Set bit in the proof nonces bytes
				proofNoncesBytes[bitPosition / Common::BITS_IN_A_BYTE] |= 1 << (bitPosition % Common::BITS_IN_A_BYTE);
			}
		}
	}
	
	// Return proof nonces bytes
	return proofNoncesBytes;
}
