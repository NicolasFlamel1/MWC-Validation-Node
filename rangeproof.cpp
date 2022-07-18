// Header files
#include"./common.h"
#include <cstring>
#include "./consensus.h"
#include "./rangeproof.h"


using namespace std;


// Supporting function implementation

// Constructor
Rangeproof::Rangeproof(const uint64_t length, const uint8_t proof[Crypto::BULLETPROOF_LENGTH], const bool isGenesisBlockRangeproof) :

	// Set length to length
	length(length)
{

	// Check if length is invalid
	if(length != sizeof(this->proof)) {
	
		// Throw exception
		throw runtime_error("Length is invalid");
	}

	// Set proof to proof
	memcpy(this->proof, proof, sizeof(this->proof));
	
	// Check if rangeproof doesn't match the genesis block rangeproof
	if(isGenesisBlockRangeproof && *this != Consensus::GENESIS_BLOCK_RANGEPROOF) {
	
		// Throw exception
		throw runtime_error("Rangeproof doesn't match the genesis block rangeproof");
	}
}

// Serialize
const vector<uint8_t> Rangeproof::serialize() const {

	// Initialize serialized rangeproof
	vector<uint8_t> serializedRangeproof;
	
	// Append length to serialized rangeproof
	Common::writeUint64(serializedRangeproof, length);
	
	// Append proof to serialized rangeproof
	serializedRangeproof.insert(serializedRangeproof.cend(), cbegin(proof), cend(proof));
	
	// Return serialized rangeproof
	return serializedRangeproof;
}

// Equality operator
const bool Rangeproof::operator==(const Rangeproof &other) const {

	// Check if lengths differ
	if(length != other.length) {
	
		// Return false
		return false;
	}
	
	// Check if proofs differ
	if(memcmp(proof, other.proof, sizeof(other.proof))) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Inequality operator
const bool Rangeproof::operator!=(const Rangeproof &other) const {

	// Return if rangeproofs aren't equal
	return !(*this == other);
}

// Get length
const uint64_t Rangeproof::getLength() const {

	// Return length
	return length;
}

// Get proof
const uint8_t *Rangeproof::getProof() const {

	// Return proof
	return proof;
}

// Unserialize
const Rangeproof Rangeproof::unserialize(const array<uint8_t, SERIALIZED_LENGTH> &serializedRangeproof, const bool isGenesisBlockRangeproof) {

	// Get length from serialized rangeproof
	const uint64_t length = Common::readUint64(serializedRangeproof, 0);
	
	// Get proof from serialized rangeproof
	const uint8_t *proof = &serializedRangeproof[sizeof(length)];
	
	// Return rangeproof
	return Rangeproof(length, proof, isGenesisBlockRangeproof);
}
