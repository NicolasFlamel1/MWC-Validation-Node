// Header files
#include"./common.h"
#include <cstring>
#include "./consensus.h"
#include "./rangeproof.h"


using namespace std;


// Namespace
using namespace MwcValidationNode;


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
vector<uint8_t> Rangeproof::serialize() const {

	// Initialize serialized rangeproof
	vector<uint8_t> serializedRangeproof;
	
	// Append length to serialized rangeproof
	Common::writeUint64(serializedRangeproof, length);
	
	// Append proof to serialized rangeproof
	serializedRangeproof.insert(serializedRangeproof.cend(), cbegin(proof), cend(proof));
	
	// Return serialized rangeproof
	return serializedRangeproof;
}

// Save
void Rangeproof::save(ofstream &file) const {

	// Write length to file
	const uint64_t serializedLength = Common::hostByteOrderToBigEndian(length);
	file.write(reinterpret_cast<const char *>(&serializedLength), sizeof(serializedLength));
	
	// Write proof to file
	file.write(reinterpret_cast<const char *>(proof), sizeof(proof));
}

// Equality operator
bool Rangeproof::operator==(const Rangeproof &other) const {

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
bool Rangeproof::operator!=(const Rangeproof &other) const {

	// Return if rangeproofs aren't equal
	return !(*this == other);
}

// Get length
uint64_t Rangeproof::getLength() const {

	// Return length
	return length;
}

// Get proof
const uint8_t *Rangeproof::getProof() const {

	// Return proof
	return proof;
}

// Get serialized protocol version
uint32_t Rangeproof::getSerializedProtocolVersion(const array<uint8_t, MAXIMUM_SERIALIZED_LENGTH> &serializedRangeproof, const array<uint8_t, MAXIMUM_SERIALIZED_LENGTH>::size_type serializedRangeproofLength, const uint32_t protocolVersion) {

	// Return protocol version
	return protocolVersion;
}

// Unserialize
pair<Rangeproof, array<uint8_t, Rangeproof::MAXIMUM_SERIALIZED_LENGTH>::size_type> Rangeproof::unserialize(const array<uint8_t, MAXIMUM_SERIALIZED_LENGTH> &serializedRangeproof, const array<uint8_t, MAXIMUM_SERIALIZED_LENGTH>::size_type serializedRangeproofLength, const uint32_t protocolVersion, const bool isGenesisBlockRangeproof) {

	// Check if serialized rangeproof doesn't contain a length and a proof
	if(serializedRangeproofLength < MAXIMUM_SERIALIZED_LENGTH) {
	
		// Throw exception
		throw runtime_error("Serialized rangeproof doesn't contain a length and a proof");
	}
	
	// Get length from serialized rangeproof
	const uint64_t length = Common::readUint64(serializedRangeproof, 0);
	
	// Get proof from serialized rangeproof
	const uint8_t *proof = &serializedRangeproof[sizeof(length)];
	
	// Return rangeproof
	return {Rangeproof(length, proof, isGenesisBlockRangeproof), MAXIMUM_SERIALIZED_LENGTH};
}

// Restore
Rangeproof Rangeproof::restore(ifstream &file) {

	// Return rangeproof created from file
	return Rangeproof(file);
}

// Save sum
void Rangeproof::saveSum(const int &sum, ofstream &file) {

}

// Restore sum
void Rangeproof::restoreSum(int &sum, ifstream &file) {

}

// Constructor
Rangeproof::Rangeproof(ifstream &file) {

	// Read length from file
	uint64_t serializedLength;
	file.read(reinterpret_cast<char *>(&serializedLength), sizeof(serializedLength));
	length = Common::bigEndianToHostByteOrder(serializedLength);
	
	// Read proof from file
	file.read(reinterpret_cast<char *>(proof), sizeof(proof));
}
