// Header guard
#ifndef MWC_VALIDATION_NODE_RANGEPROOF_H
#define MWC_VALIDATION_NODE_RANGEPROOF_H


// Header files
#include "./common.h"
#include "./crypto.h"
#include "./merkle_mountain_range_leaf.h"

using namespace std;


// Namespace
namespace MwcValidationNode {


// Classes

// Rangeproof class
class Rangeproof final : public MerkleMountainRangeLeaf<Rangeproof, sizeof(uint64_t) + Crypto::BULLETPROOF_LENGTH> {

	// Public
	public:
	
		// Constructor
		explicit Rangeproof(const uint64_t length, const uint8_t proof[Crypto::BULLETPROOF_LENGTH], const bool isGenesisBlockRangeproof = false);
		
		// Serialize
		virtual vector<uint8_t> serialize() const override final;
		
		// Save
		virtual void save(ofstream &file) const override final;
		
		// Equality operator
		bool operator==(const Rangeproof &other) const;
		
		// Inequality operator
		bool operator!=(const Rangeproof &other) const;
		
		// Get length
		uint64_t getLength() const;
		
		// Get proof
		const uint8_t *getProof() const;
		
		// Get hash
		array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH> getHash() const;
		
		// Get serialized protocol version
		static uint32_t getSerializedProtocolVersion(const array<uint8_t, MAXIMUM_SERIALIZED_LENGTH> &serializedRangeproof, const array<uint8_t, MAXIMUM_SERIALIZED_LENGTH>::size_type serializedRangeproofLength, const uint32_t protocolVersion);
		
		// Unserialize
		static pair<Rangeproof, array<uint8_t, MAXIMUM_SERIALIZED_LENGTH>::size_type> unserialize(const array<uint8_t, MAXIMUM_SERIALIZED_LENGTH> &serializedRangeproof, const array<uint8_t, MAXIMUM_SERIALIZED_LENGTH>::size_type serializedRangeproofLength, const uint32_t protocolVersion, const bool isGenesisBlockRangeproof);
		
		// Restore
		static Rangeproof restore(ifstream &file);
		
		// Save sum
		static void saveSum(const int &sum, ofstream &file);
		
		// Restore sum
		static void restoreSum(int &sum, ifstream &file);
	
	// Private
	private:
		
		// Constructor
		explicit Rangeproof(ifstream &file);
		
		// length
		uint64_t length;
		
		// Proof
		uint8_t proof[Crypto::BULLETPROOF_LENGTH];
};


}


#endif
