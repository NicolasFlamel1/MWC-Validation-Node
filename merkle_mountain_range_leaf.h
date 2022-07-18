// Header guard
#ifndef MERKLE_MOUNTAIN_RANGE_LEAF_H
#define MERKLE_MOUNTAIN_RANGE_LEAF_H


// Header files
#include "./common.h"
#include <array>
#include <optional>

using namespace std;


// Classes

// Merkle mountain range leaf class
template<typename DerivedClass, size_t serializedMerkleMountainRangeLeafLength = 0, typename SumClass = int> class MerkleMountainRangeLeaf {

	// Public
	public:
	
		// Serialized length
		static const size_t SERIALIZED_LENGTH = serializedMerkleMountainRangeLeafLength;
		
		// Addition reason
		enum class AdditionReason {
		
			// Appended
			APPENDED,
			
			// Restored
			RESTORED
		};
		
		// Subtraction reason
		enum class SubtractionReason {
		
			// Pruned
			PRUNED,
			
			// Rewinded
			REWINDED,
			
			// Discarded
			DISCARDED
		};
		
		// Sum
		typedef SumClass Sum;
		
		// Serialize
		virtual const vector<uint8_t> serialize() const = 0;
		
		// Get lookup value
		virtual const optional<vector<uint8_t>> getLookupValue() const;
		
		// Add to sum
		virtual void addToSum(SumClass &sum, const AdditionReason additionReason) const;
		
		// Subtract from sum
		virtual void subtractFromSum(SumClass &sum, const SubtractionReason subtractionReason) const;
		
		// Unserialize
		static const DerivedClass unserialize(const array<uint8_t, SERIALIZED_LENGTH> &serializedMerkleMountainRangeLeaf, const bool isGenesisBlock = false);
};


// Supporting function implementation

// Get lookup value
template<typename DerivedClass, size_t serializedMerkleMountainRangeLeafLength, typename SumClass> const optional<vector<uint8_t>> MerkleMountainRangeLeaf<DerivedClass, serializedMerkleMountainRangeLeafLength, SumClass>::getLookupValue() const {

	// Return no look up value
	return nullopt;
}

// Add to sum
template<typename DerivedClass, size_t serializedMerkleMountainRangeLeafLength, typename SumClass> void MerkleMountainRangeLeaf<DerivedClass, serializedMerkleMountainRangeLeafLength, SumClass>::addToSum(SumClass &sum, const AdditionReason additionReason) const {

}

// Subtract from sum
template<typename DerivedClass, size_t serializedMerkleMountainRangeLeafLength, typename SumClass> void MerkleMountainRangeLeaf<DerivedClass, serializedMerkleMountainRangeLeafLength, SumClass>::subtractFromSum(SumClass &sum, const SubtractionReason subtractionReason) const {

}

// Unserialize
template<typename DerivedClass, size_t serializedMerkleMountainRangeLeafLength, typename SumClass> const DerivedClass MerkleMountainRangeLeaf<DerivedClass, serializedMerkleMountainRangeLeafLength, SumClass>::unserialize(const array<uint8_t, SERIALIZED_LENGTH> &serializedMerkleMountainRangeLeaf, const bool isGenesisBlock) {

	// Return unserialized derived class
	return DerivedClass::unserialize(serializedMerkleMountainRangeLeaf, isGenesisBlock);
}


#endif
