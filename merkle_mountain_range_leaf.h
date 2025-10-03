// Header guard
#ifndef MWC_VALIDATION_NODE_MERKLE_MOUNTAIN_RANGE_LEAF_H
#define MWC_VALIDATION_NODE_MERKLE_MOUNTAIN_RANGE_LEAF_H


// Header files
#include "./common.h"
#include <array>
#include <fstream>
#include <optional>

using namespace std;


// Namespace
namespace MwcValidationNode {


// Classes

// Merkle mountain range class forward declaration
template<typename MerkleMountainRangeLeafDerivedClass> class MerkleMountainRange;

// Merkle mountain range leaf class
template<typename DerivedClass, size_t maximumSerializedMerkleMountainRangeLeafLength = 0, typename SumClass = int, bool allowDuplicateLookupValues = false> class MerkleMountainRangeLeaf {

	// Public for Merkle mountain range class
	protected:
	
		// Merkle mountain range friend class
		friend class MerkleMountainRange<DerivedClass>;
		
		// Maximum serialized length
		static const size_t MAXIMUM_SERIALIZED_LENGTH = maximumSerializedMerkleMountainRangeLeafLength;
		
		// Allow duplicate lookup values
		static const bool ALLOW_DUPLICATE_LOOKUP_VALUES = allowDuplicateLookupValues;
		
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
		
		// Get lookup value
		virtual optional<vector<uint8_t>> getLookupValue() const;
		
		// Add to sum
		virtual void addToSum(SumClass &sum, const AdditionReason additionReason) const;
		
		// Subtract from sum
		virtual void subtractFromSum(SumClass &sum, const SubtractionReason subtractionReason) const;
		
	// Private
	private:
		
		// Serialize
		virtual vector<uint8_t> serialize() const = 0;
		
		// Save
		virtual void save(ofstream &file) const = 0;
		
		// Get serialized protocol version
		static uint32_t getSerializedProtocolVersion(const array<uint8_t, MAXIMUM_SERIALIZED_LENGTH> &serializedMerkleMountainRangeLeaf, const typename array<uint8_t, MAXIMUM_SERIALIZED_LENGTH>::size_type serializedMerkleMountainRangeLeafLength, const uint32_t protocolVersion);
		
		// Unserialize
		static pair<DerivedClass, array<uint8_t, 0>::size_type> unserialize(const array<uint8_t, MAXIMUM_SERIALIZED_LENGTH> &serializedMerkleMountainRangeLeaf, const typename array<uint8_t, MAXIMUM_SERIALIZED_LENGTH>::size_type serializedMerkleMountainRangeLeafLength, const uint32_t protocolVersion, const bool isGenesisBlock = false);
		
		// Restore
		static DerivedClass restore(ifstream &file);
		
		// Save sum
		static void saveSum(const SumClass &sum, ofstream &file);
		
		// Restore sum
		static void restoreSum(SumClass &sum, ifstream &file);
};


// Supporting function implementation

// Get lookup value
template<typename DerivedClass, size_t maximumSerializedMerkleMountainRangeLeafLength, typename SumClass, bool allowDuplicateLookupValues> optional<vector<uint8_t>> MerkleMountainRangeLeaf<DerivedClass, maximumSerializedMerkleMountainRangeLeafLength, SumClass, allowDuplicateLookupValues>::getLookupValue() const {

	// Return no look up value
	return nullopt;
}

// Add to sum
template<typename DerivedClass, size_t maximumSerializedMerkleMountainRangeLeafLength, typename SumClass, bool allowDuplicateLookupValues> void MerkleMountainRangeLeaf<DerivedClass, maximumSerializedMerkleMountainRangeLeafLength, SumClass, allowDuplicateLookupValues>::addToSum(SumClass &sum, const AdditionReason additionReason) const {

}

// Subtract from sum
template<typename DerivedClass, size_t maximumSerializedMerkleMountainRangeLeafLength, typename SumClass, bool allowDuplicateLookupValues> void MerkleMountainRangeLeaf<DerivedClass, maximumSerializedMerkleMountainRangeLeafLength, SumClass, allowDuplicateLookupValues>::subtractFromSum(SumClass &sum, const SubtractionReason subtractionReason) const {

}

// Get serialized protocol version
template<typename DerivedClass, size_t maximumSerializedMerkleMountainRangeLeafLength, typename SumClass, bool allowDuplicateLookupValues> uint32_t MerkleMountainRangeLeaf<DerivedClass, maximumSerializedMerkleMountainRangeLeafLength, SumClass, allowDuplicateLookupValues>::getSerializedProtocolVersion(const array<uint8_t, MAXIMUM_SERIALIZED_LENGTH> &serializedMerkleMountainRangeLeaf, const typename array<uint8_t, MAXIMUM_SERIALIZED_LENGTH>::size_type serializedMerkleMountainRangeLeafLength, const uint32_t protocolVersion) {

	// Return get serialized protocol version derived class
	return DerivedClass::getSerializedProtocolVersion(serializedMerkleMountainRangeLeaf, serializedMerkleMountainRangeLeafLength, protocolVersion);
}

// Unserialize
template<typename DerivedClass, size_t maximumSerializedMerkleMountainRangeLeafLength, typename SumClass, bool allowDuplicateLookupValues> pair<DerivedClass, array<uint8_t, 0>::size_type> MerkleMountainRangeLeaf<DerivedClass, maximumSerializedMerkleMountainRangeLeafLength, SumClass, allowDuplicateLookupValues>::unserialize(const array<uint8_t, MAXIMUM_SERIALIZED_LENGTH> &serializedMerkleMountainRangeLeaf, const typename array<uint8_t, MAXIMUM_SERIALIZED_LENGTH>::size_type serializedMerkleMountainRangeLeafLength, const uint32_t protocolVersion, const bool isGenesisBlock) {

	// Return unserialized derived class
	return DerivedClass::unserialize(serializedMerkleMountainRangeLeaf, serializedMerkleMountainRangeLeafLength, protocolVersion, isGenesisBlock);
}

// Restore
template<typename DerivedClass, size_t maximumSerializedMerkleMountainRangeLeafLength, typename SumClass, bool allowDuplicateLookupValues> DerivedClass MerkleMountainRangeLeaf<DerivedClass, maximumSerializedMerkleMountainRangeLeafLength, SumClass, allowDuplicateLookupValues>::restore(ifstream &file) {

	// Return restored derived class
	return DerivedClass::restore(file);
}

// Save sum
template<typename DerivedClass, size_t maximumSerializedMerkleMountainRangeLeafLength, typename SumClass, bool allowDuplicateLookupValues> void MerkleMountainRangeLeaf<DerivedClass, maximumSerializedMerkleMountainRangeLeafLength, SumClass, allowDuplicateLookupValues>::saveSum(const SumClass &sum, ofstream &file) {

	// Save sum
	DerivedClass::saveSum(sum, file);
}

// Restore sum
template<typename DerivedClass, size_t maximumSerializedMerkleMountainRangeLeafLength, typename SumClass, bool allowDuplicateLookupValues> void MerkleMountainRangeLeaf<DerivedClass, maximumSerializedMerkleMountainRangeLeafLength, SumClass, allowDuplicateLookupValues>::restoreSum(SumClass &sum, ifstream &file) {

	// Restore sum
	DerivedClass::restoreSum(sum, file);
}


}


#endif
