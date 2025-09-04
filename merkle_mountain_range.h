// Header guard
#ifndef MWC_VALIDATION_NODE_MERKLE_MOUNTAIN_RANGE_H
#define MWC_VALIDATION_NODE_MERKLE_MOUNTAIN_RANGE_H


// Header files
#include "./common.h"
#include <array>
#include <cstring>
#include <fstream>
#include <memory>
#include <optional>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include "blake2.h"
#include "roaring/roaring64map.hh"
#include "./saturate_math.h"
#include "zip.h"

using namespace std;


// Namespace
namespace MwcValidationNode {


// Classes

// Merkle mountain range class
template<typename MerkleMountainRangeLeafDerivedClass> class MerkleMountainRange final {

	// Public
	public:
	
		// Constant iterator
		typedef typename map<uint64_t, MerkleMountainRangeLeafDerivedClass>::const_iterator const_iterator;
		
		// Constant reverse iterator
		typedef typename map<uint64_t, MerkleMountainRangeLeafDerivedClass>::const_reverse_iterator const_reverse_iterator;
		
		// Constructor
		MerkleMountainRange();
		
		// Initializer list constructor
		explicit MerkleMountainRange(const initializer_list<MerkleMountainRangeLeafDerivedClass> &leaves);
		
		// Append leaf
		void appendLeaf(const MerkleMountainRangeLeafDerivedClass &leaf);
		
		// Append leaf
		void appendLeaf(MerkleMountainRangeLeafDerivedClass &&leaf);
		
		// Prune leaf
		void pruneLeaf(const uint64_t leafIndex, const bool permanent = false);
		
		// Get size
		uint64_t getSize() const;
		
		// Get number of leaves
		uint64_t getNumberOfLeaves() const;
		
		// Get leaf
		const MerkleMountainRangeLeafDerivedClass *getLeaf(const uint64_t leafIndex) const;
		
		// Leaf with lookup value exists
		bool leafWithLookupValueExists(const vector<uint8_t> &lookupValue) const;
		
		// Get leaf by lookup value
		const MerkleMountainRangeLeafDerivedClass *getLeafByLookupValue(const vector<uint8_t> &lookupValue) const;
		
		// Get leaf indices by lookup value
		const unordered_set<uint64_t> &getLeafIndicesByLookupValue(const vector<uint8_t> &lookupValue) const;
		
		// Get leaf index by lookup value
		uint64_t getLeafIndexByLookupValue(const vector<uint8_t> &lookupValue) const;
		
		// Rewind to size
		void rewindToSize(const uint64_t size);
		
		// Rewind to number of leaves
		void rewindToNumberOfLeaves(const uint64_t numberOfLeaves);
		
		// Clear
		void clear();
		
		// Get root at size
		array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH> getRootAtSize(const uint64_t size) const;
		
		// Get root at number of leaves
		array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH> getRootAtNumberOfLeaves(const uint64_t numberOfLeaves) const;
		
		// Iterator constant begin
		const_iterator cbegin() const;
		
		// Iterator constant end
		const_iterator cend() const;
		
		// Iterator constant reverse begin
		const_reverse_iterator crbegin() const;
		
		// Iterator constant reverse end
		const_reverse_iterator crend() const;
		
		// Empty
		bool empty() const;
		
		// Front
		const MerkleMountainRangeLeafDerivedClass &front() const;
		
		// Back
		const MerkleMountainRangeLeafDerivedClass &back() const;
		
		// Get sum
		const typename MerkleMountainRangeLeafDerivedClass::Sum &getSum() const;
		
		// Set minimum size
		void setMinimumSize(const uint64_t minimumSize);
		
		// Get minimum size
		uint64_t getMinimumSize() const;
		
		// Save
		void save(ofstream &file) const;
		
		// Restore
		static MerkleMountainRange restore(ifstream &file);
		
		// Create from ZIP
		static MerkleMountainRange createFromZip(zip_t *zip, uint32_t protocolVersion, const char *dataPath, const char *hashesPath, const char *pruneListPath = nullptr, const char *leafSetPath = nullptr);
		
		// Is size valid
		static bool isSizeValid(const uint64_t size);
		
		// Get number of leaves at size
		static uint64_t getNumberOfLeavesAtSize(const uint64_t size);
		
		// Get size at number of leaves
		static uint64_t getSizeAtNumberOfLeaves(const uint64_t numberOfLeaves);
		
		// Get leaf's index
		static uint64_t getLeafsIndex(const uint64_t leafIndex);
		
	// Private
	private:
	
		// Append leaf or pruned leaf
		void appendLeafOrPrunedLeaf(optional<MerkleMountainRangeLeafDerivedClass> &&leafOrPrunedLeaf);
	
		// Set hash at index
		void setHashAtIndex(const uint64_t index, array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH> &&hash);
		
		// Prune hash
		void pruneHash(const uint64_t leafIndex);
		
		// Get peak indices at size
		static vector<uint64_t> getPeakIndicesAtSize(const uint64_t size);
	
		// Get height at index
		static uint64_t getHeightAtIndex(const uint64_t index);
		
		// Get left sibling index
		static uint64_t getLeftSiblingIndex(const uint64_t index);
		
		// Get right sibling index
		static uint64_t getRightSiblingIndex(const uint64_t index);
		
		// Get parent index
		static uint64_t getParentIndex(const uint64_t index);
		
		// Get left child index
		static uint64_t getLeftChildIndex(const uint64_t index);
		
		// Get right child index
		static uint64_t getRightChildIndex(const uint64_t index);
		
		// Get next peak index
		static uint64_t getNextPeakIndex(const uint64_t index);
		
		// Lookup table
		unordered_map<vector<uint8_t>, unordered_set<uint64_t>, Common::Uint8VectorHash> lookupTable;
		
		// Unpruned leaves
		map<uint64_t, MerkleMountainRangeLeafDerivedClass> unprunedLeaves;
		
		// Number of leaves
		uint64_t numberOfLeaves;
		
		// Unpruned hashes
		map<uint64_t, array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH>> unprunedHashes;
		
		// Number of hashes
		uint64_t numberOfHashes;
		
		// Minimum size
		uint64_t minimumSize;
		
		// Sum
		typename MerkleMountainRangeLeafDerivedClass::Sum sum;
		
		// Prune history
		map<uint64_t, unordered_set<uint64_t>> pruneHistory;
		
		// Prune list
		unordered_map<uint64_t, MerkleMountainRangeLeafDerivedClass> pruneList;
};


// Supporting function implementation

// Constructor
template<typename MerkleMountainRangeLeafDerivedClass> MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::MerkleMountainRange() :

	// Set number of leaves to zero
	numberOfLeaves(0),
	
	// Set number of hashes to zero
	numberOfHashes(0),
	
	// Set minimum size to zero
	minimumSize(0)
{

	// Set sum to zero
	memset(&sum, 0, sizeof(sum));
}

// Initializer list constructor
template<typename MerkleMountainRangeLeafDerivedClass> MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::MerkleMountainRange(const initializer_list<MerkleMountainRangeLeafDerivedClass> &leaves) :

	// Set number of leaves to zero
	numberOfLeaves(0),
	
	// Set number of hashes to zero
	numberOfHashes(0),
	
	// Set minimum size to zero
	minimumSize(0)
{

	// Set sum to zero
	memset(&sum, 0, sizeof(sum));
	
	// Go through all leaves
	for(const MerkleMountainRangeLeafDerivedClass &leaf : leaves) {
	
		// Append leaf
		appendLeaf(leaf);
	}
}

// Append leaf
template<typename MerkleMountainRangeLeafDerivedClass> void MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::appendLeaf(const MerkleMountainRangeLeafDerivedClass &leaf) {

	// Append leaf
	appendLeafOrPrunedLeaf(optional<MerkleMountainRangeLeafDerivedClass>(leaf));
}

// Append leaf
template<typename MerkleMountainRangeLeafDerivedClass> void MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::appendLeaf(MerkleMountainRangeLeafDerivedClass &&leaf) {

	// Append leaf
	appendLeafOrPrunedLeaf(optional<MerkleMountainRangeLeafDerivedClass>(move(leaf)));
}

// Prune leaf
template<typename MerkleMountainRangeLeafDerivedClass> void MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::pruneLeaf(const uint64_t leafIndex, const bool permanent) {

	// Check if leaf index is invalid
	if(leafIndex >= numberOfLeaves) {
	
		// Throw exception
		throw runtime_error("Leaf index is invalid");
	}
	
	// Check if leaf is pruned
	if(!unprunedLeaves.contains(leafIndex)) {
	
		// Throw exception
		throw runtime_error("Leaf is pruned");
	}
	
	// Check if leaf has a lookup value
	const optional<vector<uint8_t>> lookupValue = unprunedLeaves.at(leafIndex).getLookupValue();
	if(lookupValue.has_value()) {
	
		// Remove leaf from lookup value from the lookup table
		lookupTable.at(lookupValue.value()).erase(leafIndex);
		
		// Check if no more leaves have the lookup value
		if(lookupTable.at(lookupValue.value()).empty()) {
		
			// Remove lookup value from the lookup table
			lookupTable.erase(lookupValue.value());
		}
	}
	
	// Subtract from sum
	unprunedLeaves.at(leafIndex).subtractFromSum(sum, MerkleMountainRangeLeafDerivedClass::SubtractionReason::PRUNED);
	
	// Check if permanent
	if(permanent) {
	
		// Remove leaf
		unprunedLeaves.erase(leafIndex);
		
		// Prune leaf's hash
		pruneHash(leafIndex);
	}
	
	// Otherwise
	else {
	
		// Add prune event to the prune history
		pruneHistory[numberOfLeaves].insert(leafIndex);
		
		// Move leaf to the prune list
		pruneList.emplace(leafIndex, move(unprunedLeaves.extract(leafIndex).mapped()));
	}
}

// Get size
template<typename MerkleMountainRangeLeafDerivedClass> uint64_t MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::getSize() const {

	// Return number of hashes
	return numberOfHashes;
}

// Get number of leaves
template<typename MerkleMountainRangeLeafDerivedClass> uint64_t MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::getNumberOfLeaves() const {

	// Return number of leaves
	return numberOfLeaves;
}

// Get leaf
template<typename MerkleMountainRangeLeafDerivedClass> const MerkleMountainRangeLeafDerivedClass *MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::getLeaf(const uint64_t leafIndex) const {

	// Check if leaf doesn't exist or is pruned
	if(!unprunedLeaves.contains(leafIndex)) {
	
		// Return null
		return nullptr;
	}
	
	// Return leaf
	return &unprunedLeaves.at(leafIndex);
}

// Leaf with lookup value exists
template<typename MerkleMountainRangeLeafDerivedClass> bool MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::leafWithLookupValueExists(const vector<uint8_t> &lookupValue) const {

	// Return if lookup value exists in the lookup table
	return lookupTable.contains(lookupValue);
}

// Get leaf by lookup value
template<typename MerkleMountainRangeLeafDerivedClass> const MerkleMountainRangeLeafDerivedClass *MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::getLeafByLookupValue(const vector<uint8_t> &lookupValue) const {

	// Check if duplicate lookup values are allowed
	if(MerkleMountainRangeLeafDerivedClass::ALLOW_DUPLICATE_LOOKUP_VALUES) {
	
		// Throw exception
		throw runtime_error("Lookup value can be more than one leaf");
	}
	
	// Check if lookup value doesn't exist in the lookup table
	if(!lookupTable.contains(lookupValue)) {
	
		// Return null
		return nullptr;
	}
	
	// Return first leaf with the lookup value
	return getLeaf(*lookupTable.at(lookupValue).cbegin());
}

// Get leaf indices by lookup value
template<typename MerkleMountainRangeLeafDerivedClass> const unordered_set<uint64_t> &MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::getLeafIndicesByLookupValue(const vector<uint8_t> &lookupValue) const {

	// Check if lookup value doesn't exist in the lookup table
	if(!lookupTable.contains(lookupValue)) {
	
		// Throw exception
		throw runtime_error("Lookup value doesn't exist in the lookup table");
	}
	
	// Return leaf indices with the lookup value
	return lookupTable.at(lookupValue);
}

// Get leaf index by lookup value
template<typename MerkleMountainRangeLeafDerivedClass> uint64_t MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::getLeafIndexByLookupValue(const vector<uint8_t> &lookupValue) const {

	// Check if duplicate lookup values are allowed
	if(MerkleMountainRangeLeafDerivedClass::ALLOW_DUPLICATE_LOOKUP_VALUES) {
	
		// Throw exception
		throw runtime_error("Lookup value can be more than one leaf");
	}
	
	// Return first leaf index with the lookup value
	return *getLeafIndicesByLookupValue(lookupValue).cbegin();
}

// Rewind to size
template<typename MerkleMountainRangeLeafDerivedClass> void MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::rewindToSize(const uint64_t size) {

	// Check if size is invalid
	if(size > numberOfHashes || !isSizeValid(size) || size < minimumSize) {
	
		// Throw exception
		throw runtime_error("Size is invalid");
	}
	
	// Set number of hashes to size
	numberOfHashes = size;
	
	// Check if hashes exist
	if(numberOfHashes) {
	
		// Check if unpruned hashes can be removed
		const map<uint64_t, array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH>>::const_iterator start = unprunedHashes.upper_bound(numberOfHashes - 1);
		if(start != unprunedHashes.cend()) {
	
			// Remove trailing unpruned hashes
			unprunedHashes.erase(start, unprunedHashes.cend());
		}
	}
	
	// Otherwise
	else {
	
		// Clear all unpruned hashes
		unprunedHashes.clear();
	}
	
	// Set number of leaves to number of leaves at size
	numberOfLeaves = getNumberOfLeavesAtSize(size);
	
	// Check if leaves exist
	if(numberOfLeaves) {
	
		// Check if unpruned leaves can be removed
		const typename map<uint64_t, MerkleMountainRangeLeafDerivedClass>::const_iterator start = unprunedLeaves.upper_bound(numberOfLeaves - 1);
		if(start != unprunedLeaves.cend()) {
		
			// Go through all leaves that will be removed
			for(typename map<uint64_t, MerkleMountainRangeLeafDerivedClass>::const_iterator i = start; i != unprunedLeaves.cend(); ++i) {
			
				// Get leaf
				const MerkleMountainRangeLeafDerivedClass &leaf = i->second;
				
				// Check if leaf has a lookup value
				const optional<vector<uint8_t>> lookupValue = leaf.getLookupValue();
				if(lookupValue.has_value()) {
				
					// Remove leaf from lookup value from the lookup table
					lookupTable.at(lookupValue.value()).erase(i->first);
					
					// Check if no more leaves have the lookup value
					if(lookupTable.at(lookupValue.value()).empty()) {
					
						// Remove lookup value from the lookup table
						lookupTable.erase(lookupValue.value());
					}
				}
				
				// Subtract from sum
				leaf.subtractFromSum(sum, MerkleMountainRangeLeafDerivedClass::SubtractionReason::REWINDED);
			}
	
			// Remove trailing pruned leaves
			unprunedLeaves.erase(start, unprunedLeaves.cend());
		}
		
		// Go through all prune history events from newest to oldest
		for(map<uint64_t, unordered_set<uint64_t>>::const_reverse_iterator i = pruneHistory.crbegin(); i != pruneHistory.crend(); ++i) {
		
			// Check if prune history event was rewinded
			if(i->first > numberOfLeaves) {
			
				// Get pruned leaf indices in the prune history event
				const unordered_set<uint64_t> &prunedLeafIndices = i->second;
				
				// Go through all pruned leaf indices
				for(const uint64_t prunedLeafIndex : prunedLeafIndices) {
				
					// Check if pruned leaf can be restored
					if(prunedLeafIndex < numberOfLeaves) {
					
						// Move pruned leaf to unpruned leaves
						unprunedLeaves.emplace(prunedLeafIndex, move(pruneList.extract(prunedLeafIndex).mapped()));
						
						// Check if pruned leaf has a lookup value
						optional<vector<uint8_t>> lookupValue = unprunedLeaves.at(prunedLeafIndex).getLookupValue();
						if(lookupValue.has_value()) {
						
							// Check if lookup value exists in the lookup table
							if(lookupTable.contains(lookupValue.value())) {
							
								// Add leaf to lookup value in the lookup table
								lookupTable.at(lookupValue.value()).insert(prunedLeafIndex);
							}
							
							// Otherwise
							else {
						
								// Append lookup value to the lookup table
								lookupTable.emplace(move(lookupValue.value()), unordered_set<uint64_t>({prunedLeafIndex}));
							}
						}
						
						// Add to sum
						unprunedLeaves.at(prunedLeafIndex).addToSum(sum, MerkleMountainRangeLeafDerivedClass::AdditionReason::RESTORED);
					}
					
					// Otherwise
					else {
					
						// Subtract from sum
						pruneList.at(prunedLeafIndex).subtractFromSum(sum, MerkleMountainRangeLeafDerivedClass::SubtractionReason::DISCARDED);
						
						// Remove pruned leaf
						pruneList.erase(prunedLeafIndex);
					}
				}
			}
			
			// Otherwise
			else {
			
				// Check if a prune history event was rewinded
				if(i != pruneHistory.crbegin()) {
				
					// Remove rewinded prune history events
					pruneHistory.erase(i.base(), pruneHistory.cend());
				}
			
				// break
				break;
			}
			
			// Check if all prune history events were rewinded
			if(next(i) == pruneHistory.crend()) {
			
				// Clear prune history
				pruneHistory.clear();
				
				// Break
				break;
			}
		}
	}
	
	// Otherwise
	else {
	
		// Clear lookup table
		lookupTable.clear();
		
		// Set sum to zero
		memset(&sum, 0, sizeof(sum));
	
		// Clear all unpruned leaves
		unprunedLeaves.clear();
		
		// Clear prune history
		pruneHistory.clear();
		
		// Clear prune list
		pruneList.clear();
	}
}

// Rewind to number of leaves
template<typename MerkleMountainRangeLeafDerivedClass> void MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::rewindToNumberOfLeaves(const uint64_t numberOfLeaves) {

	// Rewind to size at the number of leaves
	rewindToSize(getSizeAtNumberOfLeaves(numberOfLeaves));
}

// Get leaf's index
template<typename MerkleMountainRangeLeafDerivedClass> uint64_t MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::getLeafsIndex(const uint64_t leafIndex) {

	// Return leaf's index
	return 2 * leafIndex - Common::numberOfOnes(leafIndex);
}

// Clear
template<typename MerkleMountainRangeLeafDerivedClass> void MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::clear() {

	// Set number of leaves to zero
	numberOfLeaves = 0;
	
	// Set number of hashes to zero
	numberOfHashes = 0;
	
	// Set minimum size to zero
	minimumSize = 0;
	
	// Clear lookup table
	lookupTable.clear();
	
	// Set sum to zero
	memset(&sum, 0, sizeof(sum));
	
	// Clear unpruned leaves
	unprunedLeaves.clear();
	
	// Clear unpruned hashes
	unprunedHashes.clear();
	
	// Clear prune history
	pruneHistory.clear();
	
	// Clear prune list
	pruneList.clear();
	
	// Free memory
	Common::freeMemory();
}

// Get root at size
template<typename MerkleMountainRangeLeafDerivedClass> array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH> MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::getRootAtSize(const uint64_t size) const {

	// Check if size is invalid
	if(size > numberOfHashes || !isSizeValid(size) || size < minimumSize) {
	
		// Throw exception
		throw runtime_error("Size is invalid");
	}

	// Initialize root
	array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH> root;
	
	// Get peak indices at size
	const vector peakIndices = getPeakIndicesAtSize(size);
	
	// Check if peak indices exist
	if(!peakIndices.empty()) {
	
		// Set root to the last peak's hash
		memcpy(root.data(), unprunedHashes.at(*peakIndices.crbegin()).data(), root.size());
		
		// Go through all remaining peaks in reverse
		for(vector<uint64_t>::const_reverse_iterator i = peakIndices.crbegin() + 1; i != peakIndices.crend(); ++i) {
		
			// Get peak hash
			const array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH> &peakHash = unprunedHashes.at(*i);
			
			// Create index and hashes
			const uint64_t indexBigEndian = Common::hostByteOrderToBigEndian(size);
			uint8_t indexAndHashes[sizeof(indexBigEndian) + peakHash.size() + root.size()];
			memcpy(indexAndHashes, &indexBigEndian, sizeof(indexBigEndian));
			memcpy(&indexAndHashes[sizeof(indexBigEndian)], peakHash.data(), peakHash.size());
			memcpy(&indexAndHashes[sizeof(indexBigEndian) + peakHash.size()], root.data(), root.size());
			
			// Check if updating root failed
			if(blake2b(root.data(), root.size(), indexAndHashes, sizeof(indexAndHashes), nullptr, 0)) {
			
				// Throw exception
				throw runtime_error("Updating root failed");
			}
		}
	}
	
	// Otherwise
	else {
	
		// Set root to zero hash
		root.fill(0);
	}
	
	// Return root
	return root;
}

// Get root at number of leaves
template<typename MerkleMountainRangeLeafDerivedClass> array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH> MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::getRootAtNumberOfLeaves(const uint64_t numberOfLeaves) const {

	// Get root at size at the number of leaves
	return getRootAtSize(getSizeAtNumberOfLeaves(numberOfLeaves));
}

// Iterator constant begin
template<typename MerkleMountainRangeLeafDerivedClass> typename MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::const_iterator MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::cbegin() const {

	// Return unpruned leaves constant begin
	return unprunedLeaves.cbegin();
}

// Iterator constant end
template<typename MerkleMountainRangeLeafDerivedClass> typename MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::const_iterator MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::cend() const {

	// Return unpruned leaves constant end
	return unprunedLeaves.cend();
}

// Iterator constant reverse begin
template<typename MerkleMountainRangeLeafDerivedClass> typename MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::const_reverse_iterator MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::crbegin() const {

	// Return unpruned leaves constant reverse begin
	return unprunedLeaves.crbegin();
}

// Iterator constant reverse end
template<typename MerkleMountainRangeLeafDerivedClass> typename MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::const_reverse_iterator MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::crend() const {

	// Return unpruned leaves constant reverse end
	return unprunedLeaves.crend();
}

// Empty
template<typename MerkleMountainRangeLeafDerivedClass> bool MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::empty() const {

	// Return if unpruned leaves is empty
	return unprunedLeaves.empty();
}

// Front
template<typename MerkleMountainRangeLeafDerivedClass> const MerkleMountainRangeLeafDerivedClass &MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::front() const {

	// Check if no unpruned leaves exist
	if(unprunedLeaves.empty()) {
	
		// Throw exception
		throw runtime_error("No unpruned leaves exist");
	}
	
	// Return first unpruned leaf
	return unprunedLeaves.cbegin()->second;
}

// Back
template<typename MerkleMountainRangeLeafDerivedClass> const MerkleMountainRangeLeafDerivedClass &MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::back() const {

	// Check if no unpruned leaves exist
	if(unprunedLeaves.empty()) {
	
		// Throw exception
		throw runtime_error("No unpruned leaves exist");
	}
	
	// Return last unpruned leaf
	return unprunedLeaves.crbegin()->second;
}

// Get sum
template<typename MerkleMountainRangeLeafDerivedClass> const typename MerkleMountainRangeLeafDerivedClass::Sum &MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::getSum() const {

	// Return sum
	return sum;
}

// Set minimum size
template<typename MerkleMountainRangeLeafDerivedClass> void MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::setMinimumSize(const uint64_t minimumSize) {

	// Check if minimum size is invalid
	if(!isSizeValid(minimumSize) || minimumSize < this->minimumSize) {
	
		// Throw exception
		throw runtime_error("Minimum size is invalid");
	}
	
	// Set minimum size to minimum size
	this->minimumSize = minimumSize;
	
	// Get minimum number of leaves at the minimum size
	const uint64_t minimumNumberOfLeaves = getNumberOfLeavesAtSize(minimumSize);
	
	// Check if minimum number of leaves exist
	if(minimumNumberOfLeaves) {
	
		// Check if prune history events can be removed
		const map<uint64_t, unordered_set<uint64_t>>::const_iterator start = pruneHistory.upper_bound(minimumNumberOfLeaves);
		if(start != pruneHistory.cbegin()) {
		
			// Go through all prune history events that will be removed
			for(map<uint64_t, unordered_set<uint64_t>>::const_iterator i = pruneHistory.cbegin(); i != start; ++i) {
			
				// Get pruned leaf indices in the prune history event
				const unordered_set<uint64_t> &prunedLeafIndices = i->second;
				
				// Go through all pruned leaf indices
				for(const uint64_t prunedLeafIndex : prunedLeafIndices) {
				
					// Remove pruned leaf from the prune list
					pruneList.erase(prunedLeafIndex);
					
					// Prune pruned leaf's hash
					pruneHash(prunedLeafIndex);
				}
			}
	
			// Remove prune history events
			pruneHistory.erase(pruneHistory.cbegin(), start);
		}
	}
}

// Get minimum size
template<typename MerkleMountainRangeLeafDerivedClass> uint64_t MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::getMinimumSize() const {

	// Return minimum size
	return minimumSize;
}

// Save
template<typename MerkleMountainRangeLeafDerivedClass> void MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::save(ofstream &file) const {

	// Write lookup table size to file
	const uint64_t serializedLookupTableSize = Common::hostByteOrderToBigEndian(lookupTable.size());
	file.write(reinterpret_cast<const char *>(&serializedLookupTableSize), sizeof(serializedLookupTableSize));
	
	// Go through all lookup values in the lookup table
	for(const pair<const vector<uint8_t>, unordered_set<uint64_t>> &lookupValue : lookupTable) {
	
		// Write lookup value size to file
		const uint64_t serializedLookupValueSize = Common::hostByteOrderToBigEndian(lookupValue.first.size());
		file.write(reinterpret_cast<const char *>(&serializedLookupValueSize), sizeof(serializedLookupValueSize));
		
		// Write lookup value to file
		file.write(reinterpret_cast<const char *>(lookupValue.first.data()), lookupValue.first.size());
		
		// Check if duplicate lookup values are allowed
		if(MerkleMountainRangeLeafDerivedClass::ALLOW_DUPLICATE_LOOKUP_VALUES) {
		
			// Write lookup value number of leaves to file
			const uint64_t serializedLookupValueNumberOfLeaves = Common::hostByteOrderToBigEndian(lookupValue.second.size());
			file.write(reinterpret_cast<const char *>(&serializedLookupValueNumberOfLeaves), sizeof(serializedLookupValueNumberOfLeaves));
			
			// Go through all leaves in the lookup value
			for(const uint64_t leafIndex : lookupValue.second) {
			
				// Write leaf index to file
				const uint64_t serializedLeafIndex = Common::hostByteOrderToBigEndian(leafIndex);
				file.write(reinterpret_cast<const char *>(&serializedLeafIndex), sizeof(serializedLeafIndex));
			}
		}
		
		// Otherwise
		else {
		
			// Write lookup value first leaf index to file
			const uint64_t serializedFirstLeafIndex = Common::hostByteOrderToBigEndian(*lookupValue.second.cbegin());
			file.write(reinterpret_cast<const char *>(&serializedFirstLeafIndex), sizeof(serializedFirstLeafIndex));
		}
	}
	
	// Write unpruned leaves size to file
	const uint64_t serializedUnprunedLeavesSize = Common::hostByteOrderToBigEndian(unprunedLeaves.size());
	file.write(reinterpret_cast<const char *>(&serializedUnprunedLeavesSize), sizeof(serializedUnprunedLeavesSize));
	
	// Go through all unpruned leaves
	for(const pair<const uint64_t, MerkleMountainRangeLeafDerivedClass> &unprunedLeaf : unprunedLeaves) {
	
		// Write leaf index to file
		const uint64_t serializedLeafIndex = Common::hostByteOrderToBigEndian(unprunedLeaf.first);
		file.write(reinterpret_cast<const char *>(&serializedLeafIndex), sizeof(serializedLeafIndex));
		
		// Write leaf to file
		unprunedLeaf.second.save(file);
	}
	
	// Write number of leaves to file
	const uint64_t serializedNumberOfLeaves = Common::hostByteOrderToBigEndian(numberOfLeaves);
	file.write(reinterpret_cast<const char *>(&serializedNumberOfLeaves), sizeof(serializedNumberOfLeaves));
	
	// Write unpruned hashes size to file
	const uint64_t serializedUnprunedHashesSize = Common::hostByteOrderToBigEndian(unprunedHashes.size());
	file.write(reinterpret_cast<const char *>(&serializedUnprunedHashesSize), sizeof(serializedUnprunedHashesSize));
	
	// Go through all unpruned hashes
	for(const pair<const uint64_t, array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH>> &unprunedHash : unprunedHashes) {
	
		// Write index to file
		const uint64_t serializedIndex = Common::hostByteOrderToBigEndian(unprunedHash.first);
		file.write(reinterpret_cast<const char *>(&serializedIndex), sizeof(serializedIndex));
		
		// Write hash to file
		file.write(reinterpret_cast<const char *>(unprunedHash.second.data()), unprunedHash.second.size());
	}
	
	// Write number of hashes to file
	const uint64_t serializedNumberOfHashes = Common::hostByteOrderToBigEndian(numberOfHashes);
	file.write(reinterpret_cast<const char *>(&serializedNumberOfHashes), sizeof(serializedNumberOfHashes));
	
	// Write minimum size to file
	const uint64_t serializedMinimumSize = Common::hostByteOrderToBigEndian(minimumSize);
	file.write(reinterpret_cast<const char *>(&serializedMinimumSize), sizeof(serializedMinimumSize));
	
	// Write sum to file
	MerkleMountainRangeLeafDerivedClass::saveSum(sum, file);
	
	// Write prune history size to file
	const uint64_t serializedPruneHistorySize = Common::hostByteOrderToBigEndian(pruneHistory.size());
	file.write(reinterpret_cast<const char *>(&serializedPruneHistorySize), sizeof(serializedPruneHistorySize));
	
	// Go through all prune history events
	for(const pair<const uint64_t, unordered_set<uint64_t>> &pruneHistoryEvent : pruneHistory) {
	
		// Write prune history event number of leaves to file
		const uint64_t serializedPruneHistoryEventNumberOfLeaves = Common::hostByteOrderToBigEndian(pruneHistoryEvent.first);
		file.write(reinterpret_cast<const char *>(&serializedPruneHistoryEventNumberOfLeaves), sizeof(serializedPruneHistoryEventNumberOfLeaves));
		
		// Write prune history event size to file
		const uint64_t serializedPruneHistoryEventSize = Common::hostByteOrderToBigEndian(pruneHistoryEvent.second.size());
		file.write(reinterpret_cast<const char *>(&serializedPruneHistoryEventSize), sizeof(serializedPruneHistoryEventSize));
		
		// Go through all leaves pruned in the event
		for(const uint64_t leafIndex : pruneHistoryEvent.second) {
		
			// Write leaf index to file
			const uint64_t serializedLeafIndex = Common::hostByteOrderToBigEndian(leafIndex);
			file.write(reinterpret_cast<const char *>(&serializedLeafIndex), sizeof(serializedLeafIndex));
		}
	}
	
	// Write prune list size to file
	const uint64_t serializedPruneListSize = Common::hostByteOrderToBigEndian(pruneList.size());
	file.write(reinterpret_cast<const char *>(&serializedPruneListSize), sizeof(serializedPruneListSize));
	
	// Go through all leaves in the prune list
	for(const pair<const uint64_t, MerkleMountainRangeLeafDerivedClass> &leaf : pruneList) {
	
		// Write leaf index to file
		const uint64_t serializedLeafIndex = Common::hostByteOrderToBigEndian(leaf.first);
		file.write(reinterpret_cast<const char *>(&serializedLeafIndex), sizeof(serializedLeafIndex));
		
		// Write leaf to file
		leaf.second.save(file);
	}
}

// Restore
template<typename MerkleMountainRangeLeafDerivedClass> MerkleMountainRange<MerkleMountainRangeLeafDerivedClass> MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::restore(ifstream &file) {

	// Initialize Merkle mountain range
	MerkleMountainRange merkleMountainRange;
	
	// Read lookup table size from file
	uint64_t serializedLookupTableSize;
	file.read(reinterpret_cast<char *>(&serializedLookupTableSize), sizeof(serializedLookupTableSize));
	const uint64_t lookupTableSize = Common::bigEndianToHostByteOrder(serializedLookupTableSize);
	
	// Go through all lookup values in the lookup table
	for(uint64_t i = 0; i < lookupTableSize; ++i) {
	
		// Read lookup value size from file
		uint64_t serializedLookupValueSize;
		file.read(reinterpret_cast<char *>(&serializedLookupValueSize), sizeof(serializedLookupValueSize));
		
		// Read lookup value from file
		vector<uint8_t> lookupValue(Common::bigEndianToHostByteOrder(serializedLookupValueSize));
		file.read(reinterpret_cast<char *>(lookupValue.data()), lookupValue.size());
		
		// Check if duplicate lookup values are allowed
		if(MerkleMountainRangeLeafDerivedClass::ALLOW_DUPLICATE_LOOKUP_VALUES) {
		
			// Read lookup value number of leaves from file
			uint64_t serializedLookupValueNumberOfLeaves;
			file.read(reinterpret_cast<char *>(&serializedLookupValueNumberOfLeaves), sizeof(serializedLookupValueNumberOfLeaves));
			const uint64_t lookupValueNumberOfLeaves = Common::bigEndianToHostByteOrder(serializedLookupValueNumberOfLeaves);
			
			// Go through all leaves in the lookup value
			unordered_set<uint64_t> leaves;
			for(uint64_t j = 0; j < lookupValueNumberOfLeaves; ++j) {
			
				// Read leaf index from file
				uint64_t serializedLeafIndex;
				file.read(reinterpret_cast<char *>(&serializedLeafIndex), sizeof(serializedLeafIndex));
				
				// Add leaf index to leaves
				leaves.insert(Common::bigEndianToHostByteOrder(serializedLeafIndex));
			}
			
			// Add lookup value to lookup table
			merkleMountainRange.lookupTable.emplace(move(lookupValue), move(leaves));
		}
		
		// Otherwise
		else {
		
			// Read lookup value first leaf index from file
			uint64_t serializedFirstLeafIndex;
			file.read(reinterpret_cast<char *>(&serializedFirstLeafIndex), sizeof(serializedFirstLeafIndex));
			
			// Add lookup value to lookup table
			merkleMountainRange.lookupTable.emplace(move(lookupValue), unordered_set<uint64_t>({Common::bigEndianToHostByteOrder(serializedFirstLeafIndex)}));
		}
	}
	
	// Read unpruned leaves size from file
	uint64_t serializedUnprunedLeavesSize;
	file.read(reinterpret_cast<char *>(&serializedUnprunedLeavesSize), sizeof(serializedUnprunedLeavesSize));
	const uint64_t unprunedLeavesSize = Common::bigEndianToHostByteOrder(serializedUnprunedLeavesSize);
	
	// Go through all unpruned leaves
	for(uint64_t i = 0; i < unprunedLeavesSize; ++i) {
	
		// Read leaf index from file
		uint64_t serializedLeafIndex;
		file.read(reinterpret_cast<char *>(&serializedLeafIndex), sizeof(serializedLeafIndex));
		
		// Read leaf from file and add it to unpruned leaves
		merkleMountainRange.unprunedLeaves.emplace(Common::bigEndianToHostByteOrder(serializedLeafIndex), MerkleMountainRangeLeafDerivedClass::restore(file));
	}
	
	// Read number of leaves from file
	uint64_t serializedNumberOfLeaves;
	file.read(reinterpret_cast<char *>(&serializedNumberOfLeaves), sizeof(serializedNumberOfLeaves));
	merkleMountainRange.numberOfLeaves = Common::bigEndianToHostByteOrder(serializedNumberOfLeaves);
	
	// Read unpruned hashes size from file
	uint64_t serializedUnprunedHashesSize;
	file.read(reinterpret_cast<char *>(&serializedUnprunedHashesSize), sizeof(serializedUnprunedHashesSize));
	const uint64_t unprunedHashesSize = Common::bigEndianToHostByteOrder(serializedUnprunedHashesSize);
	
	// Go through all unpruned hashes
	for(uint64_t i = 0; i < unprunedHashesSize; ++i) {
	
		// Read index from file
		uint64_t serializedIndex;
		file.read(reinterpret_cast<char *>(&serializedIndex), sizeof(serializedIndex));
		
		// Read hash from file
		array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH> hash;
		file.read(reinterpret_cast<char *>(hash.data()), hash.size());
		
		// Add hash to unpruned hashes
		merkleMountainRange.unprunedHashes.emplace(Common::bigEndianToHostByteOrder(serializedIndex), move(hash));
	}
	
	// Read number of hashes from file
	uint64_t serializedNumberOfHashes;
	file.read(reinterpret_cast<char *>(&serializedNumberOfHashes), sizeof(serializedNumberOfHashes));
	merkleMountainRange.numberOfHashes = Common::bigEndianToHostByteOrder(serializedNumberOfHashes);
	
	// Read minimum size from file
	uint64_t serializedMinimumSize;
	file.read(reinterpret_cast<char *>(&serializedMinimumSize), sizeof(serializedMinimumSize));
	merkleMountainRange.minimumSize = Common::bigEndianToHostByteOrder(serializedMinimumSize);
	
	// Read sum from file
	MerkleMountainRangeLeafDerivedClass::restoreSum(merkleMountainRange.sum, file);
	
	// Read prune history size from file
	uint64_t serializedPruneHistorySize;
	file.read(reinterpret_cast<char *>(&serializedPruneHistorySize), sizeof(serializedPruneHistorySize));
	const uint64_t pruneHistorySize = Common::bigEndianToHostByteOrder(serializedPruneHistorySize);
	
	// Go through all prune history events
	for(uint64_t i = 0; i < pruneHistorySize; ++i) {
	
		// Read prune history event number of leaves from file
		uint64_t serializedPruneHistoryEventNumberOfLeaves;
		file.read(reinterpret_cast<char *>(&serializedPruneHistoryEventNumberOfLeaves), sizeof(serializedPruneHistoryEventNumberOfLeaves));
		
		// Read prune history event size from file
		uint64_t serializedPruneHistoryEventSize;
		file.read(reinterpret_cast<char *>(&serializedPruneHistoryEventSize), sizeof(serializedPruneHistoryEventSize));
		const uint64_t pruneHistoryEventSize = Common::bigEndianToHostByteOrder(serializedPruneHistoryEventSize);
		
		// Go through all leaves pruned in the event
		unordered_set<uint64_t> prunedLeaves;
		for(uint64_t j = 0; j < pruneHistoryEventSize; ++j) {
		
			// Read leaf index from file
			uint64_t serializedLeafIndex;
			file.read(reinterpret_cast<char *>(&serializedLeafIndex), sizeof(serializedLeafIndex));
			
			// Add leaf index to pruned leaves
			prunedLeaves.insert(Common::bigEndianToHostByteOrder(serializedLeafIndex));
		}
		
		// Add prune history event to prune history events
		merkleMountainRange.pruneHistory.emplace(Common::bigEndianToHostByteOrder(serializedPruneHistoryEventNumberOfLeaves), move(prunedLeaves));
	}
	
	// Read prune list size from file
	uint64_t serializedPruneListSize;
	file.read(reinterpret_cast<char *>(&serializedPruneListSize), sizeof(serializedPruneListSize));
	const uint64_t pruneListSize = Common::bigEndianToHostByteOrder(serializedPruneListSize);
	
	// Go through all leaves in the prune list
	for(uint64_t i = 0; i < pruneListSize; ++i) {
	
		// Read leaf index from file
		uint64_t serializedLeafIndex;
		file.read(reinterpret_cast<char *>(&serializedLeafIndex), sizeof(serializedLeafIndex));
		
		// Read leaf from file and add it to prune list
		merkleMountainRange.pruneList.emplace(Common::bigEndianToHostByteOrder(serializedLeafIndex), MerkleMountainRangeLeafDerivedClass::restore(file));
	}
	
	// Return Merkle mountain range
	return merkleMountainRange;
}

// Create from ZIP
template<typename MerkleMountainRangeLeafDerivedClass> MerkleMountainRange<MerkleMountainRangeLeafDerivedClass> MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::createFromZip(zip_t *zip, uint32_t protocolVersion, const char *dataPath, const char *hashesPath, const char *pruneListPath, const char *leafSetPath) {

	// Initialize prune list
	roaring::Roaring pruneList;
	
	// Check if prune list path exists
	if(pruneListPath) {
	
		// Initialize file info
		zip_stat_t fileInfo;
		zip_stat_init(&fileInfo);
		
		// Check if getting prune list file info failed
		if(zip_stat(zip, pruneListPath, ZIP_FL_ENC_STRICT | ZIP_FL_ENC_UTF_8, &fileInfo)) {
		
			// Throw exception
			throw runtime_error("Getting prune list file info failed");
		}
		
		// Check if opening prune list file in the ZIP failed
		unique_ptr<zip_file_t, decltype(&zip_fclose)> file(zip_fopen(zip, pruneListPath, ZIP_FL_ENC_STRICT | ZIP_FL_ENC_UTF_8), zip_fclose);
		if(!file) {
		
			// Throw exception
			throw runtime_error("Opening prune list file in the ZIP failed");
		}
		
		// Initialize buffer
		unique_ptr buffer = make_unique<uint8_t []>(fileInfo.size);
	
		// Go through all bytes in the file
		zip_int64_t bytesRead;
		zip_uint64_t remainingBufferSize = fileInfo.size;
		do {
		
			// Read bytes into buffer
			bytesRead = zip_fread(file.get(), &buffer.get()[fileInfo.size - remainingBufferSize], remainingBufferSize);
				
			// Check if reading bytes failed
			if(bytesRead == -1) {
			
				// Throw exception
				throw runtime_error("Reading bytes failed");
			}
			
			// Update remaining buffer size
			remainingBufferSize -= bytesRead;
		
		} while(bytesRead);
		
		// Check if buffer was partially filled
		if(remainingBufferSize) {
		
			// Throw exception
			throw runtime_error("Buffer was partially filled");
		}
		
		// Get prune list
		pruneList = roaring::Roaring::readSafe(reinterpret_cast<char *>(buffer.get()), fileInfo.size);
	}
	
	// Initialize Merkle mountain range
	MerkleMountainRange merkleMountainRange;
	
	// Initialize expecting all hashes
	bool expectingAllHashes;
	
	{
		// Initialize leaf set
		roaring::Roaring leafSet;
		
		// Check if leaf set path exists
		if(leafSetPath) {
		
			// Initialize file info
			zip_stat_t fileInfo;
			zip_stat_init(&fileInfo);
			
			// Check if getting leaf set file info failed
			if(zip_stat(zip, leafSetPath, ZIP_FL_ENC_STRICT | ZIP_FL_ENC_UTF_8, &fileInfo)) {
			
				// Throw exception
				throw runtime_error("Getting leaf set file info failed");
			}
			
			// Check if opening leaf set file in the ZIP failed
			unique_ptr<zip_file_t, decltype(&zip_fclose)> file(zip_fopen(zip, leafSetPath, ZIP_FL_ENC_STRICT | ZIP_FL_ENC_UTF_8), zip_fclose);
			if(!file) {
			
				// Throw exception
				throw runtime_error("Opening leaf set file in the ZIP failed");
			}
			
			// Initialize buffer
			unique_ptr buffer = make_unique<uint8_t []>(fileInfo.size);
		
			// Go through all bytes in the file
			zip_int64_t bytesRead;
			zip_uint64_t remainingBufferSize = fileInfo.size;
			do {
			
				// Read bytes into buffer
				bytesRead = zip_fread(file.get(), &buffer.get()[fileInfo.size - remainingBufferSize], remainingBufferSize);
					
				// Check if reading bytes failed
				if(bytesRead == -1) {
				
					// Throw exception
					throw runtime_error("Reading bytes failed");
				}
				
				// Update remaining buffer size
				remainingBufferSize -= bytesRead;
			
			} while(bytesRead);
			
			// Check if buffer was partially filled
			if(remainingBufferSize) {
			
				// Throw exception
				throw runtime_error("Buffer was partially filled");
			}
			
			// Get leaf set
			leafSet = roaring::Roaring::readSafe(reinterpret_cast<char *>(buffer.get()), fileInfo.size);
		}
		
		// Initialize newest pruned node index
		uint64_t newestPrunedNodeIndex = 0;
		
		// Set newest pruned node index is valid to false
		bool newestPrunedNodeIndexIsValid = false;
		
		// Initialize leaf shifts
		vector<uint64_t> leafShifts;
		
		// Go through all pruned node roots
		uint64_t totalLeafShift = 0;
		
		for(const uint64_t prunedNodeRootIndex : pruneList) {
		
			// Check if pruned node root is valid
			if(prunedNodeRootIndex > 0) {
		
				// Get height at node
				const uint64_t height = getHeightAtIndex(prunedNodeRootIndex - 1);
				
				// Get leaf shift at height
				const uint64_t leafShift = height ? static_cast<uint64_t>(1) << height : 0;
				
				// Update total leaf shift
				totalLeafShift += leafShift;
				
				// Append total leaf shift to list of leaf shifts
				leafShifts.push_back(totalLeafShift);
				
				// Check if leaf set doesn't exist or doesn't contain the pruned node
				if(!leafSetPath || prunedNodeRootIndex > leafSet.maximum() || !leafSet.contains(prunedNodeRootIndex)) {
				
					// Set newest pruned node index to the node
					newestPrunedNodeIndex = prunedNodeRootIndex - 1;
					
					// Set newest pruned node index is valid to true
					newestPrunedNodeIndexIsValid = true;
				}
			}
		}
		
		// Check if newest pruned node index is valid
		if(newestPrunedNodeIndexIsValid) {
		
			// Set Merkle mountain range's minimum size to be at the newest pruned node
			merkleMountainRange.minimumSize = getNextPeakIndex(newestPrunedNodeIndex) + 1;
		}
		
		// Check if opening data file in the ZIP failed
		unique_ptr<zip_file_t, decltype(&zip_fclose)> file(zip_fopen(zip, dataPath, ZIP_FL_ENC_STRICT | ZIP_FL_ENC_UTF_8), zip_fclose);
		if(!file) {
		
			// Throw exception
			throw runtime_error("Opening data file in the ZIP failed");
		}
		
		// Set read leaf count to zero
		uint64_t readLeafCount = 0;
		
		// Go through all bytes in the file
		zip_int64_t bytesRead;
		do {
		
			// Initialize buffer
			array<uint8_t, MerkleMountainRangeLeafDerivedClass::MAXIMUM_SERIALIZED_LENGTH> buffer;
			
			// Initialize remaining buffer size
			typename array<uint8_t, MerkleMountainRangeLeafDerivedClass::MAXIMUM_SERIALIZED_LENGTH>::size_type remainingBufferSize;
			
			// Initialize leaf shift
			uint64_t leafShift;
			
			// Get rank at node
			const uint64_t rank = pruneList.rank(merkleMountainRange.numberOfHashes + 1);
			
			// Check if rank is zero
			if(!rank) {
			
				// Set leaf shift to zero
				leafShift = 0;
			}
			
			// Otherwise check if rank uses the total leaf shift
			else if(rank > leafShifts.size()) {
			
				// Set leaf shift to the total leaf shift
				leafShift = leafShifts[SaturateMath::subtract(leafShifts.size(), 1)];
			}
			
			// Otherwise
			else {
			
				// Set leaf shift to the leaf shift at the rank
				leafShift = leafShifts[rank - 1];
			}
			
			// Go through all leaves to read
			do {
			
				// Go through all bytes in the buffer
				for(remainingBufferSize = buffer.size(); remainingBufferSize; remainingBufferSize -= bytesRead) {
			
					// Read bytes into buffer
					bytesRead = zip_fread(file.get(), &buffer[buffer.size() - remainingBufferSize], remainingBufferSize);
					
					// Check if reading bytes failed
					if(bytesRead == -1) {
					
						// Throw exception
						throw runtime_error("Reading bytes failed");
					}
					
					// Check if no more bytes to read
					if(!bytesRead) {
					
						// Break
						break;
					}
				}
			
			} while(++readLeafCount <= merkleMountainRange.numberOfLeaves - leafShift);
			
			// Check if bytes were read
			if(remainingBufferSize != buffer.size()) {
			
				// Check if at the first Merkle mountain range leaf
				if(!merkleMountainRange.numberOfHashes) {
				
					// Set protocol version to the detected protocol version of the bytes
					protocolVersion = MerkleMountainRangeLeafDerivedClass::getSerializedProtocolVersion(buffer, buffer.size() - remainingBufferSize, protocolVersion);
				}
			
				// Get Merkle mountain range leaf from bytes
				pair leaf = MerkleMountainRangeLeafDerivedClass::unserialize(buffer, buffer.size() - remainingBufferSize, protocolVersion, !merkleMountainRange.numberOfHashes && (!leafSetPath || (leafSet.maximum() > 0 && leafSet.contains(1))));
				
				// Check if leaf set doesn't exist or leaf set contains the leaf
				if(!leafSetPath || (merkleMountainRange.numberOfHashes < leafSet.maximum() && leafSet.contains(merkleMountainRange.numberOfHashes + 1))) {
			
					// Append leaf to the Merkle mountain range
					merkleMountainRange.appendLeaf(move(leaf.first));
				}
				
				// Otherwise
				else {
				
					// Append pruned leaf to the Merkle mountain range
					merkleMountainRange.appendLeafOrPrunedLeaf(nullopt);
				}
				
				// Check if some bytes wern't used
				if(leaf.second < buffer.size() - remainingBufferSize) {
				
					// Check if going back by the number of unused bytes failed
					if(zip_fseek(file.get(), static_cast<int64_t>(leaf.second) - (buffer.size() - remainingBufferSize), SEEK_CUR)) {
					
						// Throw exception
						throw runtime_error("Going back by the number of unused bytes failed");
					}
					
					// Cause unused bytes to be read
					bytesRead = !0;
				}
				
				// Loop while node is pruned
				while(true) {
				
					// Set node pruned to false
					bool nodePruned = false;
			
					// Go through the node and its ancestors
					for(uint64_t i = merkleMountainRange.numberOfHashes; i < pruneList.maximum(); i = getParentIndex(i)) {
					
						// Check if node is pruned
						if(pruneList.contains(i + 1)) {
						
							// Set node pruned
							nodePruned = true;
							
							// Append pruned leaf to the Merkle mountain range
							merkleMountainRange.appendLeafOrPrunedLeaf(nullopt);
							
							// Break
							break;
						}
					}
					
					// Check if node isn't pruned
					if(!nodePruned) {
					
						// Break
						break;
					}
				}
			}
		
		} while(bytesRead);
		
		// Set expecting all hashes to if the prune list is empty and the leaf set doesn't exist
		expectingAllHashes = pruneList.isEmpty() && !leafSetPath;
	}
	
	{
		// Initialize hash shifts
		vector<uint64_t> hashShifts;
		
		// Go through all pruned node roots
		uint64_t totalHashShift = 0;
		
		for(const uint64_t prunedNodeRootIndex : pruneList) {
		
			// Check if pruned node root is valid
			if(prunedNodeRootIndex > 0) {
		
				// Get height at node
				const uint64_t height = getHeightAtIndex(prunedNodeRootIndex - 1);
				
				// Get hash shift at height
				const uint64_t hashShift = 2 * ((static_cast<uint64_t>(1) << height) - 1);
				
				// Update total hash shift
				totalHashShift += hashShift;
				
				// Append total hash shift to list of hash shifts
				hashShifts.push_back(totalHashShift);
			}
		}
		
		// Initialize hashes indices
		set<uint64_t> hashesIndices;
		
		// Check if not expecting all hashes
		if(!expectingAllHashes) {
		
			// Go through all of the Merkle mountain range's unpruned leafs
			for(const pair<const uint64_t, MerkleMountainRangeLeafDerivedClass> &unprunedLeaf : merkleMountainRange.unprunedLeaves) {

				// Go through the leaf's node and its ancestors
				for(uint64_t j = getLeafsIndex(unprunedLeaf.first); j < merkleMountainRange.numberOfHashes; j = getParentIndex(j)) {
				
					// Check if node has children
					if(getHeightAtIndex(j)) {
					
						// Add node's children's indices to list
						hashesIndices.insert(getLeftChildIndex(j));
						hashesIndices.insert(getRightChildIndex(j));
					}
					
					// Add node's index to list
					hashesIndices.insert(j);
				}
			}
		}
		
		// Check if opening hashes file in the ZIP failed
		unique_ptr<zip_file_t, decltype(&zip_fclose)> file(zip_fopen(zip, hashesPath, ZIP_FL_ENC_STRICT | ZIP_FL_ENC_UTF_8), zip_fclose);
		if(!file) {
		
			// Throw exception
			throw runtime_error("Opening hashes file in the ZIP failed");
		}
		
		// Set read hash count to zero
		uint64_t readHashCount = 0;
		
		// Set all hashes index to the first unpruned hash index
		map<uint64_t, array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH>>::const_iterator allHashesIndex = merkleMountainRange.unprunedHashes.cbegin();
		
		// Set hashes index to the first hash index
		set<uint64_t>::const_iterator hashesIndex = hashesIndices.cbegin();
		
		// Go through all bytes in the file
		zip_int64_t bytesRead;
		do {
		
			// Initialize buffer
			array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH> buffer;
			
			// Initialize remaining buffer size
			array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH>::size_type remainingBufferSize;
			
			// Initialize hash shift
			uint64_t hashShift;
			
			// Initialize rank
			uint64_t rank;
			
			// Check if expecting all hashes
			if(expectingAllHashes) {
			
				// Get rank at node
				rank = (allHashesIndex != merkleMountainRange.unprunedHashes.cend()) ? pruneList.rank(allHashesIndex->first + 1) : 0;
			}
			
			// Otherwise
			else {
			
				// Get rank at node
				rank = (hashesIndex != hashesIndices.cend()) ? pruneList.rank(*hashesIndex + 1) : 0;
			}
			
			// Check if rank is zero
			if(!rank) {
			
				// Set hash shift to zero
				hashShift = 0;
			}
			
			// Otherwise check if rank uses the total hash shift
			else if(rank > hashShifts.size()) {
			
				// Set hash shift to the total hash shift
				hashShift = hashShifts[SaturateMath::subtract(hashShifts.size(), 1)];
			}
			
			// Otherwise
			else {
			
				// Set hash shift to the hash shift at the rank
				hashShift = hashShifts[rank - 1];
			}
			
			// Go through all hashes to read
			while(true) {
			
				// Go through all bytes in the buffer
				for(remainingBufferSize = buffer.size(); remainingBufferSize; remainingBufferSize -= bytesRead) {
			
					// Read bytes into buffer
					bytesRead = zip_fread(file.get(), &buffer[buffer.size() - remainingBufferSize], remainingBufferSize);
					
					// Check if reading bytes failed
					if(bytesRead == -1) {
					
						// Throw exception
						throw runtime_error("Reading bytes failed");
					}
					
					// Check if no more bytes to read
					if(!bytesRead) {
					
						// Break
						break;
					}
				}
				
				// Check if expecting all hashes
				if(expectingAllHashes) {
				
					// Check if no more hashes are expected or done reading the current hash
					if(allHashesIndex == merkleMountainRange.unprunedHashes.cend() || ++readHashCount > allHashesIndex->first - hashShift) {
					
						// Break
						break;
					}
				}
				
				// Otherwise
				else {
				
					// Check if no more hashes are expected or done reading the current hash
					if(hashesIndex == hashesIndices.cend() || ++readHashCount > *hashesIndex - hashShift) {
					
						// Break
						break;
					}
				}
			}
			
			// Check if buffer was completely filled
			if(!remainingBufferSize) {
			
				// Initialize hash expected
				bool hashExpected;
			
				// Check if expecting all hashes
				if(expectingAllHashes) {
				
					// Set hash expected to if more hashes exist
					hashExpected = allHashesIndex != merkleMountainRange.unprunedHashes.cend();
				}
				
				// Otherwise
				else {
				
					// Set hash expected to if more hashes exist
					hashExpected = hashesIndex != hashesIndices.cend();
				}
			
				// Check if hash is expected
				if(hashExpected) {
				
					// Set current hashes index to the current hashes index
					const uint64_t currentHashesIndex = expectingAllHashes ? allHashesIndex->first : *hashesIndex;
				
					// Check if node at index doesn't have a hash
					if(!merkleMountainRange.unprunedHashes.contains(currentHashesIndex)) {
					
						// Set node's hash
						merkleMountainRange.setHashAtIndex(currentHashesIndex, move(buffer));
					}
					
					// Otherwise check if hash is invalid
					else if(buffer != merkleMountainRange.unprunedHashes[currentHashesIndex]) {
					
						// Throw exception
						throw runtime_error("Hash is invalid");
					}
					
					// Check if expecting all hashes
					if(expectingAllHashes) {
					
						// Increment all hashes index
						++allHashesIndex;
					}
					
					// Otherwise
					else {
					
						// Increment hashes index
						++hashesIndex;
					}
				}
			}
			
			// Otherwise check if buffer was partially filled
			else if(remainingBufferSize != Crypto::BLAKE2B_HASH_LENGTH) {
			
				// Throw exception
				throw runtime_error("Buffer was partially filled");
			}
		
		} while(bytesRead);
		
		// Check if expecting all hashes
		if(expectingAllHashes) {
		
			// Check if number of hashes is invalid
			if(allHashesIndex != merkleMountainRange.unprunedHashes.cend()) {
			
				// Throw exception
				throw runtime_error("Number of hashes is invalid");
			}
		}
		
		// Otherwise
		else {
		
			// Check if number of hashes is invalid
			if(hashesIndex != hashesIndices.cend()) {
			
				// Throw exception
				throw runtime_error("Number of hashes is invalid");
			}
		}
	}
	
	// Return Merkle mountain range
	return merkleMountainRange;
}

// Is size valid
template<typename MerkleMountainRangeLeafDerivedClass> bool MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::isSizeValid(const uint64_t size) {

	// Set height to size
	uint64_t height = size;
	
	// Check if height isn't zero
	if(height) {
	
		// Go through all peak sizes
		for(uint64_t peakSize = UINT64_MAX >> Common::numberOfLeadingZeros(height); peakSize; peakSize >>= 1) {
		
			// Check if height is greater than or equal to the peak size
			if(height >= peakSize) {
			
				// Update height
				height -= peakSize;
			}
		}
	}
	
	// Return if height is zero
	return !height;
}

// Get number of leaves at size
template<typename MerkleMountainRangeLeafDerivedClass> uint64_t MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::getNumberOfLeavesAtSize(const uint64_t size) {

	// Check if size is invalid
	if(!isSizeValid(size)) {
	
		// Throw exception
		throw runtime_error("Size is invalid");
	}

	// Set height to size
	uint64_t height = size;
	
	// Set number of leaves to zero
	uint64_t numberOfLeaves = 0;
	
	// Check if height isn't zero
	if(height) {
	
		// Go through all peak sizes
		for(uint64_t peakSize = UINT64_MAX >> Common::numberOfLeadingZeros(height); peakSize; peakSize >>= 1) {
		
			// Check if height is greater than or equal to the peak size
			if(height >= peakSize) {
			
				// Increase number of leaves
				numberOfLeaves += (peakSize + 1) / 2;
				
				// Update height
				height -= peakSize;
			}
		}
	}
	
	// Return number of leaves
	return height ? numberOfLeaves + 1 : numberOfLeaves;
}

// Get size at number of leaves
template<typename MerkleMountainRangeLeafDerivedClass> uint64_t MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::getSizeAtNumberOfLeaves(const uint64_t numberOfLeaves) {

	// Check if no leaves exist
	if(!numberOfLeaves) {
	
		// Return zero
		return 0;
	}

	// Get last leaf index at the number of leaves
	uint64_t index = getLeafsIndex(numberOfLeaves - 1);
	
	// Loop while node is a right sibling
	while(getHeightAtIndex(index) < getHeightAtIndex(index + 1)) {
	
		// Set index to its parent
		index = getParentIndex(index);
	}
	
	// Return size
	return index + 1;
}

// Append leaf or pruned leaf
template<typename MerkleMountainRangeLeafDerivedClass> void MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::appendLeafOrPrunedLeaf(optional<MerkleMountainRangeLeafDerivedClass> &&leafOrPrunedLeaf) {

	// Check if leaf isn't pruned
	if(leafOrPrunedLeaf.has_value()) {
	
		// Check if leaf has a lookup value
		optional<vector<uint8_t>> lookupValue = leafOrPrunedLeaf.value().getLookupValue();
		if(lookupValue.has_value()) {
		
			// Check if lookup value exists in the lookup table
			if(lookupTable.contains(lookupValue.value())) {
			
				// Check if duplicate lookup values are allowed
				if(MerkleMountainRangeLeafDerivedClass::ALLOW_DUPLICATE_LOOKUP_VALUES) {
				
					// Add leaf to lookup value in the lookup table
					lookupTable.at(lookupValue.value()).insert(numberOfLeaves);
				}
				
				// Otherwise
				else {
				
					// Throw exception
					throw runtime_error("Lookup value already exists in the lookup table");
				}
			}
			
			// Otherwise
			else {
			
				// Append lookup value to the lookup table
				lookupTable.emplace(move(lookupValue.value()), unordered_set<uint64_t>({numberOfLeaves}));
			}
		}
	
		// Append leaf to list
		unprunedLeaves.emplace(numberOfLeaves, move(leafOrPrunedLeaf.value()));
		
		// Add to sum
		unprunedLeaves.at(numberOfLeaves).addToSum(sum, MerkleMountainRangeLeafDerivedClass::AdditionReason::APPENDED);
	
		// Get leaf data
		const vector<uint8_t> &leafData = unprunedLeaves.at(numberOfLeaves).serialize();
	
		// Create index and leaf
		const uint64_t indexBigEndian = Common::hostByteOrderToBigEndian(numberOfHashes);
		uint8_t indexAndLeaf[sizeof(indexBigEndian) + leafData.size()];
		memcpy(indexAndLeaf, &indexBigEndian, sizeof(indexBigEndian));
		memcpy(&indexAndLeaf[sizeof(indexBigEndian)], leafData.data(), leafData.size());
		
		// Check if creating leaf's hash failed
		unprunedHashes.emplace(numberOfHashes, array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH>());
		if(blake2b(unprunedHashes[numberOfHashes].data(), unprunedHashes[numberOfHashes].size(), indexAndLeaf, sizeof(indexAndLeaf), nullptr, 0)) {
		
			// Throw exception
			throw runtime_error("Creating leaf's hash failed");
		}
	}
	
	// Increment number of leaves
	++numberOfLeaves;
	
	// increment number of hashes
	++numberOfHashes;
	
	// Loop while node is a right sibling
	for(uint64_t i = numberOfHashes - 1; getHeightAtIndex(i) < getHeightAtIndex(i + 1); i = numberOfHashes - 1) {
	
		// Get left sibling index
		const uint64_t leftSiblingIndex = getLeftSiblingIndex(i);
	
		// Check if neither sibling is pruned
		if(unprunedHashes.contains(i) && unprunedHashes.contains(leftSiblingIndex)) {
		
			// Create index and hashes
			const uint64_t indexBigEndian = Common::hostByteOrderToBigEndian(i + 1);
			uint8_t indexAndHashes[sizeof(indexBigEndian) + unprunedHashes[leftSiblingIndex].size() + unprunedHashes[i].size()];
			memcpy(indexAndHashes, &indexBigEndian, sizeof(indexBigEndian));
			memcpy(&indexAndHashes[sizeof(indexBigEndian)], unprunedHashes[leftSiblingIndex].data(), unprunedHashes[leftSiblingIndex].size());
			memcpy(&indexAndHashes[sizeof(indexBigEndian) + unprunedHashes[leftSiblingIndex].size()], unprunedHashes[i].data(), unprunedHashes[i].size());
			
			// Check if creating parent's hash failed
			unprunedHashes.emplace(numberOfHashes, array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH>());
			if(blake2b(unprunedHashes[numberOfHashes].data(), unprunedHashes[numberOfHashes].size(), indexAndHashes, sizeof(indexAndHashes), nullptr, 0)) {
			
				// Throw exception
				throw runtime_error("Creating parent's hash failed");
			}
		}
		
		// Increment number of hashes
		++numberOfHashes;
	}
}

// Set hash at index
template<typename MerkleMountainRangeLeafDerivedClass> void MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::setHashAtIndex(const uint64_t index, array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH> &&hash) {

	// Check if index is invalid
	if(index >= numberOfHashes) {
	
		// Throw exception
		throw runtime_error("Index is invalid");
	}

	// Check if hash already exists
	if(unprunedHashes.contains(index)) {
	
		// Throw exception
		throw runtime_error("Hash already exists");
	}
	
	// Check if node is a parent
	if(getHeightAtIndex(index)) {
	
		// Check if node's children's hashes exist
		if(unprunedHashes.contains(getLeftChildIndex(index)) || unprunedHashes.contains(getRightChildIndex(index))) {
		
			// Throw exception
			throw runtime_error("Node's children's hashes exist");
		}
	}
	
	// Set hash at index
	unprunedHashes.emplace(index, move(hash));
	
	// Loop through all of the node's ancestors
	for(uint64_t parentIndex = getParentIndex(index); parentIndex < numberOfHashes; parentIndex = getParentIndex(parentIndex)) {
	
		// Check if parent's hash already exists
		if(unprunedHashes.contains(parentIndex)) {
		
			// Throw exception
			throw runtime_error("Parent's hash already exists");
		}
		
		// Get parent's children indices
		const uint64_t leftChildIndex = getLeftChildIndex(parentIndex);
		const uint64_t rightChildIndex = getRightChildIndex(parentIndex);
		
		// Check if parent's children's hashes exist
		if(unprunedHashes.contains(leftChildIndex) && unprunedHashes.contains(rightChildIndex)) {
		
			// Create index and hashes
			const uint64_t indexBigEndian = Common::hostByteOrderToBigEndian(parentIndex);
			uint8_t indexAndHashes[sizeof(indexBigEndian) + unprunedHashes[leftChildIndex].size() + unprunedHashes[rightChildIndex].size()];
			memcpy(indexAndHashes, &indexBigEndian, sizeof(indexBigEndian));
			memcpy(&indexAndHashes[sizeof(indexBigEndian)], unprunedHashes[leftChildIndex].data(), unprunedHashes[leftChildIndex].size());
			memcpy(&indexAndHashes[sizeof(indexBigEndian) + unprunedHashes[leftChildIndex].size()], unprunedHashes[rightChildIndex].data(), unprunedHashes[rightChildIndex].size());
			
			// Check if creating parent's hash failed
			unprunedHashes.emplace(parentIndex, array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH>());
			if(blake2b(unprunedHashes[parentIndex].data(), unprunedHashes[parentIndex].size(), indexAndHashes, sizeof(indexAndHashes), nullptr, 0)) {
			
				// Throw exception
				throw runtime_error("Creating parent's hash failed");
			}
		}
		
		// Otherwise
		else {
		
			// Break
			break;
		}
	}
}

// Prune hash
template<typename MerkleMountainRangeLeafDerivedClass> void MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::pruneHash(const uint64_t leafIndex) {

	// Get leaf's index
	uint64_t index = getLeafsIndex(leafIndex);
	
	// Loop through all of the node's ancestors
	for(uint64_t parentIndex = getParentIndex(index); parentIndex < numberOfHashes; parentIndex = getParentIndex(parentIndex)) {
	
		// Prune node
		unprunedHashes.erase(index);
		
		// Initialize sibling index and leaf index
		uint64_t siblingIndex;
		uint64_t siblingLeafIndex;
		
		// Check if node is a right sibling
		if(getHeightAtIndex(index) < getHeightAtIndex(index + 1)) {
		
			// Set sibling index to the node's left sibling
			siblingIndex = getLeftSiblingIndex(index);
			
			// Set sibling leaf index to the previous leaf index
			siblingLeafIndex = leafIndex - 1;
		}
		
		// Otherwise
		else {
		
			// Set sibling index to the node's right sibling
			siblingIndex = getRightSiblingIndex(index);
			
			// Set sibling leaf index to the next leaf index
			siblingLeafIndex = leafIndex + 1;
		}
		
		// Check if sibling has children
		if(getHeightAtIndex(siblingIndex)) {
		
			// Check if both of the sibling's children are pruned
			if(!unprunedHashes.contains(getLeftChildIndex(siblingIndex)) && !unprunedHashes.contains(getRightChildIndex(siblingIndex))) {
			
				// Prune sibling
				unprunedHashes.erase(siblingIndex);
			}
		}
		
		// Otherwise
		else {
		
			// Check if sibling leaf is pruned
			if(!unprunedLeaves.contains(siblingLeafIndex)) {
			
				// Prune sibling
				unprunedHashes.erase(siblingIndex);
			}
		}
		
		// Check if sibling isn't pruned
		if(unprunedHashes.contains(siblingIndex)) {
		
			// Break
			break;
		}
		
		// Set index to parent index
		index = parentIndex;
	}
}

// Get peak indices at size
template<typename MerkleMountainRangeLeafDerivedClass> vector<uint64_t> MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::getPeakIndicesAtSize(const uint64_t size) {

	// Check if size is invalid
	if(!isSizeValid(size)) {
	
		// Throw exception
		throw runtime_error("Size is invalid");
	}

	// Initialize peak indices
	vector<uint64_t> peakIndices;

	// Set height to size
	uint64_t height = size;
	
	// Check if height isn't zero
	if(height) {
	
		// Go through all peak sizes
		for(uint64_t peakSize = UINT64_MAX >> Common::numberOfLeadingZeros(height), peakSum = 0; peakSize; peakSize >>= 1) {
		
			// Check if height is greater than or equal to the peak size
			if(height >= peakSize) {
			
				// Update peak sum
				peakSum += peakSize;
				
				// Append peak index to list
				peakIndices.push_back(peakSum - 1);
			
				// Update height
				height -= peakSize;
			}
		}
	}
	
	// Return peak indices
	return peakIndices;
}

// Get height at index
template<typename MerkleMountainRangeLeafDerivedClass> uint64_t MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::getHeightAtIndex(const uint64_t index) {

	// Set height to index
	uint64_t height = index;
	
	// Check if height isn't zero
	if(height) {
	
		// Go through all peak sizes
		for(uint64_t peakSize = UINT64_MAX >> Common::numberOfLeadingZeros(height); peakSize; peakSize >>= 1) {
		
			// Check if height is greater than or equal to the peak size
			if(height >= peakSize) {
			
				// Update height
				height -= peakSize;
			}
		}
	}
	
	// Return height
	return height;
}

// Get left sibling index
template<typename MerkleMountainRangeLeafDerivedClass> uint64_t MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::getLeftSiblingIndex(const uint64_t index) {

	// Get height
	const uint64_t height = getHeightAtIndex(index);

	// Return left sibling index
	return index - ((static_cast<uint64_t>(1) << (height + 1)) - 1);
}

// Get right sibling index
template<typename MerkleMountainRangeLeafDerivedClass> uint64_t MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::getRightSiblingIndex(const uint64_t index) {

	// Get height
	const uint64_t height = getHeightAtIndex(index);

	// Return right sibling index
	return index + ((static_cast<uint64_t>(1) << (height + 1)) - 1);
}

// Get parent index
template<typename MerkleMountainRangeLeafDerivedClass> uint64_t MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::getParentIndex(const uint64_t index) {

	// Get height
	const uint64_t height = getHeightAtIndex(index);
	
	// Check if node at index is a right sibling
	if(height < getHeightAtIndex(index + 1)) {

		// Return parent index
		return index + 1;
	}
	
	// Otherwise
	else {
	
		// Return parent index
		return index + (static_cast<uint64_t>(1) << (height + 1));
	}
}

// Get left child index
template<typename MerkleMountainRangeLeafDerivedClass> uint64_t MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::getLeftChildIndex(const uint64_t index) {

	// Get height
	const uint64_t height = getHeightAtIndex(index);
	
	// Return left child index
	return index - (static_cast<uint64_t>(1) << height);
}

// Get right child index
template<typename MerkleMountainRangeLeafDerivedClass> uint64_t MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::getRightChildIndex(const uint64_t index) {

	// Return right child index
	return index - 1;
}

// Get next peak index
template<typename MerkleMountainRangeLeafDerivedClass> uint64_t MerkleMountainRange<MerkleMountainRangeLeafDerivedClass>::getNextPeakIndex(const uint64_t index) {

	// Set peak index to the next index
	uint64_t peakIndex = index + 1;
	
	// Loop while not at a peak or while not at a higher peak
	while(getHeightAtIndex(peakIndex) <= getHeightAtIndex(peakIndex + 1) || getHeightAtIndex(peakIndex) <= getHeightAtIndex(index)) {
	
		// Increment peak index
		++peakIndex;
	}
	
	// Return peak index
	return peakIndex;
}


}


#endif
