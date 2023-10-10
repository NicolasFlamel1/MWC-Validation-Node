// Header files
#include"./common.h"
#include <cstring>
#include "blake2.h"
#include "./consensus.h"
#include "./kernel.h"
#include "secp256k1_aggsig.h"
#include "secp256k1_commitment.h"

using namespace std;


// Namespace
using namespace MwcValidationNode;


// Constants

// Maximum relative height
const uint64_t Kernel::MAXIMUM_RELATIVE_HEIGHT = Consensus::WEEK_HEIGHT;


// Supporting function implementation

// Constructor
Kernel::Kernel(const Features features, const uint64_t fee, const uint64_t lockHeight, const uint64_t relativeHeight, const uint8_t excess[Crypto::COMMITMENT_LENGTH], const uint8_t signature[Crypto::SINGLE_SIGNER_SIGNATURE_LENGTH], const bool isGenesisBlockKernel) :

	// Set features to features
	features(features),
	
	// Set fee to fee
	fee(fee),
	
	// Set lock height to lock height
	lockHeight(lockHeight),
	
	// Set relative height to relative height
	relativeHeight(relativeHeight)
{

	// Check features
	switch(features) {
	
		// Plain
		case Features::PLAIN:
		
			// Check if lock height and/or relative height are invalid
			if(lockHeight || relativeHeight) {
			
				// Throw exception
				throw runtime_error("Lock height and/or relative height are invalid");
			}
			
			// Break
			break;
		
		// Coinbase
		case Features::COINBASE:
		
			// Check if fee, lock height, and/or relative height are invalid
			if(fee || lockHeight || relativeHeight) {
			
				// Throw exception
				throw runtime_error("Fee, lock height, and/or relative height are invalid");
			}
		
			// Break
			break;
		
		// Height locked
		case Features::HEIGHT_LOCKED:
		
			// Check if relative height is invalid
			if(relativeHeight) {
			
				// Throw exception
				throw runtime_error("Relative height is invalid");
			}
		
			// Break
			break;
		
		// No recent duplicate
		case Features::NO_RECENT_DUPLICATE:
		
			// Check if not floonet
			#ifndef FLOONET
			
				// Throw exception
				throw runtime_error("No recent duplicate features aren't enabled");
			#endif
			
			// Check if lock height is invalid
			if(lockHeight) {
			
				// Throw exception
				throw runtime_error("Lock height is invalid");
			}
			
			// Check if relative height is invalid
			if(!relativeHeight || relativeHeight > MAXIMUM_RELATIVE_HEIGHT) {
			
				// Throw exception
				throw runtime_error("Relative height is invalid");
			}
		
			// Break
			break;
		
		// Default
		default:
		
			// Throw exception
			throw runtime_error("Features is invalid");
		
			// Break
			break;
	}

	// Check if excess is invalid
	if(!secp256k1_pedersen_commitment_parse(secp256k1_context_no_precomp, &this->excess, excess)) {
	
		// Throw exception
		throw runtime_error("Excess is invalid");
	}
	
	// Check if excess isn't a valid public key
	secp256k1_pubkey publicKey;
	if(!secp256k1_pedersen_commitment_to_pubkey(secp256k1_context_no_precomp, &publicKey, &this->excess)) {
	
		// Throw exception
		throw runtime_error("Excess isn't a valid public key");
	}
	
	// Check if public key is invalid (mwc-node only checks first 32 bytes)
	if(all_of(reinterpret_cast<uint8_t *>(&publicKey), reinterpret_cast<uint8_t *>(&publicKey) + 256 / Common::BITS_IN_A_BYTE, [](const uint8_t value) {
	
		// Return if value is zero
		return !value;
	})) {
	
		// Throw exception
		throw runtime_error("Public key is invalid");
	}
	
	// Check if signature is invalid (mwc-node only checks first 32 bytes)
	if(all_of(signature, signature + 256 / Common::BITS_IN_A_BYTE, [](const uint8_t value) {
	
		// Return if value is zero
		return !value;
	})) {
	
		// Throw exception
		throw runtime_error("Signature is invalid");
	}
	
	// Check if signature isn't for the kernel
	if(!isGenesisBlockKernel && !secp256k1_aggsig_verify_single(Crypto::getSecp256k1Context(), signature, getMessageToSign().data(), nullptr, &publicKey, &publicKey, nullptr, false)) {
	
		// Throw exception
		throw runtime_error("Signature isn't for the kernel");
	}
	
	// Set signature to signature
	memcpy(&this->signature, signature, sizeof(this->signature));
	
	// Check if kernel doesn't match the genesis block kernel
	if(isGenesisBlockKernel && *this != Consensus::GENESIS_BLOCK_KERNEL) {
	
		// Throw exception
		throw runtime_error("Kernel doesn't match the genesis block kernel");
	}
}

// Serialize
vector<uint8_t> Kernel::serialize() const {

	// Initialize serialized kernel
	vector<uint8_t> serializedKernel;
	
	// Append features to serialized kernel
	Common::writeUint8(serializedKernel, static_cast<underlying_type_t<Features>>(features));
	
	// Append fee to serialized kernel
	Common::writeUint64(serializedKernel, fee);
	
	// Check features
	switch(features) {
	
		// Plain, coinbase, or height locked
		case Features::PLAIN:
		case Features::COINBASE:
		case Features::HEIGHT_LOCKED:
			
			// Append lock height to serialized kernel
			Common::writeUint64(serializedKernel, lockHeight);
			
			// Break
			break;
		
		// No recent duplicate
		case Features::NO_RECENT_DUPLICATE:
			
			// Append relative height to serialized kernel
			Common::writeUint64(serializedKernel, relativeHeight);
		
			// Break
			break;
		
		// Default
		default:
		
			// Break
			break;
	}
	
	// Check if serializing excess failed
	uint8_t serializedExcess[Crypto::COMMITMENT_LENGTH];
	if(!secp256k1_pedersen_commitment_serialize(secp256k1_context_no_precomp, serializedExcess, &excess)) {
	
		// Throw exception
		throw runtime_error("Serializing excess failed");
	}
	
	// Append serialized excess to serialized kernel
	serializedKernel.insert(serializedKernel.cend(), cbegin(serializedExcess), cend(serializedExcess));
	
	// Append signature to serialized kernel
	serializedKernel.insert(serializedKernel.cend(), signature, signature + sizeof(signature));
	
	// Return serialized kernel
	return serializedKernel;
}

// Get lookup value
optional<vector<uint8_t>> Kernel::getLookupValue() const {

	// Check if serializing excess failed
	vector<uint8_t> serializedExcess(Crypto::COMMITMENT_LENGTH);
	if(!secp256k1_pedersen_commitment_serialize(secp256k1_context_no_precomp, serializedExcess.data(), &excess)) {
	
		// Throw exception
		throw runtime_error("Serializing excess failed");
	}
	
	// Return serialized excess
	return serializedExcess;
}

// Add to sum
void Kernel::addToSum(secp256k1_pedersen_commitment &sum, const AdditionReason additionReason) const {

	// Check if adding because appended
	if(additionReason == AdditionReason::APPENDED) {
	
		// Check if sum is zero
		if(all_of(reinterpret_cast<uint8_t *>(&sum), reinterpret_cast<uint8_t *>(&sum) + sizeof(sum), [](const uint8_t value) {
		
			// Return if value is zero
			return !value;
		})) {
		
			// Set sum to excess
			sum = excess;
		}
		
		// Otherwise
		else {
		
			// Set positive excesses
			const secp256k1_pedersen_commitment *positiveExcesses[] = {
			
				// Sum
				&sum,
				
				// Excess
				&excess
			};
			
			// Set negative excesses
			const secp256k1_pedersen_commitment *negativeExcesses[] = {};

			// Check if adding to positive and negative excesses failed
			secp256k1_pedersen_commitment result;
			if(!secp256k1_pedersen_commit_sum(secp256k1_context_no_precomp, &result, positiveExcesses, 2, negativeExcesses, 0)) {
			
				// Throw exception
				throw runtime_error("Adding to positive and negative excesses failed");
			}
			
			// Set sum to the result
			sum = result;
		}
	}
}

// Subtract from sum
void Kernel::subtractFromSum(secp256k1_pedersen_commitment &sum, const SubtractionReason subtractionReason) const {

	// Check if subtracting because rewinded or discarded
	if(subtractionReason == SubtractionReason::REWINDED || subtractionReason == SubtractionReason::DISCARDED) {
	
		// Check if sum is zero
		if(all_of(reinterpret_cast<uint8_t *>(&sum), reinterpret_cast<uint8_t *>(&sum) + sizeof(sum), [](const uint8_t value) {
		
			// Return if value is zero
			return !value;
		})) {
		
			// Set positive excesses
			const secp256k1_pedersen_commitment *positiveExcesses[] = {};
			
			// Set negative excesses
			const secp256k1_pedersen_commitment *negativeExcesses[] = {
			
				// Excess
				&excess
			};

			// Check if adding to positive and negative excesses failed
			secp256k1_pedersen_commitment result;
			if(!secp256k1_pedersen_commit_sum(secp256k1_context_no_precomp, &result, positiveExcesses, 0, negativeExcesses, 1)) {
			
				// Throw exception
				throw runtime_error("Adding to positive and negative excesses failed");
			}
			
			// Set sum to the result
			sum = result;
		}
		
		// Otherwise
		else {
		
			// Check if serializing sum and/or excess failed
			uint8_t serializedSum[Crypto::COMMITMENT_LENGTH];
			uint8_t serializedExcess[Crypto::COMMITMENT_LENGTH];
			if(!secp256k1_pedersen_commitment_serialize(secp256k1_context_no_precomp, serializedSum, &sum) || !secp256k1_pedersen_commitment_serialize(secp256k1_context_no_precomp, serializedExcess, &excess)) {
			
				// Throw exception
				throw runtime_error("Serializing sum and/or excess failed");
			}
			
			// Check if serialized sum and serialized excess are equal
			if(!memcmp(serializedSum, serializedExcess, sizeof(serializedExcess))) {
			
				// Set sum to zero
				memset(&sum, 0, sizeof(sum));
			}
			
			// Otherwise
			else {
			
				// Set positive excesses
				const secp256k1_pedersen_commitment *positiveExcesses[] = {
				
					// Sum
					&sum
				};
				
				// Set negative excesses
				const secp256k1_pedersen_commitment *negativeExcesses[] = {
				
					// Excess
					&excess
				};

				// Check if adding to positive and negative excesses failed
				secp256k1_pedersen_commitment result;
				if(!secp256k1_pedersen_commit_sum(secp256k1_context_no_precomp, &result, positiveExcesses, 1, negativeExcesses, 1)) {
				
					// Throw exception
					throw runtime_error("Adding to positive and negative excesses failed");
				}
				
				// Set sum to the result
				sum = result;
			}
		}
	}
}

// Save
void Kernel::save(ofstream &file) const {

	// Write features to file
	file.write(reinterpret_cast<const char *>(&features), sizeof(features));
	
	// Write fee to file
	const uint64_t serializedFee = Common::hostByteOrderToBigEndian(fee);
	file.write(reinterpret_cast<const char *>(&serializedFee), sizeof(serializedFee));
	
	// Write lock height to file
	const uint64_t serializedLockHeight = Common::hostByteOrderToBigEndian(lockHeight);
	file.write(reinterpret_cast<const char *>(&serializedLockHeight), sizeof(serializedLockHeight));
	
	// Write relative height to file
	const uint64_t serializedRelativeHeight = Common::hostByteOrderToBigEndian(relativeHeight);
	file.write(reinterpret_cast<const char *>(&serializedRelativeHeight), sizeof(serializedRelativeHeight));
	
	// Check if serializing excess failed
	uint8_t serializedExcess[Crypto::COMMITMENT_LENGTH];
	if(!secp256k1_pedersen_commitment_serialize(secp256k1_context_no_precomp, serializedExcess, &excess)) {
	
		// Throw exception
		throw runtime_error("Serializing excess failed");
	}
	
	// Write excess to file
	file.write(reinterpret_cast<const char *>(serializedExcess), sizeof(serializedExcess));
	
	// Write signature to file
	file.write(reinterpret_cast<const char *>(signature), sizeof(signature));
}

// Equality operator
bool Kernel::operator==(const Kernel &other) const {

	// Check if features differ
	if(features != other.features) {
	
		// Return false
		return false;
	}
	
	// Check if fees differ
	if(fee != other.fee) {
	
		// Return false
		return false;
	}
	
	// Check if lock heights differ
	if(lockHeight != other.lockHeight) {
	
		// Return false
		return false;
	}
	
	// Check if relative heights differ
	if(relativeHeight != other.relativeHeight) {
	
		// Return false
		return false;
	}
	
	// Check if serializing excesses failed
	uint8_t serializedExcess[Crypto::COMMITMENT_LENGTH];
	uint8_t otherSerializedExcess[Crypto::COMMITMENT_LENGTH];
	if(!secp256k1_pedersen_commitment_serialize(secp256k1_context_no_precomp, serializedExcess, &excess) || !secp256k1_pedersen_commitment_serialize(secp256k1_context_no_precomp, otherSerializedExcess, &other.excess)) {
	
		// Throw exception
		throw runtime_error("Serializing excesses failed");
	}
	
	// Check if serialized excesses differ
	if(memcmp(serializedExcess, otherSerializedExcess, sizeof(otherSerializedExcess))) {
	
		// Return false
		return false;
	}
	
	// Check if signatures differ
	if(memcmp(signature, other.signature, sizeof(other.signature))) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Inequality operator
bool Kernel::operator!=(const Kernel &other) const {

	// Return if kernels aren't equal
	return !(*this == other);
}

// Get features
Kernel::Features Kernel::getFeatures() const {

	// Return features
	return features;
}

// Get fee
uint64_t Kernel::getFee() const {

	// Return fee
	return fee;
}

// Get lock height
uint64_t Kernel::getLockHeight() const {

	// Return lock height
	return lockHeight;
}

// Get relative height
uint64_t Kernel::getRelativeHeight() const {

	// Return relative height
	return relativeHeight;
}

// Get excess
const secp256k1_pedersen_commitment &Kernel::getExcess() const {

	// Return excess
	return excess;
}

// Get signature
const uint8_t *Kernel::getSignature() const {

	// Return signature
	return signature;
}

// Get serialized protocol version
uint32_t Kernel::getSerializedProtocolVersion(const array<uint8_t, MAXIMUM_SERIALIZED_LENGTH> &serializedKernel, const array<uint8_t, MAXIMUM_SERIALIZED_LENGTH>::size_type serializedKernelLength, const uint32_t protocolVersion) {

	// Check if serialized kernel doesn't contain features
	if(serializedKernelLength < sizeof(Kernel::Features)) {
	
		// Return protocol version
		return protocolVersion;
	}
	
	// Get features from serialized kernel
	const Features features = (Common::readUint8(serializedKernel, 0) < static_cast<underlying_type_t<Features>>(Features::UNKNOWN)) ? static_cast<Features>(Common::readUint8(serializedKernel, 0)) : Features::UNKNOWN;
	
	// Check if features is invalid
	if(features != Consensus::GENESIS_BLOCK_KERNEL.getFeatures()) {
	
		// Return protocol version
		return protocolVersion;
	}
	
	// Check if serialized kernel doesn't contain a fee
	if(serializedKernelLength < sizeof(features) + sizeof(uint64_t)) {
	
		// Return protocol version
		return protocolVersion;
	}
	
	// Get fee from serialized kernel
	const uint64_t fee = Common::readUint64(serializedKernel, sizeof(features));
	
	// Return version based on if the fee exists
	return (fee == Consensus::GENESIS_BLOCK_KERNEL.getFee()) ? 0 : 2;
}

// Unserialize
pair<Kernel, array<uint8_t, Kernel::MAXIMUM_SERIALIZED_LENGTH>::size_type> Kernel::unserialize(const array<uint8_t, MAXIMUM_SERIALIZED_LENGTH> &serializedKernel, const array<uint8_t, MAXIMUM_SERIALIZED_LENGTH>::size_type serializedKernelLength, const uint32_t protocolVersion, const bool isGenesisBlockKernel) {

	// Check if serialized kernel doesn't contain features
	if(serializedKernelLength < sizeof(Kernel::Features)) {
	
		// Throw exception
		throw runtime_error("Serialized kernel doesn't contain features");
	}
	
	// Get features from serialized kernel
	const Features features = (Common::readUint8(serializedKernel, 0) < static_cast<underlying_type_t<Features>>(Features::UNKNOWN)) ? static_cast<Features>(Common::readUint8(serializedKernel, 0)) : Features::UNKNOWN;
	
	// Set fee to zero
	uint64_t fee = 0;
	
	// Set lock height to zero
	uint64_t lockHeight = 0;
	
	// Set relative height to zero
	uint64_t relativeHeight = 0;
	
	// Initialize features size
	array<uint8_t, MAXIMUM_SERIALIZED_LENGTH>::size_type featuresSize;
	
	// Check protocol version
	switch(protocolVersion) {
	
		// Zero or one
		case 0:
		case 1:
	
			// Check if serialized kernel doesn't contain a fee and a lock height or a relative height
			if(serializedKernelLength < sizeof(features) + sizeof(fee) + sizeof(uint64_t)) {
			
				// Throw exception
				throw runtime_error("Serialized kernel doesn't contain a fee and a lock height or a relative height");
			}
			
			// Get fee from serialized kernel
			fee = Common::readUint64(serializedKernel, sizeof(features));
			
			// Check features
			switch(features) {
			
				// Plain, coinbase, or height locked
				case Features::PLAIN:
				case Features::COINBASE:
				case Features::HEIGHT_LOCKED:
				
					// Set lock height from serialized kernel
					lockHeight = Common::readUint64(serializedKernel, sizeof(features) + sizeof(fee));
					
					// Set features size
					featuresSize = sizeof(fee) + sizeof(lockHeight);
					
					// Break
					break;
				
				// No recent duplicate
				case Features::NO_RECENT_DUPLICATE:
				
					// Set relative height from serialized kernel
					relativeHeight = Common::readUint64(serializedKernel, sizeof(features) + sizeof(fee));
					
					// Set features size
					featuresSize = sizeof(fee) + sizeof(relativeHeight);
					
					// Break
					break;
				
				// Default
				default:
				
					// Throw exception
					throw runtime_error("Unknown features");
				
					// Break
					break;
			}
			
			// Break
			break;
		
		// Two or three
		case 2:
		case 3:
		
			// Check features
			switch(features) {
			
				// Plain
				case Features::PLAIN:
				
					// Check if serialized kernel doesn't contain a fee
					if(serializedKernelLength < sizeof(features) + sizeof(fee)) {
					
						// Throw exception
						throw runtime_error("Serialized kernel doesn't contain a fee");
					}
					
					// Get fee from serialized kernel
					fee = Common::readUint64(serializedKernel, sizeof(features));
					
					// Set features size
					featuresSize = sizeof(fee);
					
					// Break
					break;
				
				// Coinbase
				case Features::COINBASE:
				
					// Set features size
					featuresSize = 0;
					
					// Break
					break;
				
				// Height locked
				case Features::HEIGHT_LOCKED:
				
					// Check if serialized kernel doesn't contain a fee and a lock height
					if(serializedKernelLength < sizeof(features) + sizeof(fee) + sizeof(lockHeight)) {
					
						// Throw exception
						throw runtime_error("Serialized kernel doesn't contain a fee and a lock height");
					}
					
					// Get fee from serialized kernel
					fee = Common::readUint64(serializedKernel, sizeof(features));
					
					// Set lock height from serialized kernel
					lockHeight = Common::readUint64(serializedKernel, sizeof(features) + sizeof(fee));
					
					// Set features size
					featuresSize = sizeof(fee) + sizeof(lockHeight);
					
					// Break
					break;
				
				// No recent duplicate
				case Features::NO_RECENT_DUPLICATE:
				
					// Check if serialized kernel doesn't contain a fee and a relative height
					if(serializedKernelLength < sizeof(features) + sizeof(fee) + sizeof(uint16_t)) {
					
						// Throw exception
						throw runtime_error("Serialized kernel doesn't contain a fee and a relative height");
					}
					
					// Get fee from serialized kernel
					fee = Common::readUint64(serializedKernel, sizeof(features));
					
					// Set relative height from serialized kernel
					relativeHeight = Common::readUint16(serializedKernel, sizeof(features) + sizeof(fee));
					
					// Set features size
					featuresSize = sizeof(fee) + sizeof(uint16_t);
					
					// Break
					break;
				
				// Default
				default:
				
					// Throw exception
					throw runtime_error("Unknown features");
				
					// Break
					break;
			}
			
			// Break
			break;
		
		// Default
		default:
		
			// Throw exception
			throw runtime_error("Unknown protocol version");
		
			// Break
			break;
	}
	
	// Check if serialized kernel doesn't contain an excess and a signature
	if(serializedKernelLength < sizeof(features) + featuresSize + Crypto::COMMITMENT_LENGTH + Crypto::SINGLE_SIGNER_SIGNATURE_LENGTH) {
	
		// Throw exception
		throw runtime_error("Serialized kernel doesn't contain an excess and a signature");
	}
	
	// Get excess from serialized kernel
	const uint8_t *excess = &serializedKernel[sizeof(features) + featuresSize];
	
	// Get signature from serialized kernel
	const uint8_t *signature = &serializedKernel[sizeof(features) + featuresSize + Crypto::COMMITMENT_LENGTH];
	
	// Return kernel
	return {Kernel(features, fee, lockHeight, relativeHeight, excess, signature, isGenesisBlockKernel), sizeof(features) + featuresSize + Crypto::COMMITMENT_LENGTH + Crypto::SINGLE_SIGNER_SIGNATURE_LENGTH};
}

// Restore
Kernel Kernel::restore(ifstream &file) {

	// Return kernel created from file
	return Kernel(file);
}

// Save sum
void Kernel::saveSum(const secp256k1_pedersen_commitment &sum, ofstream &file) {

	// Check if sum isn't zero
	uint8_t serializedSum[Crypto::COMMITMENT_LENGTH] = {};
	if(any_of(reinterpret_cast<const uint8_t *>(&sum), reinterpret_cast<const uint8_t *>(&sum) + sizeof(sum), [](const uint8_t value) {
	
		// Return if value isn't zero
		return value;
	})) {
	
		// Check if serializing sum failed
		if(!secp256k1_pedersen_commitment_serialize(secp256k1_context_no_precomp, serializedSum, &sum)) {
		
			// Throw exception
			throw runtime_error("Serializing sum failed");
		}
	}
	
	// Write sum to file
	file.write(reinterpret_cast<const char *>(serializedSum), sizeof(serializedSum));
}

// Restore sum
void Kernel::restoreSum(secp256k1_pedersen_commitment &sum, ifstream &file) {

	// Read sum from file
	uint8_t serializedSum[Crypto::COMMITMENT_LENGTH];
	file.read(reinterpret_cast<char *>(serializedSum), sizeof(serializedSum));
	
	// Check if sum is zero
	if(all_of(serializedSum, serializedSum + sizeof(serializedSum), [](const uint8_t value) {
	
		// Return if value is zero
		return !value;
	})) {
	
		// Set sum to zero
		memset(&sum, 0, sizeof(sum));
	}
	
	// Otherwise
	else {
	
		// Check if parsing sum failed
		if(!secp256k1_pedersen_commitment_parse(secp256k1_context_no_precomp, &sum, serializedSum)) {
	
			// Throw exception
			throw runtime_error("Parsing sum failed");
		}
	}
}

// Constructor
Kernel::Kernel(ifstream &file) {

	// Read features from file
	file.read(reinterpret_cast<char *>(&features), sizeof(features));
	
	// Read fee from file
	uint64_t serializedFee;
	file.read(reinterpret_cast<char *>(&serializedFee), sizeof(serializedFee));
	fee = Common::bigEndianToHostByteOrder(serializedFee);
	
	// Read lock height from file
	uint64_t serializedLockHeight;
	file.read(reinterpret_cast<char *>(&serializedLockHeight), sizeof(serializedLockHeight));
	lockHeight = Common::bigEndianToHostByteOrder(serializedLockHeight);
	
	// Read relative height from file
	uint64_t serializedRelativeHeight;
	file.read(reinterpret_cast<char *>(&serializedRelativeHeight), sizeof(serializedRelativeHeight));
	relativeHeight = Common::bigEndianToHostByteOrder(serializedRelativeHeight);
	
	// Read excess from file
	uint8_t serializedExcess[Crypto::COMMITMENT_LENGTH];
	file.read(reinterpret_cast<char *>(serializedExcess), sizeof(serializedExcess));
	
	// Check if parsing excess failed
	if(!secp256k1_pedersen_commitment_parse(secp256k1_context_no_precomp, &excess, serializedExcess)) {
	
		// Throw exception
		throw runtime_error("Parsing excess failed");
	}
	
	// Read signature from file
	file.read(reinterpret_cast<char *>(signature), sizeof(signature));
}

// Get message to sign
array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH> Kernel::getMessageToSign() const {

	// Initialize data
	vector<uint8_t> data;
	
	// Append features to data
	Common::writeUint8(data, static_cast<underlying_type_t<Features>>(features));

	// Check features
	switch(features) {
	
		// Plain
		case Features::PLAIN:
		
			// Append fee to data
			Common::writeUint64(data, fee);
		
			// Break
			break;
		
		// Height lockeds
		case Features::HEIGHT_LOCKED:
		
			// Append fee to data
			Common::writeUint64(data, fee);
			
			// Append lock height to data
			Common::writeUint64(data, lockHeight);
		
			// Break
			break;
		
		// No recent duplicate
		case Features::NO_RECENT_DUPLICATE:
		
			// Append fee to data
			Common::writeUint64(data, fee);
			
			// Append relative height to data
			Common::writeUint16(data, relativeHeight);
		
			// Break
			break;
		
		// Default
		default:
		
			// Break
			break;
	}
	
	// Initialize message
	array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH> message;
	
	// Check if getting message failed
	if(blake2b(message.data(), message.size(), data.data(), data.size(), nullptr, 0)) {
	
		// Throw error
		throw runtime_error("Getting message failed");
	}
	
	// Return message
	return message;
}
