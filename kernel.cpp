// Header files
#include"./common.h"
#include <cstring>
#include "blake2.h"
#include "./consensus.h"
#include "./kernel.h"
#include "secp256k1_aggsig.h"
#include "secp256k1_commitment.h"

using namespace std;


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
	
	// Check if public key is invalid
	if(all_of(reinterpret_cast<uint8_t *>(&publicKey), reinterpret_cast<uint8_t *>(&publicKey) + 256 / Common::BITS_IN_A_BYTE, [](const uint8_t value) {
	
		// Return if value is zero
		return !value;
	})) {
	
		// Throw exception
		throw runtime_error("Public key is invalid");
	}
	
	// Check if signature is invalid
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
const vector<uint8_t> Kernel::serialize() const {

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
	serializedKernel.insert(serializedKernel.cend(), reinterpret_cast<const uint8_t *>(&signature), reinterpret_cast<const uint8_t *>(&signature) + sizeof(signature));
	
	// Return serialized kernel
	return serializedKernel;
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

// Equality operator
const bool Kernel::operator==(const Kernel &other) const {

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
	if(memcmp(&signature, &other.signature, sizeof(other.signature))) {
	
		// Return false
		return false;
	}
	
	// Return true
	return true;
}

// Inequality operator
const bool Kernel::operator!=(const Kernel &other) const {

	// Return if kernels aren't equal
	return !(*this == other);
}

// Get features
const Kernel::Features Kernel::getFeatures() const {

	// Return features
	return features;
}

// Get fee
const uint64_t Kernel::getFee() const {

	// Return fee
	return fee;
}

// Get lock height
const uint64_t Kernel::getLockHeight() const {

	// Return lock height
	return lockHeight;
}

// Get relative height
const uint64_t Kernel::getRelativeHeight() const {

	// Return relative height
	return relativeHeight;
}

// Get excess
const secp256k1_pedersen_commitment &Kernel::getExcess() const {

	// Return excess
	return excess;
}

// Get signature
const secp256k1_ecdsa_signature &Kernel::getSignature() const {

	// Return signature
	return signature;
}

// Unserialize
const Kernel Kernel::unserialize(const array<uint8_t, SERIALIZED_LENGTH> &serializedKernel, const bool isGenesisBlockKernel) {

	// Get features from serialized kernel
	const Features features = (Common::readUint8(serializedKernel, 0) < static_cast<underlying_type_t<Features>>(Features::UNKNOWN)) ? static_cast<Features>(Common::readUint8(serializedKernel, 0)) : Features::UNKNOWN;
	
	// Get fee from serialized kernel
	const uint64_t fee = Common::readUint64(serializedKernel, sizeof(features));
	
	// Get data from serialized kernel
	const uint64_t data = Common::readUint64(serializedKernel, sizeof(features) + sizeof(fee));
	
	// Set lock height and relative height to zero
	uint64_t lockHeight = 0;
	uint64_t relativeHeight = 0;
	
	// Check features
	switch(features) {
	
		// Plain, coinbase, or height locked
		case Features::PLAIN:
		case Features::COINBASE:
		case Features::HEIGHT_LOCKED:
		
			// Set lock height to data
			lockHeight = data;
			
			// Break
			break;
		
		// No recent duplicate
		case Features::NO_RECENT_DUPLICATE:
		
			// Set relative height to data
			relativeHeight = data;
		
			// Break
			break;
		
		// Default
		default:
		
			// Break
			break;
	}
	
	// Get excess from serialized kernel
	const uint8_t *excess = &serializedKernel[sizeof(features) + sizeof(fee) + sizeof(data)];
	
	// Get signature from serialized kernel
	const uint8_t *signature = &serializedKernel[sizeof(features) + sizeof(fee) + sizeof(data) + Crypto::COMMITMENT_LENGTH];
	
	// Return kernel
	return Kernel(features, fee, lockHeight, relativeHeight, excess, signature, isGenesisBlockKernel);
}

// Get message to sign
const array<uint8_t, Crypto::BLAKE2B_HASH_LENGTH> Kernel::getMessageToSign() const {

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
