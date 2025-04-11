// Ryckbosch Arthur 2024, Inc. All Rights Reserved.

#pragma once

// OPENSSL
#define UI UI_ST
extern "C" 
{
    #include "openssl/hmac.h"
}
#undef UI


#include "CoreMinimal.h"
#include "Misc/Base64.h"
#include "Misc/AES.h"
#include "Misc/SecureHash.h"
#include "Dom/JsonObject.h"
#include "Dom/JsonValue.h"
#include <string>
#include <vector> // MAC --> NEED THIS TO BUILD WITH XCODE 14.1 
#include "JWT.generated.h"

#define SHA256_DIGEST_LENGTH 32
#define SHA512_DIGEST_LENGTH 64
#define SHA1_DIGEST_LENGTH 20
#define SHA224_DIGEST_LENGTH 28
#define SHA384_DIGEST_LENGTH 48
#define SHA3_224_DIGEST_LENGTH 28
#define SHA3_256_DIGEST_LENGTH 32
#define SHA3_384_DIGEST_LENGTH 48
#define SHA3_512_DIGEST_LENGTH 64
#define MD5_DIGEST_LENGTH 16


UENUM(BlueprintType)
enum class EHashAlgorithm : uint8
{
	EHT_SHA3_256	= 0 UMETA(DisplayName = "SHA3-256"),
	EHT_SHA256		= 1 UMETA(DisplayName = "SHA-256"),
	EHT_SHA3_512	= 2 UMETA(DisplayName = "SHA3-512"),
	EHT_SHA512		= 3 UMETA(DisplayName = "SHA-512"),
	EHT_SHA1		= 4 UMETA(DisplayName = "SHA-1"),
	EHT_MD5			= 5 UMETA(DisplayName = "MD5"),
	EHT_SHA3_224	= 6 UMETA(DisplayName = "SHA3-224"),
	EHT_SHA224		= 7 UMETA(DisplayName = "SHA-224"),
	EHT_SHA3_384	= 8 UMETA(DisplayName = "SHA3-384"),
	EHT_SHA384		= 9 UMETA(DisplayName = "SHA-384")
};

USTRUCT(BlueprintType)
struct FHash
{
	GENERATED_USTRUCT_BODY()
	
	const EVP_MD* Algorithm;
	
	int32 Lenth;
};

UCLASS()
class UJWT : public UObject
{
	GENERATED_BODY()
	
public:
	UJWT();

	UFUNCTION()
	FString GenerateJTW(TMap<FString, FString> Header, TMap<FString, FString> Payload, int Validity, EHashAlgorithm HashAlgorithm, bool bEncodeSecretKeyBase64 = true);

	UFUNCTION()
	bool VerifyToken(FString Token, EHashAlgorithm HashAlgorithm, bool bEncodeSecretKeyBase64 = true);

	UFUNCTION()
	bool IsExpired(FString Token);

	UFUNCTION()
	void SetSecretKey(FString SecretKey);


private :
	UFUNCTION()
	FString TMapToJson(TMap<FString, FString> Map);

	UFUNCTION()
	TMap<FString, FString> GetHeaderFromToken(FString Token);

	UFUNCTION()
	TMap<FString, FString> GetPayloadFromToken(FString Token);

	UPROPERTY()
	FString Secret;

	std::string CalculateHMAC(const std::string& Data, const std::string& Key, EHashAlgorithm HashAlgorithm);
	const FHash GetHash(EHashAlgorithm HashAlgorithm);
};
