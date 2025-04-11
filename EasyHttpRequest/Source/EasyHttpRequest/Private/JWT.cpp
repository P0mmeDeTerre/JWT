// Ryckbosch Arthur 2024, Inc. All Rights Reserved.

#include "JWT.h"
#include "JsonObjectConverter.h"

UJWT::UJWT()
{
}


FString UJWT::GenerateJTW(TMap<FString, FString> Header, TMap<FString, FString> Payload, int Validity, EHashAlgorithm HashAlgorithm, bool bEncodeSecretKeyBase64)
{
	if(Secret.IsEmpty())
	{
		UE_LOG(LogTemp, Error, TEXT("Secret key is empty"));
	}
	
	if(Validity > 0)
	{
		FDateTime Now = FDateTime::Now();
		int Expiration = Now.ToUnixTimestamp() + Validity;
		
		Payload.Add("iat", FString::FromInt(Now.ToUnixTimestamp()));
		Payload.Add("exp", FString::FromInt(Expiration));
	}

	// Convert header to Json and then to Base64
	FString JsonHeader;
	FString Base64Header;
	JsonHeader = TMapToJson(Header);
	Base64Header = FBase64::Encode(JsonHeader, EBase64Mode::Standard);
	Base64Header.ReplaceCharInline('+', '-', ESearchCase::CaseSensitive);
	Base64Header.ReplaceCharInline('/', '_', ESearchCase::CaseSensitive);
	Base64Header.ReplaceInline(TEXT("="), TEXT(""), ESearchCase::CaseSensitive);

	// Convert payload to Json and then to Base64
	FString JsonPayload;
	FString Base64Payload;
	JsonPayload = TMapToJson(Payload);
	Base64Payload = FBase64::Encode(JsonPayload, EBase64Mode::Standard);
	Base64Payload.ReplaceCharInline('+', '-', ESearchCase::CaseSensitive);
	Base64Payload.ReplaceCharInline('/', '_', ESearchCase::CaseSensitive);
	Base64Payload.ReplaceInline(TEXT("="), TEXT(""), ESearchCase::CaseSensitive);
	
	// Convert Secret Key to Base64
	FString Base64Key;
	Base64Key = bEncodeSecretKeyBase64 ? FBase64::Encode(Secret.IsEmpty() ? "" : Secret, EBase64Mode::Standard) : Secret.IsEmpty() ? "" : Secret;

	// Signature
	FString Base64Data = Base64Header + "." + Base64Payload;
	std::string data = std::string(TCHAR_TO_UTF8(*Base64Data));

	std::string hmac = CalculateHMAC(data, TCHAR_TO_UTF8(*Base64Key), HashAlgorithm);
	
	// Convert Signature to base64
	FString Base64Signature;
	Base64Signature =  FBase64::Encode(FString(hmac.c_str()), EBase64Mode::Standard);

	Base64Signature.ReplaceCharInline('+', '-', ESearchCase::CaseSensitive);
	Base64Signature.ReplaceCharInline('/', '_', ESearchCase::CaseSensitive);
	Base64Signature.ReplaceInline(TEXT("="), TEXT(""), ESearchCase::CaseSensitive);

	UE_LOG(LogTemp, Display, TEXT("JWT Generated"))
	
	return Base64Data + "." + Base64Signature;
}

bool UJWT::VerifyToken(FString Token, EHashAlgorithm HashAlgorithm, bool bEncodeSecretKeyBase64)
{
	TMap<FString, FString> Header = GetHeaderFromToken(Token);
	TMap<FString, FString> Payload = GetPayloadFromToken(Token);

	FString NewToken = GenerateJTW(Header, Payload, 0, HashAlgorithm, bEncodeSecretKeyBase64);
	
	return Token == NewToken;
}

bool UJWT::IsExpired(FString Token)
{
	TMap<FString, FString> Payload = GetPayloadFromToken(Token);

	if(Payload.IsEmpty() && !Payload.Find("exp")) { return false; }

	int64 Expiration = FCString::Atoi64(*Payload["exp"]);
	
	return Expiration < FDateTime::Now().ToUnixTimestamp();
}

void UJWT::SetSecretKey(FString SecretKey)
{
	Secret = SecretKey;
}

FString UJWT::TMapToJson(TMap<FString, FString> Map)
{
	FString JsonString = "{";

	for (const auto& Pair : Map)
	{
		// if can convert as a number, add as a number --> remove quotes
		if ( FCString::IsNumeric(*Pair.Value))
		{
			JsonString += "\"" + Pair.Key + "\":" + Pair.Value + ",";
			continue;
		}
		JsonString += "\"" + Pair.Key + "\":\"" + Pair.Value + "\",";
	}

	JsonString = JsonString.LeftChop(1);
	JsonString += "}";

	return JsonString;
}

TMap<FString, FString> UJWT::GetHeaderFromToken(FString Token)
{
	TArray<FString> Array;
	TMap<FString, FString> Header;
	Token.ParseIntoArray(Array, TEXT("."), true);

	if(Array.IsValidIndex(0))
	{
		FString HeaderString;
		FBase64::Decode(Array[0],HeaderString, EBase64Mode::Standard);
		
		TSharedPtr<FJsonObject> JsonObject;
		TSharedRef<TJsonReader<>> Reader = TJsonReaderFactory<>::Create(HeaderString);
		if(FJsonSerializer::Deserialize(Reader, JsonObject))
		{
			for (const auto& Pair : JsonObject->Values)
			{
				Header.Add(Pair.Key, Pair.Value->AsString());
			}
		}
	}

	return Header;
}

TMap<FString, FString> UJWT::GetPayloadFromToken(FString Token)
{
	TArray<FString> Array;
	TMap<FString, FString> Payload;
	Token.ParseIntoArray(Array, TEXT("."), true);

	if(Array.IsValidIndex(1))
	{
		FString PayloadString;
		FBase64::Decode(Array[1],PayloadString, EBase64Mode::Standard);

		TSharedPtr<FJsonObject> JsonObject;
		TSharedRef<TJsonReader<>> Reader = TJsonReaderFactory<>::Create(PayloadString);

		if(FJsonSerializer::Deserialize(Reader, JsonObject))
		{
			for (const auto& Pair : JsonObject->Values)
			{
				Payload.Add(Pair.Key, Pair.Value->AsString());
			}
		}
	}

	return Payload;
}

std::string UJWT::CalculateHMAC(const std::string& Data, const std::string& Key, EHashAlgorithm HashAlgorithm)
{
	FHash HashData = GetHash(HashAlgorithm);
	
	std::vector<unsigned char> Hash(HashData.Lenth);
	HMAC_CTX *HmacCTX = HMAC_CTX_new();
	
	HMAC_Init_ex(HmacCTX, Key.c_str(), Key.length(),HashData.Algorithm , NULL);
	HMAC_Update(HmacCTX, (unsigned char*)Data.c_str(), Data.length());
	HMAC_Final(HmacCTX, Hash.data(), NULL);
	HMAC_CTX_free(HmacCTX);
	
	std::vector<char> HexHash(2 * HashData.Lenth + 1);
	for (int i = 0; i < HashData.Lenth; i++)
	{
		#ifdef _WIN32
				sprintf_s(HexHash.data() + 2 * i, 3, "%02x", Hash[i]);
		#else
				snprintf(HexHash.data() + 2 * i, 3, "%02x", Hash[i]);
		#endif
	}
	return std::string(HexHash.data());
	
}

const FHash UJWT::GetHash(EHashAlgorithm HashAlgorithm)
{
	switch(HashAlgorithm)
	{
		case EHashAlgorithm::EHT_SHA3_256:
			return {EVP_sha3_256(), SHA256_DIGEST_LENGTH};
		
		case EHashAlgorithm::EHT_SHA256:
			return {EVP_sha256(), SHA256_DIGEST_LENGTH};

		case EHashAlgorithm::EHT_SHA3_512:
			return {EVP_sha3_512(), SHA512_DIGEST_LENGTH};

		case EHashAlgorithm::EHT_SHA512:
			return {EVP_sha512(), SHA512_DIGEST_LENGTH};

		case EHashAlgorithm::EHT_SHA1:
			return {EVP_sha1(), SHA1_DIGEST_LENGTH};

		case EHashAlgorithm::EHT_MD5:
			return {EVP_md5(), MD5_DIGEST_LENGTH};

		case EHashAlgorithm::EHT_SHA3_224:
			return {EVP_sha3_224(), SHA224_DIGEST_LENGTH};

		case EHashAlgorithm::EHT_SHA224:
			return {EVP_sha224(), SHA224_DIGEST_LENGTH};

		case EHashAlgorithm::EHT_SHA3_384:
			return {EVP_sha3_384(), SHA384_DIGEST_LENGTH};

		case EHashAlgorithm::EHT_SHA384:
			return {EVP_sha384(), SHA384_DIGEST_LENGTH};
	}

	UE_LOG(LogTemp, Warning, TEXT("Hash type not found. Using the default one (SHA3-256)"));
	return {EVP_sha3_256(), SHA256_DIGEST_LENGTH};
}

