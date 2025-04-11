// Ryckbosch Arthur 2024, Inc. All Rights Reserved.

#pragma once

#include "Kismet/BlueprintFunctionLibrary.h"
#include "JWT.h"
#include "CoreMinimal.h"
#include "Serialization/JsonSerializer.h"
#include "Async/Async.h"
#include <future>
#include <cstdio> // MAC Version
#include "EasyHttpRequestBPLibrary.generated.h"

USTRUCT(BlueprintType)
struct FHttpResponse
{
	GENERATED_USTRUCT_BODY()

	UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "Response")
	FString Response;

	UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "Response")
	int32 ResponseCode;
};

USTRUCT(BlueprintType)
struct FJsonResponseObject
{
	GENERATED_USTRUCT_BODY()

	UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "Json")
	TArray<FString> Strings;

	UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "Response")
	bool bSuccess;
};

UENUM(BlueprintType)
enum class ERequestType : uint8
{
	ERT_GET		= 0 UMETA(DisplayName = "GET"),
	ERT_POST	= 1 UMETA(DisplayName = "POST"),
	ERT_PUT		= 2 UMETA(DisplayName = "PUT"),
	ERT_DELETE	= 3 UMETA(DisplayName = "DELETE"),
	ERT_PATCH	= 4 UMETA(DisplayName = "PATCH"),
	ERT_HEAD	= 5 UMETA(DisplayName = "HEAD"),
	ERT_OPTIONS	= 6 UMETA(DisplayName = "OPTIONS")
};


DECLARE_DYNAMIC_DELEGATE_OneParam(FResponseReceivedDelegate, const FHttpResponse&, Response);

UCLASS()
class UEasyHttpRequestBPLibrary : public UBlueprintFunctionLibrary
{
	GENERATED_UCLASS_BODY()

	UFUNCTION(BlueprintCallable, Category = "JWT")
	static void InitJWT(FString SecretKey);

	UFUNCTION(BlueprintCallable, BlueprintPure, meta = (DisplayName = "JWT", CompactNodeTitle="JWT"), Category = "JWT")
	static UJWT* GetJWT();

	UFUNCTION(BlueprintCallable, meta = (DisplayName = "Generate JWT", Keywords = "JWT Genereta Token", ToolTip = "Generate a JWT\nPayload will automatically contains expiration ('iat' and 'exp')\nHeader will automatically contains JWT type and hash algorithm ('typ' and 'alg')"), Category = "JWT")
	static FString GenerateToken(UJWT* JWT, TMap<FString, FString> Payload, TMap<FString, FString> Header, int Validity, EHashAlgorithm HashAlgorithm, bool bEncodeSecretKeyBase64 = true);

	UFUNCTION(BlueprintCallable, meta = (DisplayName = "Send Request", Keywords = "Send a request\nDisable SSL Verify will disable SSL verification for HTTPS requests, it will allows you to send a HTTPS request without any SSL certificat\nDebug Enable debug mode for Curl (this only works in DEBUG mode when you launch UE5 from your IDE)"), Category = "JWT")
	static FHttpResponse SendRequest(FString Token, FString URL, ERequestType RequestType, bool bDisableSSL_Verify, bool bDebug = false);

	UFUNCTION(BlueprintCallable, BlueprintPure, meta = (DisplayName = "Convert Curl Code To String", Keywords = "JWT Convert Curl Code"), Category = "JWT")
	static FString ConvertCurlCodeToString(int32 CurlCode);

	UFUNCTION(BlueprintCallable, meta = (DisplayName = "Convert JsonString To Value", Keywords = "JWT Convert Json", ToolTip = "Fields --> [KEY][KEY] \nExample : [data][users][1][UserName]"), Category = "JWT")
	static FJsonResponseObject ConvertJsonStringToValue(FString Json, FString Fields);

	UFUNCTION(BlueprintCallable, BlueprintPure, meta = (DisplayName = "Verify Token", Keywords = "JWT Token Verify"), Category = "JWT")
	static bool VerifyToken(UJWT* JWT,FString Token, EHashAlgorithm HashAlgorithm, bool bEncodeSecretKeyBase64);

	UFUNCTION(BlueprintCallable, BlueprintPure, meta = (DisplayName = "Is Token Expired", Keywords = "JWT Token Expired"), Category = "JWT")
	static bool IsTokenExpired(UJWT* JWT,FString Token);
	
	UFUNCTION(BlueprintCallable, meta = (DisplayName = "Send Request Async", Keywords = "JWT Send Request Async", ToolTip = "Send an async request\nDisable SSL Verify will disable SSL verification for HTTPS requests, it will allows you to send a HTTPS request without any SSL certificat\nDebug Enable debug mode for Curl (this only works in DEBUG mode when you launch UE5 from your IDE)"), Category = "JWT")
	static void SendRequestAsync(FString Token, FString URL, ERequestType RequestType, FResponseReceivedDelegate Callback, bool bDisableSSL_Verify, bool bDebug = false);

	
private:
	static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* s);
	static UJWT* JWT;
	static FText EnumToString(const UEnum* Enum, int32 EnumValue);
};
