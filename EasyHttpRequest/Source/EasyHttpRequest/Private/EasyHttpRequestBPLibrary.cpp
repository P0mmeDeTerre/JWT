// Ryckbosch Arthur 2024, Inc. All Rights Reserved.

#include "EasyHttpRequestBPLibrary.h"

UJWT* UEasyHttpRequestBPLibrary::JWT;

#include <curl/curl.h> // Package libcurl

UEasyHttpRequestBPLibrary::UEasyHttpRequestBPLibrary(const FObjectInitializer& ObjectInitializer)
: Super(ObjectInitializer)
{

}

void UEasyHttpRequestBPLibrary::InitJWT(FString SecretKey)
{
	JWT = NewObject<UJWT>();
	JWT->SetSecretKey(SecretKey);
}

UJWT* UEasyHttpRequestBPLibrary::GetJWT()
{
	return JWT;
}

FString UEasyHttpRequestBPLibrary::GenerateToken(UJWT* Jwt, TMap<FString, FString> Payload, TMap<FString, FString> Header, int Validity, EHashAlgorithm HashAlgorithm, bool bEncodeSecretKeyBase64)
{
	// Add typ and alg to top of the header
	TMap<FString, FString> Headers;
	Headers.Add("typ", "JWT");
	Headers.Add("alg", EnumToString(StaticEnum<EHashAlgorithm>(), static_cast<uint8>(HashAlgorithm)).ToString());

	for(int i = 0; i < Header.Num(); i++)
	{
		Headers.Add(Header.CreateConstIterator().Key(), Header.CreateConstIterator().Value());
	}
	
	FString Token;

	if(Jwt)
	{
		Token =  Jwt->GenerateJTW(Headers, Payload, Validity, HashAlgorithm, bEncodeSecretKeyBase64);
	}
	else
	{
		UE_LOG(LogTemp, Error, TEXT("JWT is not initialized"))
	}
	
	return  Token;
}

FHttpResponse UEasyHttpRequestBPLibrary::SendRequest(FString Token, FString URL, ERequestType RequestType, bool bDisableSSLVerify, bool bDebug)
{
	FString BearerTokenFString = "Authorization: Bearer " + Token;
	char BearerToken[1024];
	snprintf(BearerToken, sizeof(BearerToken), "Authorization: Bearer %s", TCHAR_TO_UTF8(*Token));

	struct curl_slist *headers = nullptr;
	headers = curl_slist_append(headers, BearerToken);

	std::string URLString = TCHAR_TO_UTF8(*URL);
	char* CharURL = const_cast<char*>(URLString.c_str());
	CURL* Curl = curl_easy_init();
	std::string ReadBuffer;
	
	if(Curl)
	{
		curl_easy_setopt(Curl, CURLOPT_HTTPHEADER, headers);
		curl_easy_setopt(Curl, CURLOPT_URL, CharURL);
		curl_easy_setopt(Curl, CURLOPT_CUSTOMREQUEST, TCHAR_TO_UTF8(*EnumToString(StaticEnum<ERequestType>(), static_cast<uint8>(RequestType)).ToString()));
		if(bDebug)
		{
			curl_easy_setopt(Curl, CURLOPT_VERBOSE, 1L);
		}
		if(bDisableSSLVerify)
		{
			curl_easy_setopt(Curl, CURLOPT_SSL_VERIFYPEER, 0L);
		}
		curl_easy_setopt(Curl, CURLOPT_WRITEFUNCTION, UEasyHttpRequestBPLibrary::WriteCallback);
		curl_easy_setopt(Curl, CURLOPT_WRITEDATA, &ReadBuffer); 
		

		UE_LOG(LogTemp, Display, TEXT("Sending request"))
		
		CURLcode Res = curl_easy_perform(Curl);

		UE_LOG(LogTemp, Display, TEXT("Request sent"))

		curl_easy_cleanup(Curl);
		
		return {ReadBuffer.c_str(), Res};
	} 
	
	return {"Failed to send request", -1};
}

FString UEasyHttpRequestBPLibrary::ConvertCurlCodeToString(int32 CurlCode)
{
	CURLcode Code = (CURLcode)CurlCode;

	switch(Code)
	{
		case -1:
			return "Curl init failed";
		
		case CURLE_OK:
			return "All fine. Proceed as usual.";

		case CURLE_UNSUPPORTED_PROTOCOL:
		    return "The URL you passed to libcurl used a protocol that this libcurl does not support. The support might be a compile-time option that you did not use, it can be a misspelled protocol string or just a protocol libcurl has no code for.";

		case CURLE_FAILED_INIT:
		    return "Early initialization code failed. This is likely to be an internal error or problem, or a resource problem where something fundamental could not get done at init time.";

		case CURLE_URL_MALFORMAT:
		    return "The URL was not properly formatted.";

		case CURLE_NOT_BUILT_IN:
		    return "A requested feature, protocol or option was not found built-in in this libcurl due to a build-time decision. This means that a feature or option was not enabled or explicitly disabled when libcurl was built and in order to get it to function you have to get a rebuilt libcurl.";

		case CURLE_COULDNT_RESOLVE_PROXY:
		    return "Could not resolve proxy. The given proxy host could not be resolved.";

		case CURLE_COULDNT_RESOLVE_HOST:
		    return "Could not resolve host. The given remote host was not resolved.";

		case CURLE_COULDNT_CONNECT:
		    return "Failed to connect() to host or proxy.";

		case CURLE_WEIRD_SERVER_REPLY:
		    return "The server sent data libcurl could not parse. This error code was known as CURLE_FTP_WEIRD_SERVER_REPLY before 7.51.0.";

		case CURLE_REMOTE_ACCESS_DENIED:
		    return "We were denied access to the resource given in the URL. For FTP, this occurs while trying to change to the remote directory.";

		case CURLE_FTP_ACCEPT_FAILED:
		    return "While waiting for the server to connect back when an active FTP session is used, an error code was sent over the control connection or similar.";

		case CURLE_FTP_WEIRD_PASS_REPLY:
		    return "After having sent the FTP password to the server, libcurl expects a proper reply. This error code indicates that an unexpected code was returned.";

		case CURLE_FTP_ACCEPT_TIMEOUT:
		    return "During an active FTP session while waiting for the server to connect, the CURLOPT_ACCEPTTIMEOUT_MS (or the internal default) timeout expired.";

		case CURLE_FTP_WEIRD_PASV_REPLY:
		    return "libcurl failed to get a sensible result back from the server as a response to either a PASV or a EPSV command. The server is flawed.";

		case CURLE_FTP_WEIRD_227_FORMAT:
		    return "FTP servers return a 227-line as a response to a PASV command. If libcurl fails to parse that line, this return code is passed back.";

		case CURLE_FTP_CANT_GET_HOST:
		    return "An internal failure to lookup the host used for the new connection.";

		case CURLE_HTTP2:
		    return "A problem was detected in the HTTP2 framing layer. This is somewhat generic and can be one out of several problems, see the error buffer for details.";

		case CURLE_FTP_COULDNT_SET_TYPE:
		    return "Received an error when trying to set the transfer mode to binary or ASCII.";

		case CURLE_PARTIAL_FILE:
		    return "A file transfer was shorter or larger than expected. This happens when the server first reports an expected transfer size, and then delivers data that does not match the previously given size.";

		case CURLE_FTP_COULDNT_RETR_FILE:
		    return "This was either a weird reply to a 'RETR' command or a zero byte transfer complete.";

		case 20:
		    return "Obsolete error (20) - Not used in modern versions.";

		case CURLE_QUOTE_ERROR:
			return "When sending custom 'QUOTE' commands to the remote server, one of the commands returned an error code that was 400 or higher (for FTP) or otherwise indicated unsuccessful completion of the command.";

		case CURLE_HTTP_RETURNED_ERROR:
		    return "This is returned if CURLOPT_FAILONERROR is set TRUE and the HTTP server returns an error code that is >= 400.";

		case CURLE_WRITE_ERROR:
		    return "An error occurred when writing received data to a local file, or an error was returned to libcurl from a write callback.";

		case 24:
		    return "Obsolete error (24) - Not used in modern versions.";

		case CURLE_UPLOAD_FAILED:
		    return "Failed starting the upload. For FTP, the server typically denied the STOR command. The error buffer usually contains the server's explanation for this.";

		case CURLE_READ_ERROR:
		    return "There was a problem reading a local file or an error returned by the read callback.";

		case CURLE_OUT_OF_MEMORY:
		    return "A memory allocation request failed. This is serious badness and things are severely screwed up if this ever occurs.";

		case CURLE_OPERATION_TIMEDOUT:
		    return "Operation timeout. The specified time-out period was reached according to the conditions.";

		case 29:
		    return "Obsolete error (29) - Not used in modern versions.";

		case CURLE_FTP_PORT_FAILED:
		    return "The FTP PORT command returned error. This mostly happens when you have not specified a good enough address for libcurl to use. See CURLOPT_FTPPORT.";

		case CURLE_FTP_COULDNT_USE_REST:
		    return "The FTP REST command returned error. This should never happen if the server is sane.";

		case 32:
		    return "Obsolete error (32) - Not used in modern versions.";

		case CURLE_RANGE_ERROR:
		    return "The server does not support or accept range requests.";

		case CURLE_HTTP_POST_ERROR:
		    return "This is an odd error that mainly occurs due to internal confusion.";

		case CURLE_SSL_CONNECT_ERROR:
		    return "A problem occurred somewhere in the SSL/TLS handshake. You really want the error buffer and read the message there as it pinpoints the problem slightly more. Could be certificates (file formats, paths, permissions), passwords, and others.";

		case CURLE_BAD_DOWNLOAD_RESUME:
		    return "The download could not be resumed because the specified offset was out of the file boundary.";

		case CURLE_FILE_COULDNT_READ_FILE:
		    return "A file given with FILE:// could not be opened. Most likely because the file path does not identify an existing file. Did you Verify file permissions?";

		case CURLE_LDAP_CANNOT_BIND:
		    return "LDAP cannot bind. LDAP bind operation failed.";

		case CURLE_LDAP_SEARCH_FAILED:
		    return "LDAP search failed.";

		case 40:
		    return "Obsolete error (40) - Not used in modern versions.";

		case CURLE_FUNCTION_NOT_FOUND:
			return "Function not found. A required zlib function was not found.";

		case CURLE_ABORTED_BY_CALLBACK:
		    return "Aborted by callback. A callback returned 'abort' to libcurl.";

		case CURLE_BAD_FUNCTION_ARGUMENT:
		    return "A function was called with a bad parameter.";

		case 44:
		    return "Obsolete error (44) - Not used in modern versions.";

		case CURLE_INTERFACE_FAILED:
		    return "Interface error. A specified outgoing interface could not be used. Set which interface to use for outgoing connections' source IP address with CURLOPT_INTERFACE.";

		case 46:
		    return "Obsolete error (46) - Not used in modern versions.";

		case CURLE_TOO_MANY_REDIRECTS:
		    return "Too many redirects. When following redirects, libcurl hit the maximum amount. Set your limit with CURLOPT_MAXREDIRS.";

		case CURLE_UNKNOWN_OPTION:
		    return "An option passed to libcurl is not recognized/known. Refer to the appropriate documentation. This is most likely a problem in the program that uses libcurl. The error buffer might contain more specific information about which exact option it concerns.";

		case CURLE_SETOPT_OPTION_SYNTAX:
		    return "An option passed in to a setopt was wrongly formatted. See error message for details about what option.";

		case 50:
		case 51:
		    return "Obsolete errors (50-51) - Not used in modern versions.";

		case CURLE_GOT_NOTHING:
		    return "Nothing was returned from the server, and under the circumstances, getting nothing is considered an error.";

		case CURLE_SSL_ENGINE_NOTFOUND:
		    return "The specified crypto engine was not found.";

		case CURLE_SSL_ENGINE_SETFAILED:
		    return "Failed setting the selected SSL crypto engine as default.";

		case CURLE_SEND_ERROR:
		    return "Failed sending network data.";

		case CURLE_RECV_ERROR:
		    return "Failure with receiving network data.";

		case 57:
		    return "Obsolete error (57) - Not used in modern versions.";

		case CURLE_SSL_CERTPROBLEM:
		    return "Problem with the local client certificate.";

		case CURLE_SSL_CIPHER:
		    return "Could not use specified cipher.";

		case CURLE_PEER_FAILED_VERIFICATION:
		    return "The remote server's SSL certificate or SSH fingerprint was deemed not OK. This error code has been unified with CURLE_SSL_CACERT since 7.62.0. Its previous value was 51.";

		case CURLE_BAD_CONTENT_ENCODING:
		    return "Unrecognized transfer encoding.";

		case 62:
		    return "Obsolete error (62) - Not used in modern versions.";

		case CURLE_FILESIZE_EXCEEDED:
		    return "Maximum file size exceeded.";

		case CURLE_USE_SSL_FAILED:
		    return "Requested FTP SSL level failed.";

		case CURLE_SEND_FAIL_REWIND:
		    return "When doing a send operation, curl had to rewind the data to retransmit, but the rewinding operation failed.";

		case CURLE_SSL_ENGINE_INITFAILED:
		    return "Initiating the SSL Engine failed.";

		case CURLE_LOGIN_DENIED:
		    return "The remote server denied curl to login (Added in 7.13.1).";

		case CURLE_TFTP_NOTFOUND:
		    return "File not found on TFTP server.";

		case CURLE_TFTP_PERM:
		    return "Permission problem on TFTP server.";

		case CURLE_REMOTE_DISK_FULL:
		    return "Out of disk space on the server.";

		case CURLE_TFTP_ILLEGAL:
			return "Illegal TFTP operation.";

		case CURLE_TFTP_UNKNOWNID:
		    return "Unknown TFTP transfer ID.";

		case CURLE_REMOTE_FILE_EXISTS:
		    return "File already exists and is not overwritten.";

		case CURLE_TFTP_NOSUCHUSER:
		    return "This error should never be returned by a properly functioning TFTP server.";

		case 75:
		case 76:
		    return "Obsolete error (75-76) - Not used in modern versions.";

		case CURLE_SSL_CACERT_BADFILE:
		    return "Problem with reading the SSL CA cert (path? access rights?)";

		case CURLE_REMOTE_FILE_NOT_FOUND:
		    return "The resource referenced in the URL does not exist.";

		case CURLE_SSH:
		    return "An unspecified error occurred during the SSH session.";

		case CURLE_SSL_SHUTDOWN_FAILED:
		    return "Failed to shut down the SSL connection.";

		case CURLE_AGAIN:
		    return "Socket is not ready for send/recv. Wait until it is ready and try again. This return code is only returned from curl_easy_recv and curl_easy_send (Added in 7.18.2)";

		case CURLE_SSL_CRL_BADFILE:
		    return "Failed to load CRL file (Added in 7.19.0)";

		case CURLE_SSL_ISSUER_ERROR:
		    return "Issuer Verify failed (Added in 7.19.0)";

		case CURLE_FTP_PRET_FAILED:
		    return "The FTP server does not understand the PRET command at all or does not support the given argument. Be careful when using CURLOPT_CUSTOMREQUEST, a custom LIST command is sent with the PRET command before PASV as well. (Added in 7.20.0)";

		case CURLE_RTSP_CSEQ_ERROR:
		    return "Mismatch of RTSP CSeq numbers.";

		case CURLE_RTSP_SESSION_ERROR:
		    return "Mismatch of RTSP Session Identifiers.";

		case CURLE_FTP_BAD_FILE_LIST:
		    return "Unable to parse FTP file list (during FTP wildcard downloading).";

		case CURLE_CHUNK_FAILED:
		    return "Chunk callback reported error.";

		case CURLE_NO_CONNECTION_AVAILABLE:
		    return "(For internal use only, is never returned by libcurl) No connection available, the session is queued. (added in 7.30.0)";

		case CURLE_SSL_PINNEDPUBKEYNOTMATCH:
		    return "Failed to match the pinned key specified with CURLOPT_PINNEDPUBLICKEY.";

		case CURLE_SSL_INVALIDCERTSTATUS:
		    return "Status returned failure when asked with CURLOPT_SSL_VERIFYSTATUS.";

		case CURLE_HTTP2_STREAM:
		    return "Stream error in the HTTP/2 framing layer.";

		case CURLE_RECURSIVE_API_CALL:
		    return "An API function was called from inside a callback.";

		case CURLE_AUTH_ERROR:
		    return "An authentication function returned an error.";

		case CURLE_HTTP3:
		    return "A problem was detected in the HTTP/3 layer. This is somewhat generic and can be one out of several problems, see the error buffer for details.";

		case CURLE_QUIC_CONNECT_ERROR:
		    return "QUIC connection error. This error may be caused by an SSL library error. QUIC is the protocol used for HTTP/3 transfers.";

		case CURLE_PROXY:
		    return "Proxy handshake error. CURLINFO_PROXY_ERROR provides extra details on the specific problem.";

		case CURLE_SSL_CLIENTCERT:
		    return "SSL Client Certificate required.";
	
		default:
			return "Unknown error";
	}
}

FJsonResponseObject UEasyHttpRequestBPLibrary::ConvertJsonStringToValue(FString Json, FString DataToFind)
{
	TSharedPtr<FJsonObject> JsonObject;
	TSharedRef<TJsonReader<TCHAR>> JsonReader = TJsonReaderFactory<TCHAR>::Create(Json);
	
	if (FJsonSerializer::Deserialize(JsonReader, JsonObject))
	{
		TArray<FString> DataToFindArray;
		DataToFind.ParseIntoArray(DataToFindArray, TEXT("]["), true);
		DataToFindArray[0].RemoveFromStart("[");
		DataToFindArray[DataToFindArray.Num() - 1].RemoveFromEnd("]");

		const TArray<TSharedPtr<FJsonValue>>* Objects;
		FJsonResponseObject Object;
		Object.bSuccess = false;
		
		FString CurrentObject = "";

		int Index = 0;

		while(Index < DataToFindArray.Num())
		{
			Object.Strings.Empty();
			
			if(JsonObject->TryGetArrayField(DataToFindArray[Index], Objects))
			{
            	if(Index + 1 < DataToFindArray.Num() &&  FCString::IsNumeric(*DataToFindArray[Index + 1]))
            	{
            		int i = FCString::Atoi(*DataToFindArray[Index + 1]);
    
            		if(Objects->IsValidIndex(i))
            		{
            			JsonObject = (*Objects)[i]->AsObject();
              			FString ObjectString;
            			TSharedRef<TJsonWriter<>> Writer = TJsonWriterFactory<>::Create(&ObjectString);
            			FJsonSerializer::Serialize(JsonObject.ToSharedRef(), Writer);

            			Object.Strings.Add(ObjectString);
            			Object.bSuccess = true;
            			
            			Index += 2;
            		}
            		else
            		{
            			return {{"["+ DataToFindArray[Index] + "][" + FString::FromInt(i) +"] is out of range"}, 0};
            		}
            	}
            	else if(Index >= DataToFindArray.Num() - 1)
            	{
            		TArray<FString> SerializedObjects;

            		for(int i = 0; i < Objects->Num(); i++)
            		{
            			TSharedRef<TJsonWriter<>> Writer = TJsonWriterFactory<>::Create(&CurrentObject);
            			FJsonSerializer::Serialize((*Objects)[i]->AsObject().ToSharedRef(), Writer);
            			Object.Strings.Add(CurrentObject);
            		}
            		
            		Object.bSuccess = true;
            		Index++;
            	}
				else
				{
					return {{"The following member of \"" + DataToFindArray[Index] + "\" is not a number"}, false};
				}
			}
            else
            {
            	TSharedPtr<FJsonValue> Field = JsonObject->TryGetField(DataToFindArray[Index]);

            	if(Field.IsValid())
            	{
            		if(!Field->IsNull())
            		{
            			if(Field->TryGetString(CurrentObject))
            			{
            				JsonObject = MakeShareable(new FJsonObject);
            				JsonObject->SetStringField(DataToFindArray[Index], CurrentObject);
            				Object.Strings.Add(CurrentObject);
            				Object.bSuccess = true;
            				Index++;
            			}
            			else
            			{
            				return {{"error"}, false};
            			}
            		}
            		else
            		{
            			return {{"null"}, false};
            		}
            	}
	            else
	            {
	            	return {{"Error : " + DataToFindArray[Index] + " is not an array or a field"}, false};
	            }
            }
		}
		return Object;
	}
	return {{"Failed to parse Json"}, false};
}

bool UEasyHttpRequestBPLibrary::VerifyToken(UJWT* Jwt, FString Token, EHashAlgorithm HashAlgorithm, bool bEncodeSecretKeyBase64)
{
	if(!Jwt)
	{
		UE_LOG(LogTemp, Error, TEXT("JWT is not initialized"))
		return false;
	}
	return JWT->VerifyToken(Token, HashAlgorithm, bEncodeSecretKeyBase64);
	
}

bool UEasyHttpRequestBPLibrary::IsTokenExpired(UJWT* Jwt,FString Token)
{
	if(!Jwt)
	{
		UE_LOG(LogTemp, Error, TEXT("JWT is not initialized"))
		return false;
	}
	return JWT->IsExpired(Token);
}

void UEasyHttpRequestBPLibrary::SendRequestAsync(FString Token, FString URL, ERequestType RequestType, FResponseReceivedDelegate Callback, bool bDisableSSLVerify, bool bDebug)
{
	AsyncTask(ENamedThreads::AnyBackgroundThreadNormalTask, [Token, URL, RequestType, Callback, bDisableSSLVerify, bDebug]()
	{
		FHttpResponse Response = SendRequest(Token, URL, RequestType, bDisableSSLVerify, bDebug);
		
		AsyncTask(ENamedThreads::GameThread, [Response, Callback]()
		{
			Callback.ExecuteIfBound(Response);
		});
	});
}


size_t UEasyHttpRequestBPLibrary::WriteCallback(void* contents, size_t size, size_t nmemb, std::string* s)
{
	size_t newLength = size*nmemb;
	size_t oldLength = s->size();
	try
	{
		s->resize(oldLength + newLength);
	}
	catch(std::bad_alloc &e)
	{
		UE_LOG(LogTemp, Error, TEXT("Memory allocation error: %s"), *FString(e.what()));
		return 0;
	}

	std::copy((char*)contents,(char*)contents+newLength,s->begin()+oldLength);
	return newLength;
}



FText UEasyHttpRequestBPLibrary::EnumToString(const UEnum* Enum, int32 EnumValue)
{
	if (!Enum)
	{
		return FText::FromString("Invalid Enum");
	}

	return Enum->GetDisplayNameTextByIndex(EnumValue);
}

