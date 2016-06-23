
#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include <winbio.h>

#pragma comment(lib, "Winbio.lib")

HRESULT CaptureSample()
{
    HRESULT hr = S_OK;
    WINBIO_SESSION_HANDLE sessionHandle = NULL;
    WINBIO_UNIT_ID unitId = 0;
    WINBIO_REJECT_DETAIL rejectDetail = 0;
    PWINBIO_BIR sample = NULL;
    SIZE_T sampleSize = 0;

    // Connect to the system pool. 
    hr = WinBioOpenSession(
        WINBIO_TYPE_FINGERPRINT,    // Service provider
        WINBIO_POOL_SYSTEM,         // Pool type
        WINBIO_FLAG_RAW,            // Access: Capture raw data
        NULL,                       // Array of biometric unit IDs
        0,                          // Count of biometric unit IDs
        WINBIO_DB_DEFAULT,          // Default database
        &sessionHandle              // [out] Session handle
        );
    if (FAILED(hr))
    {
        wprintf_s(L"\n WinBioOpenSession failed. hr = 0x%x\n", hr);
        goto e_Exit;
    }

    // Capture a biometric sample.
    wprintf_s(L"\n Calling WinBioCaptureSample - Swipe sensor...\n");
    hr = WinBioCaptureSample(
        sessionHandle,
        WINBIO_NO_PURPOSE_AVAILABLE,
        WINBIO_DATA_FLAG_RAW,
        &unitId,
        &sample,
        &sampleSize,
        &rejectDetail
        );
    if (FAILED(hr))
    {
        if (hr == WINBIO_E_BAD_CAPTURE)
        {
            wprintf_s(L"\n Bad capture; reason: %d\n", rejectDetail);
        }
        else
        {
            wprintf_s(L"\n WinBioCaptureSample failed. hr = 0x%x\n", hr);
        }
        goto e_Exit;
    }

    FILE *fp = fopen("fingerprint.dat", "wb+");

    if (NULL != fp)
    {
        char *data = (char*)sample;
        fwrite(&data[sample->StandardDataBlock.Offset], 1, sample->StandardDataBlock.Size, fp);
        fclose(fp);
    }

    wprintf_s(L"\n Swipe processed - Unit ID: %d\n", unitId);
    wprintf_s(L"\n Captured %d bytes.\n", sampleSize);


e_Exit:
    if (sample != NULL)
    {
        WinBioFree(sample);
        sample = NULL;
    }

    if (sessionHandle != NULL)
    {
        WinBioCloseSession(sessionHandle);
        sessionHandle = NULL;
    }

    wprintf_s(L"\n Press any key to exit...");
    _getch();

    return hr;
}

//------------------------------------------------------------------------
// The following function is the callback for WinBioCaptureSampleWithCallback.
// The function filters the response from the biometric subsystem and 
// writes a result to the console window.
//
VOID CALLBACK CaptureSampleCallback(
    __in_opt PVOID CaptureCallbackContext,
    __in HRESULT OperationStatus,
    __in WINBIO_UNIT_ID UnitId,
    __in_bcount(SampleSize) PWINBIO_BIR Sample,
    __in SIZE_T SampleSize,
    __in WINBIO_REJECT_DETAIL RejectDetail
    )
{
    UNREFERENCED_PARAMETER(CaptureCallbackContext);

    wprintf_s(L"\n CaptureSampleCallback executing");
    wprintf_s(L"\n Swipe processed - Unit ID: %d", UnitId);

    if (FAILED(OperationStatus))
    {
        if (OperationStatus == WINBIO_E_BAD_CAPTURE)
        {
            wprintf_s(L"\n Bad capture; reason: %d\n", RejectDetail);
        }
        else
        {
            wprintf_s(L"\n WinBioCaptureSampleWithCallback failed. ");
            wprintf_s(L" OperationStatus = 0x%x\n", OperationStatus);
        }
        goto e_Exit;
    }

    wprintf_s(L"\n Captured %d bytes.\n", SampleSize);

e_Exit:

    if (Sample != NULL)
    {
        WinBioFree(Sample);
        Sample = NULL;
    }
}

HRESULT CaptureSampleWithCallback(BOOL bCancel)
{
    HRESULT hr = S_OK;
    WINBIO_SESSION_HANDLE sessionHandle = NULL;

    // Connect to the system pool. 
    hr = WinBioOpenSession(
        WINBIO_TYPE_FINGERPRINT,    // Service provider
        WINBIO_POOL_SYSTEM,         // Pool type
        WINBIO_FLAG_RAW,            // Raw access
        NULL,                       // Array of biometric unit IDs
        0,                          // Count of biometric unit IDs
        WINBIO_DB_DEFAULT,          // Default database
        &sessionHandle              // [out] Session handle
        );
    if (FAILED(hr))
    {
        wprintf_s(L"\n WinBioOpenSession failed. hr = 0x%x\n", hr);
        goto e_Exit;
    }

    // Capture a biometric sample asynchronously.
    wprintf_s(L"\n Calling WinBioCaptureSampleWithCallback ");
    hr = WinBioCaptureSampleWithCallback(
        sessionHandle,                  // Open session handle
        WINBIO_NO_PURPOSE_AVAILABLE,    // Intended use of the sample
        WINBIO_DATA_FLAG_RAW,           // Sample format
        CaptureSampleCallback,          // Callback function
        NULL                            // Optional context
        );
    if (FAILED(hr))
    {
        wprintf_s(L"\n WinBioCaptureSampleWithCallback failed. ");
        wprintf_s(L"hr = 0x%x\n", hr);
        goto e_Exit;
    }
    wprintf_s(L"\n Swipe the sensor ...\n");

    // Cancel the capture process if the bCancel flag is set.
    if (bCancel)
    {
        wprintf_s(L"\n Starting CANCEL timer...");
        Sleep(7000);

        wprintf_s(L"\n Calling WinBioCancel\n");
        hr = WinBioCancel(sessionHandle);
        if (FAILED(hr))
        {
            wprintf_s(L"\n WinBioCancel failed. hr = 0x%x\n", hr);
            goto e_Exit;
        }
    }

    // Wait for the asynchronous capture process to complete 
    // or be canceled.
    hr = WinBioWait(sessionHandle);
    if (FAILED(hr))
    {
        wprintf_s(L"\n WinBioWait failed. hr = 0x%x\n", hr);
    }

e_Exit:

    if (sessionHandle != NULL)
    {
        WinBioCloseSession(sessionHandle);
        sessionHandle = NULL;
    }

    wprintf_s(L"\n Press any key to exit...");
    _getch();

    return hr;
}

//------------------------------------------------------------------------
// The following function retrieves the identity of the current user.
// This is a helper function and is not part of the Windows Biometric
// Framework API.
//
HRESULT GetCurrentUserIdentity(__inout PWINBIO_IDENTITY Identity)
{
    // Declare variables.
    HRESULT hr = S_OK;
    HANDLE tokenHandle = NULL;
    DWORD bytesReturned = 0;
    struct {
        TOKEN_USER tokenUser;
        BYTE buffer[SECURITY_MAX_SID_SIZE];
    } tokenInfoBuffer;

    // Zero the input identity and specify the type.
    ZeroMemory(Identity, sizeof(WINBIO_IDENTITY));
    Identity->Type = WINBIO_ID_TYPE_NULL;

    // Open the access token associated with the
    // current process
    if (!OpenProcessToken(
        GetCurrentProcess(),            // Process handle
        TOKEN_READ,                     // Read access only
        &tokenHandle))                  // Access token handle
    {
        DWORD win32Status = GetLastError();
        wprintf_s(L"Cannot open token handle: %d\n", win32Status);
        hr = HRESULT_FROM_WIN32(win32Status);
        goto e_Exit;
    }

    // Zero the tokenInfoBuffer structure.
    ZeroMemory(&tokenInfoBuffer, sizeof(tokenInfoBuffer));

    // Retrieve information about the access token. In this case,
    // retrieve a SID.
    if (!GetTokenInformation(
        tokenHandle,                    // Access token handle
        TokenUser,                      // User for the token
        &tokenInfoBuffer.tokenUser,     // Buffer to fill
        sizeof(tokenInfoBuffer),        // Size of the buffer
        &bytesReturned))                // Size needed
    {
        DWORD win32Status = GetLastError();
        wprintf_s(L"Cannot query token information: %d\n", win32Status);
        hr = HRESULT_FROM_WIN32(win32Status);
        goto e_Exit;
    }

    // Copy the SID from the tokenInfoBuffer structure to the
    // WINBIO_IDENTITY structure. 
    CopySid(
        SECURITY_MAX_SID_SIZE,
        Identity->Value.AccountSid.Data,
        tokenInfoBuffer.tokenUser.User.Sid
        );

    // Specify the size of the SID and assign WINBIO_ID_TYPE_SID
    // to the type member of the WINBIO_IDENTITY structure.
    Identity->Value.AccountSid.Size = GetLengthSid(tokenInfoBuffer.tokenUser.User.Sid);
    Identity->Type = WINBIO_ID_TYPE_SID;

e_Exit:

    if (tokenHandle != NULL)
    {
        CloseHandle(tokenHandle);
    }

    return hr;
}

HRESULT Verify(WINBIO_BIOMETRIC_SUBTYPE subFactor)
{
    HRESULT hr = S_OK;
    WINBIO_SESSION_HANDLE sessionHandle = NULL;
    WINBIO_UNIT_ID unitId = 0;
    WINBIO_REJECT_DETAIL rejectDetail = 0;
    WINBIO_IDENTITY identity = { 0 };
    BOOLEAN match = FALSE;

    // Find the identity of the user.
    hr = GetCurrentUserIdentity(&identity);
    if (FAILED(hr))
    {
        wprintf_s(L"\n User identity not found. hr = 0x%x\n", hr);
        goto e_Exit;
    }

    // Connect to the system pool. 
    hr = WinBioOpenSession(
        WINBIO_TYPE_FINGERPRINT,    // Service provider
        WINBIO_POOL_SYSTEM,         // Pool type
        WINBIO_FLAG_DEFAULT,        // Configuration and access
        NULL,                       // Array of biometric unit IDs
        0,                          // Count of biometric unit IDs
        NULL,                       // Database ID
        &sessionHandle              // [out] Session handle
        );
    if (FAILED(hr))
    {
        wprintf_s(L"\n WinBioOpenSession failed. hr = 0x%x\n", hr);
        goto e_Exit;
    }

    // Verify a biometric sample.
    wprintf_s(L"\n Calling WinBioVerify - Swipe finger on sensor...\n");
    hr = WinBioVerify(
        sessionHandle,
        &identity,
        subFactor,
        &unitId,
        &match,
        &rejectDetail
        );
    wprintf_s(L"\n Swipe processed - Unit ID: %d\n", unitId);
    if (FAILED(hr))
    {
        if (hr == WINBIO_E_NO_MATCH)
        {
            wprintf_s(L"\n- NO MATCH - identity verification failed.\n");
        }
        else if (hr == WINBIO_E_BAD_CAPTURE)
        {
            wprintf_s(L"\n- Bad capture; reason: %d\n", rejectDetail);
        }
        else
        {
            wprintf_s(L"\n WinBioVerify failed. hr = 0x%x\n", hr);
        }
        goto e_Exit;
    }
    wprintf_s(L"\n Fingerprint verified:\n", unitId);


e_Exit:
    if (sessionHandle != NULL)
    {
        WinBioCloseSession(sessionHandle);
        sessionHandle = NULL;
    }

    wprintf_s(L"\n Press any key to exit...");
    _getch();

    return hr;
}


HRESULT EnumEnrollments()
{
    // Declare variables.
    HRESULT hr = S_OK;
    WINBIO_IDENTITY identity = { 0 };
    WINBIO_SESSION_HANDLE sessionHandle = NULL;
    WINBIO_UNIT_ID unitId = 0;
    PWINBIO_BIOMETRIC_SUBTYPE subFactorArray = NULL;
    WINBIO_BIOMETRIC_SUBTYPE SubFactor = 0;
    SIZE_T subFactorCount = 0;
    WINBIO_REJECT_DETAIL rejectDetail = 0;
    WINBIO_BIOMETRIC_SUBTYPE subFactor = WINBIO_SUBTYPE_NO_INFORMATION;

    // Connect to the system pool. 
    hr = WinBioOpenSession(
        WINBIO_TYPE_FINGERPRINT,    // Service provider
        WINBIO_POOL_SYSTEM,         // Pool type
        WINBIO_FLAG_DEFAULT,        // Configuration and access
        NULL,                       // Array of biometric unit IDs
        0,                          // Count of biometric unit IDs
        NULL,                       // Database ID
        &sessionHandle              // [out] Session handle
        );
    if (FAILED(hr))
    {
        wprintf_s(L"\n WinBioOpenSession failed. hr = 0x%x\n", hr);
        goto e_Exit;
    }

    for (int i = 0; i < 3; i++)
    {
        // Locate the biometric sensor and retrieve a WINBIO_IDENTITY object.
        wprintf_s(L"\n Calling WinBioIdentify - Swipe finger on sensor...\n");
        hr = WinBioIdentify(
            sessionHandle,              // Session handle
            &unitId,                    // Biometric unit ID
            &identity,                  // User SID
            &subFactor,                 // Finger sub factor
            &rejectDetail               // Rejection information
            );
        wprintf_s(L"\n Swipe processed - Unit ID: %d\n", unitId);
        if (FAILED(hr))
        {
            if (hr == WINBIO_E_UNKNOWN_ID)
            {
                wprintf_s(L"\n Unknown identity.\n");
            }
            else if (hr == WINBIO_E_BAD_CAPTURE)
            {
                wprintf_s(L"\n Bad capture; reason: %d\n", rejectDetail);
            }
            else
            {
                wprintf_s(L"\n WinBioEnumBiometricUnits failed. hr = 0x%x\n", hr);
            }
            goto e_Exit;
        }
        else
        {
            wprintf_s(L"Biometric unit ID = 0x%x\n", unitId);
            wprintf_s(L"User SID = %08x-%04x-%04x-%08x\n", identity.Value.TemplateGuid.Data1, identity.Value.TemplateGuid.Data2, identity.Value.TemplateGuid.Data3, identity.Value.TemplateGuid.Data4);
            wprintf_s(L"Finger sub factor = 0x%x\n", subFactor);
        }

    }

    // Retrieve the biometric sub-factors for the template.
    hr = WinBioEnumEnrollments(
        sessionHandle,              // Session handle
        unitId,                     // Biometric unit ID
        &identity,                  // Template ID
        &subFactorArray,            // Subfactors
        &subFactorCount             // Count of subfactors
        );
    if (FAILED(hr))
    {
        wprintf_s(L"\n WinBioEnumEnrollments failed. hr = 0x%x\n", hr);
        goto e_Exit;
    }

    // Print the sub-factor(s) to the console.
    wprintf_s(L"\n Enrollments for this user on Unit ID %d:", unitId);
    for (SIZE_T index = 0; index < subFactorCount; ++index)
    {
        SubFactor = subFactorArray[index];
        switch (SubFactor)
        {
        case WINBIO_ANSI_381_POS_RH_THUMB:
            wprintf_s(L"\n   RH thumb\n");
            break;
        case WINBIO_ANSI_381_POS_RH_INDEX_FINGER:
            wprintf_s(L"\n   RH index finger\n");
            break;
        case WINBIO_ANSI_381_POS_RH_MIDDLE_FINGER:
            wprintf_s(L"\n   RH middle finger\n");
            break;
        case WINBIO_ANSI_381_POS_RH_RING_FINGER:
            wprintf_s(L"\n   RH ring finger\n");
            break;
        case WINBIO_ANSI_381_POS_RH_LITTLE_FINGER:
            wprintf_s(L"\n   RH little finger\n");
            break;
        case WINBIO_ANSI_381_POS_LH_THUMB:
            wprintf_s(L"\n   LH thumb\n");
            break;
        case WINBIO_ANSI_381_POS_LH_INDEX_FINGER:
            wprintf_s(L"\n   LH index finger\n");
            break;
        case WINBIO_ANSI_381_POS_LH_MIDDLE_FINGER:
            wprintf_s(L"\n   LH middle finger\n");
            break;
        case WINBIO_ANSI_381_POS_LH_RING_FINGER:
            wprintf_s(L"\n   LH ring finger\n");
            break;
        case WINBIO_ANSI_381_POS_LH_LITTLE_FINGER:
            wprintf_s(L"\n   LH little finger\n");
            break;
        default:
            wprintf_s(L"\n   The sub-factor is not correct\n");
            break;
        }

    }

e_Exit:
    if (subFactorArray != NULL)
    {
        WinBioFree(subFactorArray);
        subFactorArray = NULL;
    }

    if (sessionHandle != NULL)
    {
        WinBioCloseSession(sessionHandle);
        sessionHandle = NULL;
    }

    wprintf_s(L"\n Press any key to exit...");
    _getch();

    return hr;
}

//------------------------------------------------------------------------
// The following function displays a GUID to the console window.
//
VOID DisplayGuid(__in PWINBIO_UUID Guid)
{
    wprintf_s(
        L"{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
        Guid->Data1,
        Guid->Data2,
        Guid->Data3,
        Guid->Data4[0],
        Guid->Data4[1],
        Guid->Data4[2],
        Guid->Data4[3],
        Guid->Data4[4],
        Guid->Data4[5],
        Guid->Data4[6],
        Guid->Data4[7]
        );
}

HRESULT EnumDatabases()
{
    // Declare variables.
    HRESULT hr = S_OK;
    PWINBIO_STORAGE_SCHEMA storageSchemaArray = NULL;
    SIZE_T storageCount = 0;
    SIZE_T index = 0;

    // Enumerate the databases.
    hr = WinBioEnumDatabases(
        WINBIO_TYPE_FINGERPRINT,    // Type of biometric unit
        &storageSchemaArray,        // Array of database schemas
        &storageCount);            // Number of database schemas
    if (FAILED(hr))
    {
        wprintf_s(L"\nWinBioEnumDatabases failed. hr = 0x%x\n", hr);
        goto e_Exit;
    }

    // Display information for each database.
    wprintf_s(L"\nDatabases:\n");
    for (index = 0; index < storageCount; ++index)
    {
        wprintf_s(L"\n[%d]: \tBiometric factor: 0x%08x\n",
            index,
            storageSchemaArray[index].BiometricFactor);

        wprintf_s(L"\tDatabase ID: ");
        DisplayGuid(&storageSchemaArray[index].DatabaseId);
        wprintf_s(L"\n");

        wprintf_s(L"\tData format: ");
        DisplayGuid(&storageSchemaArray[index].DataFormat);
        wprintf_s(L"\n");

        wprintf_s(L"\tAttributes:  0x%08x\n",
            storageSchemaArray[index].Attributes);

        wprintf_s(L"\tFile path:   %ws\n",
            storageSchemaArray[index].FilePath);

        wprintf_s(L"\tCnx string:  %ws\n",
            storageSchemaArray[index].ConnectionString);

        wprintf_s(L"\n");
    }

e_Exit:
    if (storageSchemaArray != NULL)
    {
        WinBioFree(storageSchemaArray);
        storageSchemaArray = NULL;
    }

    wprintf_s(L"\nPress any key to exit...");
    _getch();

    return hr;
}

//----------------------------------------------------

HRESULT EnrollSysPool(
    BOOL discardEnrollment,
    WINBIO_BIOMETRIC_SUBTYPE subFactor)
{
    HRESULT hr = S_OK;
    WINBIO_IDENTITY identity = { 0 };
    WINBIO_SESSION_HANDLE sessionHandle = NULL;
    WINBIO_UNIT_ID unitId = 0;
    WINBIO_REJECT_DETAIL rejectDetail = 0;
    BOOLEAN isNewTemplate = TRUE;

    // Connect to the system pool. 
    hr = WinBioOpenSession(
        WINBIO_TYPE_FINGERPRINT,    // Service provider
        WINBIO_POOL_SYSTEM,         // Pool type
        WINBIO_FLAG_DEFAULT,        // Configuration and access
        NULL,                       // Array of biometric unit IDs
        0,                          // Count of biometric unit IDs
        NULL,                       // Database ID
        &sessionHandle              // [out] Session handle
        );
    if (FAILED(hr))
    {
        wprintf_s(L"\n WinBioOpenSession failed. ");
        wprintf_s(L"hr = 0x%x\n", hr);
        goto e_Exit;
    }

    // Locate a sensor.
    wprintf_s(L"\n Swipe your finger on the sensor...\n");
    hr = WinBioLocateSensor(sessionHandle, &unitId);
    if (FAILED(hr))
    {
        wprintf_s(L"\n WinBioLocateSensor failed. hr = 0x%x\n", hr);
        goto e_Exit;
    }

    // Begin the enrollment sequence. 
    wprintf_s(L"\n Starting enrollment sequence...\n");
    hr = WinBioEnrollBegin(
        sessionHandle,      // Handle to open biometric session
        subFactor,          // Finger to create template for
        unitId              // Biometric unit ID
        );
    if (FAILED(hr))
    {
        wprintf_s(L"\n WinBioEnrollBegin failed. hr = 0x%x\n", hr);
        goto e_Exit;
    }

    // Capture enrollment information by swiping the sensor with
    // the finger identified by the subFactor argument in the 
    // WinBioEnrollBegin function.
    for (int swipeCount = 1;; ++swipeCount)
    {
        wprintf_s(L"\n Swipe the sensor to capture %s sample.",
            (swipeCount == 1) ? L"the first" : L"another");

        hr = WinBioEnrollCapture(
            sessionHandle,  // Handle to open biometric session
            &rejectDetail   // [out] Failure information
            );

        wprintf_s(L"\n Sample %d captured from unit number %d.",
            swipeCount,
            unitId);

        if (hr == WINBIO_I_MORE_DATA)
        {
            wprintf_s(L"\n    More data required.\n");
            continue;
        }
        if (FAILED(hr))
        {
            if (hr == WINBIO_E_BAD_CAPTURE)
            {
                wprintf_s(L"\n  Error: Bad capture; reason: %d",
                    rejectDetail);
                continue;
            }
            else
            {
                wprintf_s(L"\n WinBioEnrollCapture failed. hr = 0x%x", hr);
                goto e_Exit;
            }
        }
        else
        {
            wprintf_s(L"\n    Template completed.\n");
            break;
        }
    }

    // Discard the enrollment if the appropriate flag is set.
    // Commit the enrollment if it is not discarded.
    if (discardEnrollment == TRUE)
    {
        wprintf_s(L"\n Discarding enrollment...\n\n");
        hr = WinBioEnrollDiscard(sessionHandle);
        if (FAILED(hr))
        {
            wprintf_s(L"\n WinBioLocateSensor failed. hr = 0x%x\n", hr);
        }
        goto e_Exit;
    }
    else
    {
        wprintf_s(L"\n Committing enrollment...\n");
        hr = WinBioEnrollCommit(
            sessionHandle,      // Handle to open biometric session
            &identity,          // WINBIO_IDENTITY object for the user
            &isNewTemplate);    // Is this a new template

        if (FAILED(hr))
        {
            wprintf_s(L"\n WinBioEnrollCommit failed. hr = 0x%x\n", hr);
            goto e_Exit;
        }
    }


e_Exit:
    if (sessionHandle != NULL)
    {
        WinBioCloseSession(sessionHandle);
        sessionHandle = NULL;
    }

    wprintf_s(L" Press any key to continue...");
    _getch();

    return hr;
}

// need admin run
int main(int argc, char *argv[])
{
    Verify(WINBIO_SUBTYPE_ANY);
    //EnumEnrollments();
    //EnumDatabases();
    //EnrollSysPool(TRUE, WINBIO_SUBTYPE_ANY);
    //CaptureSample();
    //CaptureSampleWithCallback(FALSE);
    return 0;
}