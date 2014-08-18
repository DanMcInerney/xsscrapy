
#include <Python.h>
#include <stddef.h>

#ifdef MS_WIN32
#include <malloc.h>   /* for alloca() */
typedef __int8 int8_t;
typedef __int16 int16_t;
typedef __int32 int32_t;
typedef __int64 int64_t;
typedef unsigned __int8 uint8_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;
typedef unsigned __int64 uint64_t;
typedef unsigned char _Bool;
#endif

#if PY_MAJOR_VERSION < 3
# undef PyCapsule_CheckExact
# undef PyCapsule_GetPointer
# define PyCapsule_CheckExact(capsule) (PyCObject_Check(capsule))
# define PyCapsule_GetPointer(capsule, name) \
    (PyCObject_AsVoidPtr(capsule))
#endif

#if PY_MAJOR_VERSION >= 3
# define PyInt_FromLong PyLong_FromLong
#endif

#define _cffi_from_c_double PyFloat_FromDouble
#define _cffi_from_c_float PyFloat_FromDouble
#define _cffi_from_c_long PyInt_FromLong
#define _cffi_from_c_ulong PyLong_FromUnsignedLong
#define _cffi_from_c_longlong PyLong_FromLongLong
#define _cffi_from_c_ulonglong PyLong_FromUnsignedLongLong

#define _cffi_to_c_double PyFloat_AsDouble
#define _cffi_to_c_float PyFloat_AsDouble

#define _cffi_from_c_int(x, type)                                        \
    (((type)-1) > 0 ?   /* unsigned */                                   \
        (sizeof(type) < sizeof(long) ? PyInt_FromLong(x) :               \
         sizeof(type) == sizeof(long) ? PyLong_FromUnsignedLong(x) :     \
                                        PyLong_FromUnsignedLongLong(x))  \
      : (sizeof(type) <= sizeof(long) ? PyInt_FromLong(x) :              \
                                        PyLong_FromLongLong(x)))

#define _cffi_to_c_int(o, type)                                          \
    (sizeof(type) == 1 ? (((type)-1) > 0 ? _cffi_to_c_u8(o)              \
                                         : _cffi_to_c_i8(o)) :           \
     sizeof(type) == 2 ? (((type)-1) > 0 ? _cffi_to_c_u16(o)             \
                                         : _cffi_to_c_i16(o)) :          \
     sizeof(type) == 4 ? (((type)-1) > 0 ? _cffi_to_c_u32(o)             \
                                         : _cffi_to_c_i32(o)) :          \
     sizeof(type) == 8 ? (((type)-1) > 0 ? _cffi_to_c_u64(o)             \
                                         : _cffi_to_c_i64(o)) :          \
     (Py_FatalError("unsupported size for type " #type), 0))

#define _cffi_to_c_i8                                                    \
                 ((int(*)(PyObject *))_cffi_exports[1])
#define _cffi_to_c_u8                                                    \
                 ((int(*)(PyObject *))_cffi_exports[2])
#define _cffi_to_c_i16                                                   \
                 ((int(*)(PyObject *))_cffi_exports[3])
#define _cffi_to_c_u16                                                   \
                 ((int(*)(PyObject *))_cffi_exports[4])
#define _cffi_to_c_i32                                                   \
                 ((int(*)(PyObject *))_cffi_exports[5])
#define _cffi_to_c_u32                                                   \
                 ((unsigned int(*)(PyObject *))_cffi_exports[6])
#define _cffi_to_c_i64                                                   \
                 ((long long(*)(PyObject *))_cffi_exports[7])
#define _cffi_to_c_u64                                                   \
                 ((unsigned long long(*)(PyObject *))_cffi_exports[8])
#define _cffi_to_c_char                                                  \
                 ((int(*)(PyObject *))_cffi_exports[9])
#define _cffi_from_c_pointer                                             \
    ((PyObject *(*)(char *, CTypeDescrObject *))_cffi_exports[10])
#define _cffi_to_c_pointer                                               \
    ((char *(*)(PyObject *, CTypeDescrObject *))_cffi_exports[11])
#define _cffi_get_struct_layout                                          \
    ((PyObject *(*)(Py_ssize_t[]))_cffi_exports[12])
#define _cffi_restore_errno                                              \
    ((void(*)(void))_cffi_exports[13])
#define _cffi_save_errno                                                 \
    ((void(*)(void))_cffi_exports[14])
#define _cffi_from_c_char                                                \
    ((PyObject *(*)(char))_cffi_exports[15])
#define _cffi_from_c_deref                                               \
    ((PyObject *(*)(char *, CTypeDescrObject *))_cffi_exports[16])
#define _cffi_to_c                                                       \
    ((int(*)(char *, CTypeDescrObject *, PyObject *))_cffi_exports[17])
#define _cffi_from_c_struct                                              \
    ((PyObject *(*)(char *, CTypeDescrObject *))_cffi_exports[18])
#define _cffi_to_c_wchar_t                                               \
    ((wchar_t(*)(PyObject *))_cffi_exports[19])
#define _cffi_from_c_wchar_t                                             \
    ((PyObject *(*)(wchar_t))_cffi_exports[20])
#define _cffi_to_c_long_double                                           \
    ((long double(*)(PyObject *))_cffi_exports[21])
#define _cffi_to_c__Bool                                                 \
    ((_Bool(*)(PyObject *))_cffi_exports[22])
#define _cffi_prepare_pointer_call_argument                              \
    ((Py_ssize_t(*)(CTypeDescrObject *, PyObject *, char **))_cffi_exports[23])
#define _cffi_convert_array_from_object                                  \
    ((int(*)(char *, CTypeDescrObject *, PyObject *))_cffi_exports[24])
#define _CFFI_NUM_EXPORTS 25

typedef struct _ctypedescr CTypeDescrObject;

static void *_cffi_exports[_CFFI_NUM_EXPORTS];
static PyObject *_cffi_types, *_cffi_VerificationError;

static int _cffi_setup_custom(PyObject *lib);   /* forward */

static PyObject *_cffi_setup(PyObject *self, PyObject *args)
{
    PyObject *library;
    int was_alive = (_cffi_types != NULL);
    if (!PyArg_ParseTuple(args, "OOO", &_cffi_types, &_cffi_VerificationError,
                                       &library))
        return NULL;
    Py_INCREF(_cffi_types);
    Py_INCREF(_cffi_VerificationError);
    if (_cffi_setup_custom(library) < 0)
        return NULL;
    return PyBool_FromLong(was_alive);
}

static void _cffi_init(void)
{
    PyObject *module = PyImport_ImportModule("_cffi_backend");
    PyObject *c_api_object;

    if (module == NULL)
        return;

    c_api_object = PyObject_GetAttrString(module, "_C_API");
    if (c_api_object == NULL)
        return;
    if (!PyCapsule_CheckExact(c_api_object)) {
        Py_DECREF(c_api_object);
        PyErr_SetNone(PyExc_ImportError);
        return;
    }
    memcpy(_cffi_exports, PyCapsule_GetPointer(c_api_object, "cffi"),
           _CFFI_NUM_EXPORTS * sizeof(void *));
    Py_DECREF(c_api_object);
}

#define _cffi_type(num) ((CTypeDescrObject *)PyList_GET_ITEM(_cffi_types, num))

/**********/




#include <CoreFoundation/CoreFoundation.h>


#include <CommonCrypto/CommonDigest.h>


#include <CommonCrypto/CommonHMAC.h>


#include <CommonCrypto/CommonKeyDerivation.h>


#include <CommonCrypto/CommonCryptor.h>


#include <Security/SecImportExport.h>


#include <Security/SecItem.h>


#include <Security/SecKey.h>


#include <Security/SecKeychain.h>


#include <Security/SecDigestTransform.h>
#include <Security/SecSignVerifyTransform.h>
#include <Security/SecEncryptTransform.h>



CFDataRef CFDataCreate(CFAllocatorRef, const UInt8 *, CFIndex);
CFStringRef CFStringCreateWithCString(CFAllocatorRef, const char *,
                                      CFStringEncoding);
CFDictionaryRef CFDictionaryCreate(CFAllocatorRef, const void **,
                                   const void **, CFIndex,
                                   const CFDictionaryKeyCallBacks *,
                                   const CFDictionaryValueCallBacks *);
CFMutableDictionaryRef CFDictionaryCreateMutable(
    CFAllocatorRef,
    CFIndex,
    const CFDictionaryKeyCallBacks *,
    const CFDictionaryValueCallBacks *
);
void CFDictionarySetValue(CFMutableDictionaryRef, const void *, const void *);
CFIndex CFArrayGetCount(CFArrayRef);
const void *CFArrayGetValueAtIndex(CFArrayRef, CFIndex);
CFIndex CFDataGetLength(CFDataRef);
void CFDataGetBytes(CFDataRef, CFRange, UInt8 *);
CFRange CFRangeMake(CFIndex, CFIndex);
void CFShow(CFTypeRef);
Boolean CFBooleanGetValue(CFBooleanRef);
CFNumberRef CFNumberCreate(CFAllocatorRef, CFNumberType, const void *);
void CFRelease(CFTypeRef);
CFTypeRef CFRetain(CFTypeRef);


int CC_MD5_Init(CC_MD5_CTX *);
int CC_MD5_Update(CC_MD5_CTX *, const void *, CC_LONG);
int CC_MD5_Final(unsigned char *, CC_MD5_CTX *);

int CC_SHA1_Init(CC_SHA1_CTX *);
int CC_SHA1_Update(CC_SHA1_CTX *, const void *, CC_LONG);
int CC_SHA1_Final(unsigned char *, CC_SHA1_CTX *);

int CC_SHA224_Init(CC_SHA256_CTX *);
int CC_SHA224_Update(CC_SHA256_CTX *, const void *, CC_LONG);
int CC_SHA224_Final(unsigned char *, CC_SHA256_CTX *);

int CC_SHA256_Init(CC_SHA256_CTX *);
int CC_SHA256_Update(CC_SHA256_CTX *, const void *, CC_LONG);
int CC_SHA256_Final(unsigned char *, CC_SHA256_CTX *);

int CC_SHA384_Init(CC_SHA512_CTX *);
int CC_SHA384_Update(CC_SHA512_CTX *, const void *, CC_LONG);
int CC_SHA384_Final(unsigned char *, CC_SHA512_CTX *);

int CC_SHA512_Init(CC_SHA512_CTX *);
int CC_SHA512_Update(CC_SHA512_CTX *, const void *, CC_LONG);
int CC_SHA512_Final(unsigned char *, CC_SHA512_CTX *);


void CCHmacInit(CCHmacContext *, CCHmacAlgorithm, const void *, size_t);
void CCHmacUpdate(CCHmacContext *, const void *, size_t);
void CCHmacFinal(CCHmacContext *, void *);



int CCKeyDerivationPBKDF(CCPBKDFAlgorithm, const char *, size_t,
                         const uint8_t *, size_t, CCPseudoRandomAlgorithm,
                         uint, uint8_t *, size_t);
uint CCCalibratePBKDF(CCPBKDFAlgorithm, size_t, size_t,
                      CCPseudoRandomAlgorithm, size_t, uint32_t);


CCCryptorStatus CCCryptorCreateWithMode(CCOperation, CCMode, CCAlgorithm,
                                        CCPadding, const void *, const void *,
                                        size_t, const void *, size_t, int,
                                        CCModeOptions, CCCryptorRef *);
CCCryptorStatus CCCryptorCreate(CCOperation, CCAlgorithm, CCOptions,
                                const void *, size_t, const void *,
                                CCCryptorRef *);
CCCryptorStatus CCCryptorUpdate(CCCryptorRef, const void *, size_t, void *,
                                size_t, size_t *);
CCCryptorStatus CCCryptorFinal(CCCryptorRef, void *, size_t, size_t *);
CCCryptorStatus CCCryptorRelease(CCCryptorRef);

CCCryptorStatus CCCryptorGCMAddIV(CCCryptorRef, const void *, size_t);
CCCryptorStatus CCCryptorGCMAddAAD(CCCryptorRef, const void *, size_t);
CCCryptorStatus CCCryptorGCMEncrypt(CCCryptorRef, const void *, size_t,
                                    void *);
CCCryptorStatus CCCryptorGCMDecrypt(CCCryptorRef, const void *, size_t,
                                    void *);
CCCryptorStatus CCCryptorGCMFinal(CCCryptorRef, const void *, size_t *);
CCCryptorStatus CCCryptorGCMReset(CCCryptorRef);


OSStatus SecItemImport(CFDataRef, CFStringRef, SecExternalFormat *,
                       SecExternalItemType *, SecItemImportExportFlags,
                       const SecItemImportExportKeyParameters *,
                       SecKeychainRef, CFArrayRef *);
OSStatus SecPKCS12Import(CFDataRef, CFDictionaryRef, CFArrayRef *);




OSStatus SecKeyGeneratePair(CFDictionaryRef, SecKeyRef *, SecKeyRef *);
size_t SecKeyGetBlockSize(SecKeyRef);


OSStatus SecKeychainCreate(const char *, UInt32, const void *, Boolean,
                           SecAccessRef, SecKeychainRef *);
OSStatus SecKeychainDelete(SecKeychainRef);


Boolean SecTransformSetAttribute(SecTransformRef, CFStringRef, CFTypeRef,
                                 CFErrorRef *);
SecTransformRef SecDecryptTransformCreate(SecKeyRef, CFErrorRef *);
SecTransformRef SecEncryptTransformCreate(SecKeyRef, CFErrorRef *);
SecTransformRef SecVerifyTransformCreate(SecKeyRef, CFDataRef, CFErrorRef *);
SecTransformRef SecSignTransformCreate(SecKeyRef, CFErrorRef *) ;
CFTypeRef SecTransformExecute(SecTransformRef, CFErrorRef *);










/* Not defined in the public header */
enum {
    kCCModeGCM = 11
};












static int _cffi_e__$enum_$1(PyObject *lib)
{
  if ((kCFStringEncodingASCII) < 0 || (unsigned long)(kCFStringEncodingASCII) != 1536UL) {
    char buf[64];
    if ((kCFStringEncodingASCII) < 0)
        snprintf(buf, 63, "%ld", (long)(kCFStringEncodingASCII));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCFStringEncodingASCII));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$1", "kCFStringEncodingASCII", buf, "1536");
    return -1;
  }
  return 0;
}

static int _cffi_e__$enum_$10(PyObject *lib)
{
  if ((kCCModeECB) < 0 || (unsigned long)(kCCModeECB) != 1UL) {
    char buf[64];
    if ((kCCModeECB) < 0)
        snprintf(buf, 63, "%ld", (long)(kCCModeECB));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCCModeECB));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$10", "kCCModeECB", buf, "1");
    return -1;
  }
  if ((kCCModeCBC) < 0 || (unsigned long)(kCCModeCBC) != 2UL) {
    char buf[64];
    if ((kCCModeCBC) < 0)
        snprintf(buf, 63, "%ld", (long)(kCCModeCBC));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCCModeCBC));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$10", "kCCModeCBC", buf, "2");
    return -1;
  }
  if ((kCCModeCFB) < 0 || (unsigned long)(kCCModeCFB) != 3UL) {
    char buf[64];
    if ((kCCModeCFB) < 0)
        snprintf(buf, 63, "%ld", (long)(kCCModeCFB));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCCModeCFB));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$10", "kCCModeCFB", buf, "3");
    return -1;
  }
  if ((kCCModeCTR) < 0 || (unsigned long)(kCCModeCTR) != 4UL) {
    char buf[64];
    if ((kCCModeCTR) < 0)
        snprintf(buf, 63, "%ld", (long)(kCCModeCTR));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCCModeCTR));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$10", "kCCModeCTR", buf, "4");
    return -1;
  }
  if ((kCCModeF8) < 0 || (unsigned long)(kCCModeF8) != 5UL) {
    char buf[64];
    if ((kCCModeF8) < 0)
        snprintf(buf, 63, "%ld", (long)(kCCModeF8));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCCModeF8));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$10", "kCCModeF8", buf, "5");
    return -1;
  }
  if ((kCCModeLRW) < 0 || (unsigned long)(kCCModeLRW) != 6UL) {
    char buf[64];
    if ((kCCModeLRW) < 0)
        snprintf(buf, 63, "%ld", (long)(kCCModeLRW));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCCModeLRW));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$10", "kCCModeLRW", buf, "6");
    return -1;
  }
  if ((kCCModeOFB) < 0 || (unsigned long)(kCCModeOFB) != 7UL) {
    char buf[64];
    if ((kCCModeOFB) < 0)
        snprintf(buf, 63, "%ld", (long)(kCCModeOFB));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCCModeOFB));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$10", "kCCModeOFB", buf, "7");
    return -1;
  }
  if ((kCCModeXTS) < 0 || (unsigned long)(kCCModeXTS) != 8UL) {
    char buf[64];
    if ((kCCModeXTS) < 0)
        snprintf(buf, 63, "%ld", (long)(kCCModeXTS));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCCModeXTS));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$10", "kCCModeXTS", buf, "8");
    return -1;
  }
  if ((kCCModeRC4) < 0 || (unsigned long)(kCCModeRC4) != 9UL) {
    char buf[64];
    if ((kCCModeRC4) < 0)
        snprintf(buf, 63, "%ld", (long)(kCCModeRC4));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCCModeRC4));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$10", "kCCModeRC4", buf, "9");
    return -1;
  }
  if ((kCCModeCFB8) < 0 || (unsigned long)(kCCModeCFB8) != 10UL) {
    char buf[64];
    if ((kCCModeCFB8) < 0)
        snprintf(buf, 63, "%ld", (long)(kCCModeCFB8));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCCModeCFB8));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$10", "kCCModeCFB8", buf, "10");
    return -1;
  }
  if ((kCCModeGCM) < 0 || (unsigned long)(kCCModeGCM) != 11UL) {
    char buf[64];
    if ((kCCModeGCM) < 0)
        snprintf(buf, 63, "%ld", (long)(kCCModeGCM));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCCModeGCM));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$10", "kCCModeGCM", buf, "11");
    return -1;
  }
  return _cffi_e__$enum_$1(lib);
}

static int _cffi_e__$enum_$11(PyObject *lib)
{
  if ((ccNoPadding) < 0 || (unsigned long)(ccNoPadding) != 0UL) {
    char buf[64];
    if ((ccNoPadding) < 0)
        snprintf(buf, 63, "%ld", (long)(ccNoPadding));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(ccNoPadding));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$11", "ccNoPadding", buf, "0");
    return -1;
  }
  if ((ccPKCS7Padding) < 0 || (unsigned long)(ccPKCS7Padding) != 1UL) {
    char buf[64];
    if ((ccPKCS7Padding) < 0)
        snprintf(buf, 63, "%ld", (long)(ccPKCS7Padding));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(ccPKCS7Padding));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$11", "ccPKCS7Padding", buf, "1");
    return -1;
  }
  return _cffi_e__$enum_$10(lib);
}

static int _cffi_e__$enum_$12(PyObject *lib)
{
  if ((kSecItemTypeUnknown) < 0 || (unsigned long)(kSecItemTypeUnknown) != 0UL) {
    char buf[64];
    if ((kSecItemTypeUnknown) < 0)
        snprintf(buf, 63, "%ld", (long)(kSecItemTypeUnknown));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kSecItemTypeUnknown));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$12", "kSecItemTypeUnknown", buf, "0");
    return -1;
  }
  if ((kSecItemTypePrivateKey) < 0 || (unsigned long)(kSecItemTypePrivateKey) != 1UL) {
    char buf[64];
    if ((kSecItemTypePrivateKey) < 0)
        snprintf(buf, 63, "%ld", (long)(kSecItemTypePrivateKey));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kSecItemTypePrivateKey));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$12", "kSecItemTypePrivateKey", buf, "1");
    return -1;
  }
  if ((kSecItemTypePublicKey) < 0 || (unsigned long)(kSecItemTypePublicKey) != 2UL) {
    char buf[64];
    if ((kSecItemTypePublicKey) < 0)
        snprintf(buf, 63, "%ld", (long)(kSecItemTypePublicKey));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kSecItemTypePublicKey));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$12", "kSecItemTypePublicKey", buf, "2");
    return -1;
  }
  if ((kSecItemTypeSessionKey) < 0 || (unsigned long)(kSecItemTypeSessionKey) != 3UL) {
    char buf[64];
    if ((kSecItemTypeSessionKey) < 0)
        snprintf(buf, 63, "%ld", (long)(kSecItemTypeSessionKey));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kSecItemTypeSessionKey));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$12", "kSecItemTypeSessionKey", buf, "3");
    return -1;
  }
  if ((kSecItemTypeCertificate) < 0 || (unsigned long)(kSecItemTypeCertificate) != 4UL) {
    char buf[64];
    if ((kSecItemTypeCertificate) < 0)
        snprintf(buf, 63, "%ld", (long)(kSecItemTypeCertificate));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kSecItemTypeCertificate));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$12", "kSecItemTypeCertificate", buf, "4");
    return -1;
  }
  if ((kSecItemTypeAggregate) < 0 || (unsigned long)(kSecItemTypeAggregate) != 5UL) {
    char buf[64];
    if ((kSecItemTypeAggregate) < 0)
        snprintf(buf, 63, "%ld", (long)(kSecItemTypeAggregate));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kSecItemTypeAggregate));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$12", "kSecItemTypeAggregate", buf, "5");
    return -1;
  }
  return _cffi_e__$enum_$11(lib);
}

static int _cffi_e__$enum_$13(PyObject *lib)
{
  if ((kSecFormatUnknown) < 0 || (unsigned long)(kSecFormatUnknown) != 0UL) {
    char buf[64];
    if ((kSecFormatUnknown) < 0)
        snprintf(buf, 63, "%ld", (long)(kSecFormatUnknown));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kSecFormatUnknown));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$13", "kSecFormatUnknown", buf, "0");
    return -1;
  }
  if ((kSecFormatOpenSSL) < 0 || (unsigned long)(kSecFormatOpenSSL) != 1UL) {
    char buf[64];
    if ((kSecFormatOpenSSL) < 0)
        snprintf(buf, 63, "%ld", (long)(kSecFormatOpenSSL));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kSecFormatOpenSSL));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$13", "kSecFormatOpenSSL", buf, "1");
    return -1;
  }
  if ((kSecFormatSSH) < 0 || (unsigned long)(kSecFormatSSH) != 2UL) {
    char buf[64];
    if ((kSecFormatSSH) < 0)
        snprintf(buf, 63, "%ld", (long)(kSecFormatSSH));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kSecFormatSSH));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$13", "kSecFormatSSH", buf, "2");
    return -1;
  }
  if ((kSecFormatBSAFE) < 0 || (unsigned long)(kSecFormatBSAFE) != 3UL) {
    char buf[64];
    if ((kSecFormatBSAFE) < 0)
        snprintf(buf, 63, "%ld", (long)(kSecFormatBSAFE));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kSecFormatBSAFE));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$13", "kSecFormatBSAFE", buf, "3");
    return -1;
  }
  if ((kSecFormatRawKey) < 0 || (unsigned long)(kSecFormatRawKey) != 4UL) {
    char buf[64];
    if ((kSecFormatRawKey) < 0)
        snprintf(buf, 63, "%ld", (long)(kSecFormatRawKey));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kSecFormatRawKey));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$13", "kSecFormatRawKey", buf, "4");
    return -1;
  }
  if ((kSecFormatWrappedPKCS8) < 0 || (unsigned long)(kSecFormatWrappedPKCS8) != 5UL) {
    char buf[64];
    if ((kSecFormatWrappedPKCS8) < 0)
        snprintf(buf, 63, "%ld", (long)(kSecFormatWrappedPKCS8));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kSecFormatWrappedPKCS8));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$13", "kSecFormatWrappedPKCS8", buf, "5");
    return -1;
  }
  if ((kSecFormatWrappedOpenSSL) < 0 || (unsigned long)(kSecFormatWrappedOpenSSL) != 6UL) {
    char buf[64];
    if ((kSecFormatWrappedOpenSSL) < 0)
        snprintf(buf, 63, "%ld", (long)(kSecFormatWrappedOpenSSL));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kSecFormatWrappedOpenSSL));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$13", "kSecFormatWrappedOpenSSL", buf, "6");
    return -1;
  }
  if ((kSecFormatWrappedSSH) < 0 || (unsigned long)(kSecFormatWrappedSSH) != 7UL) {
    char buf[64];
    if ((kSecFormatWrappedSSH) < 0)
        snprintf(buf, 63, "%ld", (long)(kSecFormatWrappedSSH));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kSecFormatWrappedSSH));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$13", "kSecFormatWrappedSSH", buf, "7");
    return -1;
  }
  if ((kSecFormatWrappedLSH) < 0 || (unsigned long)(kSecFormatWrappedLSH) != 8UL) {
    char buf[64];
    if ((kSecFormatWrappedLSH) < 0)
        snprintf(buf, 63, "%ld", (long)(kSecFormatWrappedLSH));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kSecFormatWrappedLSH));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$13", "kSecFormatWrappedLSH", buf, "8");
    return -1;
  }
  if ((kSecFormatX509Cert) < 0 || (unsigned long)(kSecFormatX509Cert) != 9UL) {
    char buf[64];
    if ((kSecFormatX509Cert) < 0)
        snprintf(buf, 63, "%ld", (long)(kSecFormatX509Cert));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kSecFormatX509Cert));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$13", "kSecFormatX509Cert", buf, "9");
    return -1;
  }
  if ((kSecFormatPEMSequence) < 0 || (unsigned long)(kSecFormatPEMSequence) != 10UL) {
    char buf[64];
    if ((kSecFormatPEMSequence) < 0)
        snprintf(buf, 63, "%ld", (long)(kSecFormatPEMSequence));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kSecFormatPEMSequence));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$13", "kSecFormatPEMSequence", buf, "10");
    return -1;
  }
  if ((kSecFormatPKCS7) < 0 || (unsigned long)(kSecFormatPKCS7) != 11UL) {
    char buf[64];
    if ((kSecFormatPKCS7) < 0)
        snprintf(buf, 63, "%ld", (long)(kSecFormatPKCS7));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kSecFormatPKCS7));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$13", "kSecFormatPKCS7", buf, "11");
    return -1;
  }
  if ((kSecFormatPKCS12) < 0 || (unsigned long)(kSecFormatPKCS12) != 12UL) {
    char buf[64];
    if ((kSecFormatPKCS12) < 0)
        snprintf(buf, 63, "%ld", (long)(kSecFormatPKCS12));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kSecFormatPKCS12));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$13", "kSecFormatPKCS12", buf, "12");
    return -1;
  }
  if ((kSecFormatNetscapeCertSequence) < 0 || (unsigned long)(kSecFormatNetscapeCertSequence) != 13UL) {
    char buf[64];
    if ((kSecFormatNetscapeCertSequence) < 0)
        snprintf(buf, 63, "%ld", (long)(kSecFormatNetscapeCertSequence));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kSecFormatNetscapeCertSequence));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$13", "kSecFormatNetscapeCertSequence", buf, "13");
    return -1;
  }
  if ((kSecFormatSSHv2) < 0 || (unsigned long)(kSecFormatSSHv2) != 14UL) {
    char buf[64];
    if ((kSecFormatSSHv2) < 0)
        snprintf(buf, 63, "%ld", (long)(kSecFormatSSHv2));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kSecFormatSSHv2));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$13", "kSecFormatSSHv2", buf, "14");
    return -1;
  }
  return _cffi_e__$enum_$12(lib);
}

static int _cffi_e__$enum_$14(PyObject *lib)
{
  if ((kSecKeyImportOnlyOne) < 0 || (unsigned long)(kSecKeyImportOnlyOne) != 1UL) {
    char buf[64];
    if ((kSecKeyImportOnlyOne) < 0)
        snprintf(buf, 63, "%ld", (long)(kSecKeyImportOnlyOne));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kSecKeyImportOnlyOne));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$14", "kSecKeyImportOnlyOne", buf, "1");
    return -1;
  }
  if ((kSecKeySecurePassphrase) < 0 || (unsigned long)(kSecKeySecurePassphrase) != 2UL) {
    char buf[64];
    if ((kSecKeySecurePassphrase) < 0)
        snprintf(buf, 63, "%ld", (long)(kSecKeySecurePassphrase));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kSecKeySecurePassphrase));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$14", "kSecKeySecurePassphrase", buf, "2");
    return -1;
  }
  if ((kSecKeyNoAccessControl) < 0 || (unsigned long)(kSecKeyNoAccessControl) != 4UL) {
    char buf[64];
    if ((kSecKeyNoAccessControl) < 0)
        snprintf(buf, 63, "%ld", (long)(kSecKeyNoAccessControl));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kSecKeyNoAccessControl));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$14", "kSecKeyNoAccessControl", buf, "4");
    return -1;
  }
  return _cffi_e__$enum_$13(lib);
}

static int _cffi_e__$enum_$2(PyObject *lib)
{
  if ((kCFNumberSInt8Type) < 0 || (unsigned long)(kCFNumberSInt8Type) != 1UL) {
    char buf[64];
    if ((kCFNumberSInt8Type) < 0)
        snprintf(buf, 63, "%ld", (long)(kCFNumberSInt8Type));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCFNumberSInt8Type));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$2", "kCFNumberSInt8Type", buf, "1");
    return -1;
  }
  if ((kCFNumberSInt16Type) < 0 || (unsigned long)(kCFNumberSInt16Type) != 2UL) {
    char buf[64];
    if ((kCFNumberSInt16Type) < 0)
        snprintf(buf, 63, "%ld", (long)(kCFNumberSInt16Type));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCFNumberSInt16Type));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$2", "kCFNumberSInt16Type", buf, "2");
    return -1;
  }
  if ((kCFNumberSInt32Type) < 0 || (unsigned long)(kCFNumberSInt32Type) != 3UL) {
    char buf[64];
    if ((kCFNumberSInt32Type) < 0)
        snprintf(buf, 63, "%ld", (long)(kCFNumberSInt32Type));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCFNumberSInt32Type));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$2", "kCFNumberSInt32Type", buf, "3");
    return -1;
  }
  if ((kCFNumberSInt64Type) < 0 || (unsigned long)(kCFNumberSInt64Type) != 4UL) {
    char buf[64];
    if ((kCFNumberSInt64Type) < 0)
        snprintf(buf, 63, "%ld", (long)(kCFNumberSInt64Type));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCFNumberSInt64Type));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$2", "kCFNumberSInt64Type", buf, "4");
    return -1;
  }
  if ((kCFNumberFloat32Type) < 0 || (unsigned long)(kCFNumberFloat32Type) != 5UL) {
    char buf[64];
    if ((kCFNumberFloat32Type) < 0)
        snprintf(buf, 63, "%ld", (long)(kCFNumberFloat32Type));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCFNumberFloat32Type));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$2", "kCFNumberFloat32Type", buf, "5");
    return -1;
  }
  if ((kCFNumberFloat64Type) < 0 || (unsigned long)(kCFNumberFloat64Type) != 6UL) {
    char buf[64];
    if ((kCFNumberFloat64Type) < 0)
        snprintf(buf, 63, "%ld", (long)(kCFNumberFloat64Type));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCFNumberFloat64Type));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$2", "kCFNumberFloat64Type", buf, "6");
    return -1;
  }
  if ((kCFNumberCharType) < 0 || (unsigned long)(kCFNumberCharType) != 7UL) {
    char buf[64];
    if ((kCFNumberCharType) < 0)
        snprintf(buf, 63, "%ld", (long)(kCFNumberCharType));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCFNumberCharType));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$2", "kCFNumberCharType", buf, "7");
    return -1;
  }
  if ((kCFNumberShortType) < 0 || (unsigned long)(kCFNumberShortType) != 8UL) {
    char buf[64];
    if ((kCFNumberShortType) < 0)
        snprintf(buf, 63, "%ld", (long)(kCFNumberShortType));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCFNumberShortType));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$2", "kCFNumberShortType", buf, "8");
    return -1;
  }
  if ((kCFNumberIntType) < 0 || (unsigned long)(kCFNumberIntType) != 9UL) {
    char buf[64];
    if ((kCFNumberIntType) < 0)
        snprintf(buf, 63, "%ld", (long)(kCFNumberIntType));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCFNumberIntType));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$2", "kCFNumberIntType", buf, "9");
    return -1;
  }
  if ((kCFNumberLongType) < 0 || (unsigned long)(kCFNumberLongType) != 10UL) {
    char buf[64];
    if ((kCFNumberLongType) < 0)
        snprintf(buf, 63, "%ld", (long)(kCFNumberLongType));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCFNumberLongType));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$2", "kCFNumberLongType", buf, "10");
    return -1;
  }
  if ((kCFNumberLongLongType) < 0 || (unsigned long)(kCFNumberLongLongType) != 11UL) {
    char buf[64];
    if ((kCFNumberLongLongType) < 0)
        snprintf(buf, 63, "%ld", (long)(kCFNumberLongLongType));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCFNumberLongLongType));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$2", "kCFNumberLongLongType", buf, "11");
    return -1;
  }
  if ((kCFNumberFloatType) < 0 || (unsigned long)(kCFNumberFloatType) != 12UL) {
    char buf[64];
    if ((kCFNumberFloatType) < 0)
        snprintf(buf, 63, "%ld", (long)(kCFNumberFloatType));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCFNumberFloatType));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$2", "kCFNumberFloatType", buf, "12");
    return -1;
  }
  if ((kCFNumberDoubleType) < 0 || (unsigned long)(kCFNumberDoubleType) != 13UL) {
    char buf[64];
    if ((kCFNumberDoubleType) < 0)
        snprintf(buf, 63, "%ld", (long)(kCFNumberDoubleType));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCFNumberDoubleType));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$2", "kCFNumberDoubleType", buf, "13");
    return -1;
  }
  if ((kCFNumberCFIndexType) < 0 || (unsigned long)(kCFNumberCFIndexType) != 14UL) {
    char buf[64];
    if ((kCFNumberCFIndexType) < 0)
        snprintf(buf, 63, "%ld", (long)(kCFNumberCFIndexType));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCFNumberCFIndexType));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$2", "kCFNumberCFIndexType", buf, "14");
    return -1;
  }
  if ((kCFNumberNSIntegerType) < 0 || (unsigned long)(kCFNumberNSIntegerType) != 15UL) {
    char buf[64];
    if ((kCFNumberNSIntegerType) < 0)
        snprintf(buf, 63, "%ld", (long)(kCFNumberNSIntegerType));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCFNumberNSIntegerType));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$2", "kCFNumberNSIntegerType", buf, "15");
    return -1;
  }
  if ((kCFNumberCGFloatType) < 0 || (unsigned long)(kCFNumberCGFloatType) != 16UL) {
    char buf[64];
    if ((kCFNumberCGFloatType) < 0)
        snprintf(buf, 63, "%ld", (long)(kCFNumberCGFloatType));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCFNumberCGFloatType));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$2", "kCFNumberCGFloatType", buf, "16");
    return -1;
  }
  if ((kCFNumberMaxType) < 0 || (unsigned long)(kCFNumberMaxType) != 16UL) {
    char buf[64];
    if ((kCFNumberMaxType) < 0)
        snprintf(buf, 63, "%ld", (long)(kCFNumberMaxType));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCFNumberMaxType));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$2", "kCFNumberMaxType", buf, "16");
    return -1;
  }
  return _cffi_e__$enum_$14(lib);
}

static int _cffi_e__$enum_$3(PyObject *lib)
{
  if ((kCCHmacAlgSHA1) < 0 || (unsigned long)(kCCHmacAlgSHA1) != 0UL) {
    char buf[64];
    if ((kCCHmacAlgSHA1) < 0)
        snprintf(buf, 63, "%ld", (long)(kCCHmacAlgSHA1));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCCHmacAlgSHA1));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$3", "kCCHmacAlgSHA1", buf, "0");
    return -1;
  }
  if ((kCCHmacAlgMD5) < 0 || (unsigned long)(kCCHmacAlgMD5) != 1UL) {
    char buf[64];
    if ((kCCHmacAlgMD5) < 0)
        snprintf(buf, 63, "%ld", (long)(kCCHmacAlgMD5));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCCHmacAlgMD5));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$3", "kCCHmacAlgMD5", buf, "1");
    return -1;
  }
  if ((kCCHmacAlgSHA256) < 0 || (unsigned long)(kCCHmacAlgSHA256) != 2UL) {
    char buf[64];
    if ((kCCHmacAlgSHA256) < 0)
        snprintf(buf, 63, "%ld", (long)(kCCHmacAlgSHA256));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCCHmacAlgSHA256));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$3", "kCCHmacAlgSHA256", buf, "2");
    return -1;
  }
  if ((kCCHmacAlgSHA384) < 0 || (unsigned long)(kCCHmacAlgSHA384) != 3UL) {
    char buf[64];
    if ((kCCHmacAlgSHA384) < 0)
        snprintf(buf, 63, "%ld", (long)(kCCHmacAlgSHA384));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCCHmacAlgSHA384));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$3", "kCCHmacAlgSHA384", buf, "3");
    return -1;
  }
  if ((kCCHmacAlgSHA512) < 0 || (unsigned long)(kCCHmacAlgSHA512) != 4UL) {
    char buf[64];
    if ((kCCHmacAlgSHA512) < 0)
        snprintf(buf, 63, "%ld", (long)(kCCHmacAlgSHA512));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCCHmacAlgSHA512));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$3", "kCCHmacAlgSHA512", buf, "4");
    return -1;
  }
  if ((kCCHmacAlgSHA224) < 0 || (unsigned long)(kCCHmacAlgSHA224) != 5UL) {
    char buf[64];
    if ((kCCHmacAlgSHA224) < 0)
        snprintf(buf, 63, "%ld", (long)(kCCHmacAlgSHA224));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCCHmacAlgSHA224));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$3", "kCCHmacAlgSHA224", buf, "5");
    return -1;
  }
  return _cffi_e__$enum_$2(lib);
}

static int _cffi_e__$enum_$4(PyObject *lib)
{
  if ((kCCPBKDF2) < 0 || (unsigned long)(kCCPBKDF2) != 2UL) {
    char buf[64];
    if ((kCCPBKDF2) < 0)
        snprintf(buf, 63, "%ld", (long)(kCCPBKDF2));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCCPBKDF2));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$4", "kCCPBKDF2", buf, "2");
    return -1;
  }
  return _cffi_e__$enum_$3(lib);
}

static int _cffi_e__$enum_$5(PyObject *lib)
{
  if ((kCCPRFHmacAlgSHA1) < 0 || (unsigned long)(kCCPRFHmacAlgSHA1) != 1UL) {
    char buf[64];
    if ((kCCPRFHmacAlgSHA1) < 0)
        snprintf(buf, 63, "%ld", (long)(kCCPRFHmacAlgSHA1));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCCPRFHmacAlgSHA1));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$5", "kCCPRFHmacAlgSHA1", buf, "1");
    return -1;
  }
  if ((kCCPRFHmacAlgSHA224) < 0 || (unsigned long)(kCCPRFHmacAlgSHA224) != 2UL) {
    char buf[64];
    if ((kCCPRFHmacAlgSHA224) < 0)
        snprintf(buf, 63, "%ld", (long)(kCCPRFHmacAlgSHA224));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCCPRFHmacAlgSHA224));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$5", "kCCPRFHmacAlgSHA224", buf, "2");
    return -1;
  }
  if ((kCCPRFHmacAlgSHA256) < 0 || (unsigned long)(kCCPRFHmacAlgSHA256) != 3UL) {
    char buf[64];
    if ((kCCPRFHmacAlgSHA256) < 0)
        snprintf(buf, 63, "%ld", (long)(kCCPRFHmacAlgSHA256));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCCPRFHmacAlgSHA256));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$5", "kCCPRFHmacAlgSHA256", buf, "3");
    return -1;
  }
  if ((kCCPRFHmacAlgSHA384) < 0 || (unsigned long)(kCCPRFHmacAlgSHA384) != 4UL) {
    char buf[64];
    if ((kCCPRFHmacAlgSHA384) < 0)
        snprintf(buf, 63, "%ld", (long)(kCCPRFHmacAlgSHA384));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCCPRFHmacAlgSHA384));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$5", "kCCPRFHmacAlgSHA384", buf, "4");
    return -1;
  }
  if ((kCCPRFHmacAlgSHA512) < 0 || (unsigned long)(kCCPRFHmacAlgSHA512) != 5UL) {
    char buf[64];
    if ((kCCPRFHmacAlgSHA512) < 0)
        snprintf(buf, 63, "%ld", (long)(kCCPRFHmacAlgSHA512));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCCPRFHmacAlgSHA512));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$5", "kCCPRFHmacAlgSHA512", buf, "5");
    return -1;
  }
  return _cffi_e__$enum_$4(lib);
}

static int _cffi_e__$enum_$6(PyObject *lib)
{
  if ((kCCAlgorithmAES128) < 0 || (unsigned long)(kCCAlgorithmAES128) != 0UL) {
    char buf[64];
    if ((kCCAlgorithmAES128) < 0)
        snprintf(buf, 63, "%ld", (long)(kCCAlgorithmAES128));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCCAlgorithmAES128));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$6", "kCCAlgorithmAES128", buf, "0");
    return -1;
  }
  if ((kCCAlgorithmDES) < 0 || (unsigned long)(kCCAlgorithmDES) != 1UL) {
    char buf[64];
    if ((kCCAlgorithmDES) < 0)
        snprintf(buf, 63, "%ld", (long)(kCCAlgorithmDES));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCCAlgorithmDES));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$6", "kCCAlgorithmDES", buf, "1");
    return -1;
  }
  if ((kCCAlgorithm3DES) < 0 || (unsigned long)(kCCAlgorithm3DES) != 2UL) {
    char buf[64];
    if ((kCCAlgorithm3DES) < 0)
        snprintf(buf, 63, "%ld", (long)(kCCAlgorithm3DES));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCCAlgorithm3DES));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$6", "kCCAlgorithm3DES", buf, "2");
    return -1;
  }
  if ((kCCAlgorithmCAST) < 0 || (unsigned long)(kCCAlgorithmCAST) != 3UL) {
    char buf[64];
    if ((kCCAlgorithmCAST) < 0)
        snprintf(buf, 63, "%ld", (long)(kCCAlgorithmCAST));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCCAlgorithmCAST));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$6", "kCCAlgorithmCAST", buf, "3");
    return -1;
  }
  if ((kCCAlgorithmRC4) < 0 || (unsigned long)(kCCAlgorithmRC4) != 4UL) {
    char buf[64];
    if ((kCCAlgorithmRC4) < 0)
        snprintf(buf, 63, "%ld", (long)(kCCAlgorithmRC4));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCCAlgorithmRC4));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$6", "kCCAlgorithmRC4", buf, "4");
    return -1;
  }
  if ((kCCAlgorithmRC2) < 0 || (unsigned long)(kCCAlgorithmRC2) != 5UL) {
    char buf[64];
    if ((kCCAlgorithmRC2) < 0)
        snprintf(buf, 63, "%ld", (long)(kCCAlgorithmRC2));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCCAlgorithmRC2));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$6", "kCCAlgorithmRC2", buf, "5");
    return -1;
  }
  if ((kCCAlgorithmBlowfish) < 0 || (unsigned long)(kCCAlgorithmBlowfish) != 6UL) {
    char buf[64];
    if ((kCCAlgorithmBlowfish) < 0)
        snprintf(buf, 63, "%ld", (long)(kCCAlgorithmBlowfish));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCCAlgorithmBlowfish));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$6", "kCCAlgorithmBlowfish", buf, "6");
    return -1;
  }
  return _cffi_e__$enum_$5(lib);
}

static int _cffi_e__$enum_$7(PyObject *lib)
{
  if ((kCCSuccess) < 0 || (unsigned long)(kCCSuccess) != 0UL) {
    char buf[64];
    if ((kCCSuccess) < 0)
        snprintf(buf, 63, "%ld", (long)(kCCSuccess));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCCSuccess));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$7", "kCCSuccess", buf, "0");
    return -1;
  }
  if ((kCCParamError) >= 0 || (long)(kCCParamError) != -4300L) {
    char buf[64];
    if ((kCCParamError) < 0)
        snprintf(buf, 63, "%ld", (long)(kCCParamError));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCCParamError));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$7", "kCCParamError", buf, "-4300");
    return -1;
  }
  if ((kCCBufferTooSmall) >= 0 || (long)(kCCBufferTooSmall) != -4301L) {
    char buf[64];
    if ((kCCBufferTooSmall) < 0)
        snprintf(buf, 63, "%ld", (long)(kCCBufferTooSmall));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCCBufferTooSmall));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$7", "kCCBufferTooSmall", buf, "-4301");
    return -1;
  }
  if ((kCCMemoryFailure) >= 0 || (long)(kCCMemoryFailure) != -4302L) {
    char buf[64];
    if ((kCCMemoryFailure) < 0)
        snprintf(buf, 63, "%ld", (long)(kCCMemoryFailure));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCCMemoryFailure));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$7", "kCCMemoryFailure", buf, "-4302");
    return -1;
  }
  if ((kCCAlignmentError) >= 0 || (long)(kCCAlignmentError) != -4303L) {
    char buf[64];
    if ((kCCAlignmentError) < 0)
        snprintf(buf, 63, "%ld", (long)(kCCAlignmentError));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCCAlignmentError));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$7", "kCCAlignmentError", buf, "-4303");
    return -1;
  }
  if ((kCCDecodeError) >= 0 || (long)(kCCDecodeError) != -4304L) {
    char buf[64];
    if ((kCCDecodeError) < 0)
        snprintf(buf, 63, "%ld", (long)(kCCDecodeError));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCCDecodeError));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$7", "kCCDecodeError", buf, "-4304");
    return -1;
  }
  if ((kCCUnimplemented) >= 0 || (long)(kCCUnimplemented) != -4305L) {
    char buf[64];
    if ((kCCUnimplemented) < 0)
        snprintf(buf, 63, "%ld", (long)(kCCUnimplemented));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCCUnimplemented));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$7", "kCCUnimplemented", buf, "-4305");
    return -1;
  }
  return _cffi_e__$enum_$6(lib);
}

static int _cffi_e__$enum_$8(PyObject *lib)
{
  if ((kCCEncrypt) < 0 || (unsigned long)(kCCEncrypt) != 0UL) {
    char buf[64];
    if ((kCCEncrypt) < 0)
        snprintf(buf, 63, "%ld", (long)(kCCEncrypt));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCCEncrypt));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$8", "kCCEncrypt", buf, "0");
    return -1;
  }
  if ((kCCDecrypt) < 0 || (unsigned long)(kCCDecrypt) != 1UL) {
    char buf[64];
    if ((kCCDecrypt) < 0)
        snprintf(buf, 63, "%ld", (long)(kCCDecrypt));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCCDecrypt));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$8", "kCCDecrypt", buf, "1");
    return -1;
  }
  return _cffi_e__$enum_$7(lib);
}

static int _cffi_e__$enum_$9(PyObject *lib)
{
  if ((kCCModeOptionCTR_LE) < 0 || (unsigned long)(kCCModeOptionCTR_LE) != 1UL) {
    char buf[64];
    if ((kCCModeOptionCTR_LE) < 0)
        snprintf(buf, 63, "%ld", (long)(kCCModeOptionCTR_LE));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCCModeOptionCTR_LE));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$9", "kCCModeOptionCTR_LE", buf, "1");
    return -1;
  }
  if ((kCCModeOptionCTR_BE) < 0 || (unsigned long)(kCCModeOptionCTR_BE) != 2UL) {
    char buf[64];
    if ((kCCModeOptionCTR_BE) < 0)
        snprintf(buf, 63, "%ld", (long)(kCCModeOptionCTR_BE));
    else
        snprintf(buf, 63, "%lu", (unsigned long)(kCCModeOptionCTR_BE));
    PyErr_Format(_cffi_VerificationError,
                 "enum %s: %s has the real value %s, not %s",
                 "$enum_$9", "kCCModeOptionCTR_BE", buf, "2");
    return -1;
  }
  return _cffi_e__$enum_$8(lib);
}

static void _cffi_check__CCHmacContext(CCHmacContext *p)
{
  /* only to generate compile-time warnings or errors */
}
static PyObject *
_cffi_layout__CCHmacContext(PyObject *self, PyObject *noarg)
{
  struct _cffi_aligncheck { char x; CCHmacContext y; };
  static Py_ssize_t nums[] = {
    sizeof(CCHmacContext),
    offsetof(struct _cffi_aligncheck, y),
    -1
  };
  return _cffi_get_struct_layout(nums);
  /* the next line is not executed, but compiled */
  _cffi_check__CCHmacContext(0);
}

static void _cffi_check__CFDictionaryKeyCallBacks(CFDictionaryKeyCallBacks *p)
{
  /* only to generate compile-time warnings or errors */
}
static PyObject *
_cffi_layout__CFDictionaryKeyCallBacks(PyObject *self, PyObject *noarg)
{
  struct _cffi_aligncheck { char x; CFDictionaryKeyCallBacks y; };
  static Py_ssize_t nums[] = {
    sizeof(CFDictionaryKeyCallBacks),
    offsetof(struct _cffi_aligncheck, y),
    -1
  };
  return _cffi_get_struct_layout(nums);
  /* the next line is not executed, but compiled */
  _cffi_check__CFDictionaryKeyCallBacks(0);
}

static void _cffi_check__CFDictionaryValueCallBacks(CFDictionaryValueCallBacks *p)
{
  /* only to generate compile-time warnings or errors */
}
static PyObject *
_cffi_layout__CFDictionaryValueCallBacks(PyObject *self, PyObject *noarg)
{
  struct _cffi_aligncheck { char x; CFDictionaryValueCallBacks y; };
  static Py_ssize_t nums[] = {
    sizeof(CFDictionaryValueCallBacks),
    offsetof(struct _cffi_aligncheck, y),
    -1
  };
  return _cffi_get_struct_layout(nums);
  /* the next line is not executed, but compiled */
  _cffi_check__CFDictionaryValueCallBacks(0);
}

static void _cffi_check__CFRange(CFRange *p)
{
  /* only to generate compile-time warnings or errors */
}
static PyObject *
_cffi_layout__CFRange(PyObject *self, PyObject *noarg)
{
  struct _cffi_aligncheck { char x; CFRange y; };
  static Py_ssize_t nums[] = {
    sizeof(CFRange),
    offsetof(struct _cffi_aligncheck, y),
    -1
  };
  return _cffi_get_struct_layout(nums);
  /* the next line is not executed, but compiled */
  _cffi_check__CFRange(0);
}

static void _cffi_check__SecItemImportExportKeyParameters(SecItemImportExportKeyParameters *p)
{
  /* only to generate compile-time warnings or errors */
  (void)((p->version) << 1);
  (void)((p->flags) << 1);
  { CFTypeRef *tmp = &p->passphrase; (void)tmp; }
  { CFStringRef *tmp = &p->alertTitle; (void)tmp; }
  { CFStringRef *tmp = &p->alertPrompt; (void)tmp; }
  { SecAccessRef *tmp = &p->accessRef; (void)tmp; }
  { CFArrayRef *tmp = &p->keyUsage; (void)tmp; }
  { CFArrayRef *tmp = &p->keyAttributes; (void)tmp; }
}
static PyObject *
_cffi_layout__SecItemImportExportKeyParameters(PyObject *self, PyObject *noarg)
{
  struct _cffi_aligncheck { char x; SecItemImportExportKeyParameters y; };
  static Py_ssize_t nums[] = {
    sizeof(SecItemImportExportKeyParameters),
    offsetof(struct _cffi_aligncheck, y),
    offsetof(SecItemImportExportKeyParameters, version),
    sizeof(((SecItemImportExportKeyParameters *)0)->version),
    offsetof(SecItemImportExportKeyParameters, flags),
    sizeof(((SecItemImportExportKeyParameters *)0)->flags),
    offsetof(SecItemImportExportKeyParameters, passphrase),
    sizeof(((SecItemImportExportKeyParameters *)0)->passphrase),
    offsetof(SecItemImportExportKeyParameters, alertTitle),
    sizeof(((SecItemImportExportKeyParameters *)0)->alertTitle),
    offsetof(SecItemImportExportKeyParameters, alertPrompt),
    sizeof(((SecItemImportExportKeyParameters *)0)->alertPrompt),
    offsetof(SecItemImportExportKeyParameters, accessRef),
    sizeof(((SecItemImportExportKeyParameters *)0)->accessRef),
    offsetof(SecItemImportExportKeyParameters, keyUsage),
    sizeof(((SecItemImportExportKeyParameters *)0)->keyUsage),
    offsetof(SecItemImportExportKeyParameters, keyAttributes),
    sizeof(((SecItemImportExportKeyParameters *)0)->keyAttributes),
    -1
  };
  return _cffi_get_struct_layout(nums);
  /* the next line is not executed, but compiled */
  _cffi_check__SecItemImportExportKeyParameters(0);
}

static int _cffi_const_kCFAllocatorDefault(PyObject *lib)
{
  PyObject *o;
  int res;
  void const * i;
  i = (kCFAllocatorDefault);
  o = _cffi_from_c_pointer((char *)i, _cffi_type(0));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kCFAllocatorDefault", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_e__$enum_$9(lib);
}

static int _cffi_const_kCFBooleanFalse(PyObject *lib)
{
  PyObject *o;
  int res;
  CFBooleanRef i;
  i = (kCFBooleanFalse);
  o = _cffi_from_c_pointer((char *)i, _cffi_type(1));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kCFBooleanFalse", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_const_kCFAllocatorDefault(lib);
}

static int _cffi_const_kCFBooleanTrue(PyObject *lib)
{
  PyObject *o;
  int res;
  CFBooleanRef i;
  i = (kCFBooleanTrue);
  o = _cffi_from_c_pointer((char *)i, _cffi_type(1));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kCFBooleanTrue", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_const_kCFBooleanFalse(lib);
}

static int _cffi_const_kCFTypeDictionaryKeyCallBacks(PyObject *lib)
{
  PyObject *o;
  int res;
  CFDictionaryKeyCallBacks i;
  i = (kCFTypeDictionaryKeyCallBacks);
  o = _cffi_from_c_struct((char *)&i, _cffi_type(2));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kCFTypeDictionaryKeyCallBacks", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_const_kCFBooleanTrue(lib);
}

static int _cffi_const_kCFTypeDictionaryValueCallBacks(PyObject *lib)
{
  PyObject *o;
  int res;
  CFDictionaryValueCallBacks i;
  i = (kCFTypeDictionaryValueCallBacks);
  o = _cffi_from_c_struct((char *)&i, _cffi_type(3));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kCFTypeDictionaryValueCallBacks", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_const_kCFTypeDictionaryKeyCallBacks(lib);
}

static int _cffi_const_kSecAttrIsPermanent(PyObject *lib)
{
  PyObject *o;
  int res;
  CFTypeRef i;
  i = (kSecAttrIsPermanent);
  o = _cffi_from_c_pointer((char *)i, _cffi_type(4));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kSecAttrIsPermanent", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_const_kCFTypeDictionaryValueCallBacks(lib);
}

static int _cffi_const_kSecAttrKeySizeInBits(PyObject *lib)
{
  PyObject *o;
  int res;
  CFTypeRef i;
  i = (kSecAttrKeySizeInBits);
  o = _cffi_from_c_pointer((char *)i, _cffi_type(4));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kSecAttrKeySizeInBits", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_const_kSecAttrIsPermanent(lib);
}

static int _cffi_const_kSecAttrKeyType(PyObject *lib)
{
  PyObject *o;
  int res;
  CFTypeRef i;
  i = (kSecAttrKeyType);
  o = _cffi_from_c_pointer((char *)i, _cffi_type(4));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kSecAttrKeyType", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_const_kSecAttrKeySizeInBits(lib);
}

static int _cffi_const_kSecAttrKeyTypeDSA(PyObject *lib)
{
  PyObject *o;
  int res;
  CFTypeRef i;
  i = (kSecAttrKeyTypeDSA);
  o = _cffi_from_c_pointer((char *)i, _cffi_type(4));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kSecAttrKeyTypeDSA", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_const_kSecAttrKeyType(lib);
}

static int _cffi_const_kSecAttrKeyTypeRSA(PyObject *lib)
{
  PyObject *o;
  int res;
  CFTypeRef i;
  i = (kSecAttrKeyTypeRSA);
  o = _cffi_from_c_pointer((char *)i, _cffi_type(4));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kSecAttrKeyTypeRSA", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_const_kSecAttrKeyTypeDSA(lib);
}

static int _cffi_const_kSecDigestLengthAttribute(PyObject *lib)
{
  PyObject *o;
  int res;
  CFStringRef i;
  i = (kSecDigestLengthAttribute);
  o = _cffi_from_c_pointer((char *)i, _cffi_type(5));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kSecDigestLengthAttribute", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_const_kSecAttrKeyTypeRSA(lib);
}

static int _cffi_const_kSecDigestMD5(PyObject *lib)
{
  PyObject *o;
  int res;
  CFStringRef i;
  i = (kSecDigestMD5);
  o = _cffi_from_c_pointer((char *)i, _cffi_type(5));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kSecDigestMD5", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_const_kSecDigestLengthAttribute(lib);
}

static int _cffi_const_kSecDigestSHA1(PyObject *lib)
{
  PyObject *o;
  int res;
  CFStringRef i;
  i = (kSecDigestSHA1);
  o = _cffi_from_c_pointer((char *)i, _cffi_type(5));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kSecDigestSHA1", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_const_kSecDigestMD5(lib);
}

static int _cffi_const_kSecDigestSHA2(PyObject *lib)
{
  PyObject *o;
  int res;
  CFStringRef i;
  i = (kSecDigestSHA2);
  o = _cffi_from_c_pointer((char *)i, _cffi_type(5));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kSecDigestSHA2", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_const_kSecDigestSHA1(lib);
}

static int _cffi_const_kSecDigestTypeAttribute(PyObject *lib)
{
  PyObject *o;
  int res;
  CFStringRef i;
  i = (kSecDigestTypeAttribute);
  o = _cffi_from_c_pointer((char *)i, _cffi_type(5));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kSecDigestTypeAttribute", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_const_kSecDigestSHA2(lib);
}

static int _cffi_const_kSecTransformAbortAttributeName(PyObject *lib)
{
  PyObject *o;
  int res;
  CFStringRef i;
  i = (kSecTransformAbortAttributeName);
  o = _cffi_from_c_pointer((char *)i, _cffi_type(5));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kSecTransformAbortAttributeName", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_const_kSecDigestTypeAttribute(lib);
}

static int _cffi_const_kSecTransformDebugAttributeName(PyObject *lib)
{
  PyObject *o;
  int res;
  CFStringRef i;
  i = (kSecTransformDebugAttributeName);
  o = _cffi_from_c_pointer((char *)i, _cffi_type(5));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kSecTransformDebugAttributeName", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_const_kSecTransformAbortAttributeName(lib);
}

static int _cffi_const_kSecTransformInputAttributeName(PyObject *lib)
{
  PyObject *o;
  int res;
  CFStringRef i;
  i = (kSecTransformInputAttributeName);
  o = _cffi_from_c_pointer((char *)i, _cffi_type(5));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kSecTransformInputAttributeName", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_const_kSecTransformDebugAttributeName(lib);
}

static int _cffi_const_kSecTransformOutputAttributeName(PyObject *lib)
{
  PyObject *o;
  int res;
  CFStringRef i;
  i = (kSecTransformOutputAttributeName);
  o = _cffi_from_c_pointer((char *)i, _cffi_type(5));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kSecTransformOutputAttributeName", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_const_kSecTransformInputAttributeName(lib);
}

static int _cffi_const_kSecTransformTransformName(PyObject *lib)
{
  PyObject *o;
  int res;
  CFStringRef i;
  i = (kSecTransformTransformName);
  o = _cffi_from_c_pointer((char *)i, _cffi_type(5));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kSecTransformTransformName", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_const_kSecTransformOutputAttributeName(lib);
}

static int _cffi_const_kSecUseKeychain(PyObject *lib)
{
  PyObject *o;
  int res;
  CFTypeRef i;
  i = (kSecUseKeychain);
  o = _cffi_from_c_pointer((char *)i, _cffi_type(4));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kSecUseKeychain", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_const_kSecTransformTransformName(lib);
}

static PyObject *
_cffi_f_CCCalibratePBKDF(PyObject *self, PyObject *args)
{
  uint32_t x0;
  size_t x1;
  size_t x2;
  uint32_t x3;
  size_t x4;
  uint32_t x5;
  unsigned int result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;
  PyObject *arg3;
  PyObject *arg4;
  PyObject *arg5;

  if (!PyArg_ParseTuple(args, "OOOOOO:CCCalibratePBKDF", &arg0, &arg1, &arg2, &arg3, &arg4, &arg5))
    return NULL;

  x0 = _cffi_to_c_int(arg0, uint32_t);
  if (x0 == (uint32_t)-1 && PyErr_Occurred())
    return NULL;

  x1 = _cffi_to_c_int(arg1, size_t);
  if (x1 == (size_t)-1 && PyErr_Occurred())
    return NULL;

  x2 = _cffi_to_c_int(arg2, size_t);
  if (x2 == (size_t)-1 && PyErr_Occurred())
    return NULL;

  x3 = _cffi_to_c_int(arg3, uint32_t);
  if (x3 == (uint32_t)-1 && PyErr_Occurred())
    return NULL;

  x4 = _cffi_to_c_int(arg4, size_t);
  if (x4 == (size_t)-1 && PyErr_Occurred())
    return NULL;

  x5 = _cffi_to_c_int(arg5, uint32_t);
  if (x5 == (uint32_t)-1 && PyErr_Occurred())
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CCCalibratePBKDF(x0, x1, x2, x3, x4, x5); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_int(result, unsigned int);
}

static PyObject *
_cffi_f_CCCryptorCreate(PyObject *self, PyObject *args)
{
  uint32_t x0;
  uint32_t x1;
  uint32_t x2;
  void const * x3;
  size_t x4;
  void const * x5;
  CCCryptorRef * x6;
  Py_ssize_t datasize;
  int32_t result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;
  PyObject *arg3;
  PyObject *arg4;
  PyObject *arg5;
  PyObject *arg6;

  if (!PyArg_ParseTuple(args, "OOOOOOO:CCCryptorCreate", &arg0, &arg1, &arg2, &arg3, &arg4, &arg5, &arg6))
    return NULL;

  x0 = _cffi_to_c_int(arg0, uint32_t);
  if (x0 == (uint32_t)-1 && PyErr_Occurred())
    return NULL;

  x1 = _cffi_to_c_int(arg1, uint32_t);
  if (x1 == (uint32_t)-1 && PyErr_Occurred())
    return NULL;

  x2 = _cffi_to_c_int(arg2, uint32_t);
  if (x2 == (uint32_t)-1 && PyErr_Occurred())
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(0), arg3, (char **)&x3);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x3 = alloca(datasize);
    memset((void *)x3, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x3, _cffi_type(0), arg3) < 0)
      return NULL;
  }

  x4 = _cffi_to_c_int(arg4, size_t);
  if (x4 == (size_t)-1 && PyErr_Occurred())
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(0), arg5, (char **)&x5);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x5 = alloca(datasize);
    memset((void *)x5, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x5, _cffi_type(0), arg5) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(6), arg6, (char **)&x6);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x6 = alloca(datasize);
    memset((void *)x6, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x6, _cffi_type(6), arg6) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CCCryptorCreate(x0, x1, x2, x3, x4, x5, x6); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_int(result, int32_t);
}

static PyObject *
_cffi_f_CCCryptorCreateWithMode(PyObject *self, PyObject *args)
{
  uint32_t x0;
  uint32_t x1;
  uint32_t x2;
  uint32_t x3;
  void const * x4;
  void const * x5;
  size_t x6;
  void const * x7;
  size_t x8;
  int x9;
  uint32_t x10;
  CCCryptorRef * x11;
  Py_ssize_t datasize;
  int32_t result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;
  PyObject *arg3;
  PyObject *arg4;
  PyObject *arg5;
  PyObject *arg6;
  PyObject *arg7;
  PyObject *arg8;
  PyObject *arg9;
  PyObject *arg10;
  PyObject *arg11;

  if (!PyArg_ParseTuple(args, "OOOOOOOOOOOO:CCCryptorCreateWithMode", &arg0, &arg1, &arg2, &arg3, &arg4, &arg5, &arg6, &arg7, &arg8, &arg9, &arg10, &arg11))
    return NULL;

  x0 = _cffi_to_c_int(arg0, uint32_t);
  if (x0 == (uint32_t)-1 && PyErr_Occurred())
    return NULL;

  x1 = _cffi_to_c_int(arg1, uint32_t);
  if (x1 == (uint32_t)-1 && PyErr_Occurred())
    return NULL;

  x2 = _cffi_to_c_int(arg2, uint32_t);
  if (x2 == (uint32_t)-1 && PyErr_Occurred())
    return NULL;

  x3 = _cffi_to_c_int(arg3, uint32_t);
  if (x3 == (uint32_t)-1 && PyErr_Occurred())
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(0), arg4, (char **)&x4);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x4 = alloca(datasize);
    memset((void *)x4, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x4, _cffi_type(0), arg4) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(0), arg5, (char **)&x5);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x5 = alloca(datasize);
    memset((void *)x5, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x5, _cffi_type(0), arg5) < 0)
      return NULL;
  }

  x6 = _cffi_to_c_int(arg6, size_t);
  if (x6 == (size_t)-1 && PyErr_Occurred())
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(0), arg7, (char **)&x7);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x7 = alloca(datasize);
    memset((void *)x7, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x7, _cffi_type(0), arg7) < 0)
      return NULL;
  }

  x8 = _cffi_to_c_int(arg8, size_t);
  if (x8 == (size_t)-1 && PyErr_Occurred())
    return NULL;

  x9 = _cffi_to_c_int(arg9, int);
  if (x9 == (int)-1 && PyErr_Occurred())
    return NULL;

  x10 = _cffi_to_c_int(arg10, uint32_t);
  if (x10 == (uint32_t)-1 && PyErr_Occurred())
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(6), arg11, (char **)&x11);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x11 = alloca(datasize);
    memset((void *)x11, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x11, _cffi_type(6), arg11) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CCCryptorCreateWithMode(x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_int(result, int32_t);
}

static PyObject *
_cffi_f_CCCryptorFinal(PyObject *self, PyObject *args)
{
  CCCryptorRef x0;
  void * x1;
  size_t x2;
  size_t * x3;
  Py_ssize_t datasize;
  int32_t result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;
  PyObject *arg3;

  if (!PyArg_ParseTuple(args, "OOOO:CCCryptorFinal", &arg0, &arg1, &arg2, &arg3))
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(7), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(7), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(8), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = alloca(datasize);
    memset((void *)x1, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(8), arg1) < 0)
      return NULL;
  }

  x2 = _cffi_to_c_int(arg2, size_t);
  if (x2 == (size_t)-1 && PyErr_Occurred())
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(9), arg3, (char **)&x3);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x3 = alloca(datasize);
    memset((void *)x3, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x3, _cffi_type(9), arg3) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CCCryptorFinal(x0, x1, x2, x3); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_int(result, int32_t);
}

static PyObject *
_cffi_f_CCCryptorGCMAddAAD(PyObject *self, PyObject *args)
{
  CCCryptorRef x0;
  void const * x1;
  size_t x2;
  Py_ssize_t datasize;
  int32_t result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;

  if (!PyArg_ParseTuple(args, "OOO:CCCryptorGCMAddAAD", &arg0, &arg1, &arg2))
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(7), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(7), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(0), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = alloca(datasize);
    memset((void *)x1, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(0), arg1) < 0)
      return NULL;
  }

  x2 = _cffi_to_c_int(arg2, size_t);
  if (x2 == (size_t)-1 && PyErr_Occurred())
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CCCryptorGCMAddAAD(x0, x1, x2); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_int(result, int32_t);
}

static PyObject *
_cffi_f_CCCryptorGCMAddIV(PyObject *self, PyObject *args)
{
  CCCryptorRef x0;
  void const * x1;
  size_t x2;
  Py_ssize_t datasize;
  int32_t result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;

  if (!PyArg_ParseTuple(args, "OOO:CCCryptorGCMAddIV", &arg0, &arg1, &arg2))
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(7), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(7), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(0), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = alloca(datasize);
    memset((void *)x1, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(0), arg1) < 0)
      return NULL;
  }

  x2 = _cffi_to_c_int(arg2, size_t);
  if (x2 == (size_t)-1 && PyErr_Occurred())
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CCCryptorGCMAddIV(x0, x1, x2); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_int(result, int32_t);
}

static PyObject *
_cffi_f_CCCryptorGCMDecrypt(PyObject *self, PyObject *args)
{
  CCCryptorRef x0;
  void const * x1;
  size_t x2;
  void * x3;
  Py_ssize_t datasize;
  int32_t result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;
  PyObject *arg3;

  if (!PyArg_ParseTuple(args, "OOOO:CCCryptorGCMDecrypt", &arg0, &arg1, &arg2, &arg3))
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(7), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(7), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(0), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = alloca(datasize);
    memset((void *)x1, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(0), arg1) < 0)
      return NULL;
  }

  x2 = _cffi_to_c_int(arg2, size_t);
  if (x2 == (size_t)-1 && PyErr_Occurred())
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(8), arg3, (char **)&x3);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x3 = alloca(datasize);
    memset((void *)x3, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x3, _cffi_type(8), arg3) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CCCryptorGCMDecrypt(x0, x1, x2, x3); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_int(result, int32_t);
}

static PyObject *
_cffi_f_CCCryptorGCMEncrypt(PyObject *self, PyObject *args)
{
  CCCryptorRef x0;
  void const * x1;
  size_t x2;
  void * x3;
  Py_ssize_t datasize;
  int32_t result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;
  PyObject *arg3;

  if (!PyArg_ParseTuple(args, "OOOO:CCCryptorGCMEncrypt", &arg0, &arg1, &arg2, &arg3))
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(7), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(7), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(0), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = alloca(datasize);
    memset((void *)x1, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(0), arg1) < 0)
      return NULL;
  }

  x2 = _cffi_to_c_int(arg2, size_t);
  if (x2 == (size_t)-1 && PyErr_Occurred())
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(8), arg3, (char **)&x3);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x3 = alloca(datasize);
    memset((void *)x3, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x3, _cffi_type(8), arg3) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CCCryptorGCMEncrypt(x0, x1, x2, x3); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_int(result, int32_t);
}

static PyObject *
_cffi_f_CCCryptorGCMFinal(PyObject *self, PyObject *args)
{
  CCCryptorRef x0;
  void const * x1;
  size_t * x2;
  Py_ssize_t datasize;
  int32_t result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;

  if (!PyArg_ParseTuple(args, "OOO:CCCryptorGCMFinal", &arg0, &arg1, &arg2))
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(7), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(7), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(0), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = alloca(datasize);
    memset((void *)x1, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(0), arg1) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(9), arg2, (char **)&x2);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x2 = alloca(datasize);
    memset((void *)x2, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x2, _cffi_type(9), arg2) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CCCryptorGCMFinal(x0, x1, x2); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_int(result, int32_t);
}

static PyObject *
_cffi_f_CCCryptorGCMReset(PyObject *self, PyObject *arg0)
{
  CCCryptorRef x0;
  Py_ssize_t datasize;
  int32_t result;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(7), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(7), arg0) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CCCryptorGCMReset(x0); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_int(result, int32_t);
}

static PyObject *
_cffi_f_CCCryptorRelease(PyObject *self, PyObject *arg0)
{
  CCCryptorRef x0;
  Py_ssize_t datasize;
  int32_t result;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(7), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(7), arg0) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CCCryptorRelease(x0); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_int(result, int32_t);
}

static PyObject *
_cffi_f_CCCryptorUpdate(PyObject *self, PyObject *args)
{
  CCCryptorRef x0;
  void const * x1;
  size_t x2;
  void * x3;
  size_t x4;
  size_t * x5;
  Py_ssize_t datasize;
  int32_t result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;
  PyObject *arg3;
  PyObject *arg4;
  PyObject *arg5;

  if (!PyArg_ParseTuple(args, "OOOOOO:CCCryptorUpdate", &arg0, &arg1, &arg2, &arg3, &arg4, &arg5))
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(7), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(7), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(0), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = alloca(datasize);
    memset((void *)x1, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(0), arg1) < 0)
      return NULL;
  }

  x2 = _cffi_to_c_int(arg2, size_t);
  if (x2 == (size_t)-1 && PyErr_Occurred())
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(8), arg3, (char **)&x3);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x3 = alloca(datasize);
    memset((void *)x3, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x3, _cffi_type(8), arg3) < 0)
      return NULL;
  }

  x4 = _cffi_to_c_int(arg4, size_t);
  if (x4 == (size_t)-1 && PyErr_Occurred())
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(9), arg5, (char **)&x5);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x5 = alloca(datasize);
    memset((void *)x5, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x5, _cffi_type(9), arg5) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CCCryptorUpdate(x0, x1, x2, x3, x4, x5); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_int(result, int32_t);
}

static PyObject *
_cffi_f_CCHmacFinal(PyObject *self, PyObject *args)
{
  CCHmacContext * x0;
  void * x1;
  Py_ssize_t datasize;
  PyObject *arg0;
  PyObject *arg1;

  if (!PyArg_ParseTuple(args, "OO:CCHmacFinal", &arg0, &arg1))
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(10), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(10), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(8), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = alloca(datasize);
    memset((void *)x1, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(8), arg1) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { CCHmacFinal(x0, x1); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject *
_cffi_f_CCHmacInit(PyObject *self, PyObject *args)
{
  CCHmacContext * x0;
  uint32_t x1;
  void const * x2;
  size_t x3;
  Py_ssize_t datasize;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;
  PyObject *arg3;

  if (!PyArg_ParseTuple(args, "OOOO:CCHmacInit", &arg0, &arg1, &arg2, &arg3))
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(10), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(10), arg0) < 0)
      return NULL;
  }

  x1 = _cffi_to_c_int(arg1, uint32_t);
  if (x1 == (uint32_t)-1 && PyErr_Occurred())
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(0), arg2, (char **)&x2);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x2 = alloca(datasize);
    memset((void *)x2, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x2, _cffi_type(0), arg2) < 0)
      return NULL;
  }

  x3 = _cffi_to_c_int(arg3, size_t);
  if (x3 == (size_t)-1 && PyErr_Occurred())
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { CCHmacInit(x0, x1, x2, x3); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject *
_cffi_f_CCHmacUpdate(PyObject *self, PyObject *args)
{
  CCHmacContext * x0;
  void const * x1;
  size_t x2;
  Py_ssize_t datasize;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;

  if (!PyArg_ParseTuple(args, "OOO:CCHmacUpdate", &arg0, &arg1, &arg2))
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(10), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(10), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(0), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = alloca(datasize);
    memset((void *)x1, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(0), arg1) < 0)
      return NULL;
  }

  x2 = _cffi_to_c_int(arg2, size_t);
  if (x2 == (size_t)-1 && PyErr_Occurred())
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { CCHmacUpdate(x0, x1, x2); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject *
_cffi_f_CCKeyDerivationPBKDF(PyObject *self, PyObject *args)
{
  uint32_t x0;
  char const * x1;
  size_t x2;
  uint8_t const * x3;
  size_t x4;
  uint32_t x5;
  unsigned int x6;
  uint8_t * x7;
  size_t x8;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;
  PyObject *arg3;
  PyObject *arg4;
  PyObject *arg5;
  PyObject *arg6;
  PyObject *arg7;
  PyObject *arg8;

  if (!PyArg_ParseTuple(args, "OOOOOOOOO:CCKeyDerivationPBKDF", &arg0, &arg1, &arg2, &arg3, &arg4, &arg5, &arg6, &arg7, &arg8))
    return NULL;

  x0 = _cffi_to_c_int(arg0, uint32_t);
  if (x0 == (uint32_t)-1 && PyErr_Occurred())
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(12), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = alloca(datasize);
    memset((void *)x1, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(12), arg1) < 0)
      return NULL;
  }

  x2 = _cffi_to_c_int(arg2, size_t);
  if (x2 == (size_t)-1 && PyErr_Occurred())
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(13), arg3, (char **)&x3);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x3 = alloca(datasize);
    memset((void *)x3, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x3, _cffi_type(13), arg3) < 0)
      return NULL;
  }

  x4 = _cffi_to_c_int(arg4, size_t);
  if (x4 == (size_t)-1 && PyErr_Occurred())
    return NULL;

  x5 = _cffi_to_c_int(arg5, uint32_t);
  if (x5 == (uint32_t)-1 && PyErr_Occurred())
    return NULL;

  x6 = _cffi_to_c_int(arg6, unsigned int);
  if (x6 == (unsigned int)-1 && PyErr_Occurred())
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(14), arg7, (char **)&x7);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x7 = alloca(datasize);
    memset((void *)x7, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x7, _cffi_type(14), arg7) < 0)
      return NULL;
  }

  x8 = _cffi_to_c_int(arg8, size_t);
  if (x8 == (size_t)-1 && PyErr_Occurred())
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CCKeyDerivationPBKDF(x0, x1, x2, x3, x4, x5, x6, x7, x8); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_int(result, int);
}

static PyObject *
_cffi_f_CC_MD5_Final(PyObject *self, PyObject *args)
{
  unsigned char * x0;
  CC_MD5_CTX * x1;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;

  if (!PyArg_ParseTuple(args, "OO:CC_MD5_Final", &arg0, &arg1))
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(15), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(15), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(16), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = alloca(datasize);
    memset((void *)x1, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(16), arg1) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CC_MD5_Final(x0, x1); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_int(result, int);
}

static PyObject *
_cffi_f_CC_MD5_Init(PyObject *self, PyObject *arg0)
{
  CC_MD5_CTX * x0;
  Py_ssize_t datasize;
  int result;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(16), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(16), arg0) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CC_MD5_Init(x0); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_int(result, int);
}

static PyObject *
_cffi_f_CC_MD5_Update(PyObject *self, PyObject *args)
{
  CC_MD5_CTX * x0;
  void const * x1;
  uint32_t x2;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;

  if (!PyArg_ParseTuple(args, "OOO:CC_MD5_Update", &arg0, &arg1, &arg2))
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(16), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(16), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(0), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = alloca(datasize);
    memset((void *)x1, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(0), arg1) < 0)
      return NULL;
  }

  x2 = _cffi_to_c_int(arg2, uint32_t);
  if (x2 == (uint32_t)-1 && PyErr_Occurred())
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CC_MD5_Update(x0, x1, x2); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_int(result, int);
}

static PyObject *
_cffi_f_CC_SHA1_Final(PyObject *self, PyObject *args)
{
  unsigned char * x0;
  CC_SHA1_CTX * x1;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;

  if (!PyArg_ParseTuple(args, "OO:CC_SHA1_Final", &arg0, &arg1))
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(15), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(15), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(17), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = alloca(datasize);
    memset((void *)x1, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(17), arg1) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CC_SHA1_Final(x0, x1); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_int(result, int);
}

static PyObject *
_cffi_f_CC_SHA1_Init(PyObject *self, PyObject *arg0)
{
  CC_SHA1_CTX * x0;
  Py_ssize_t datasize;
  int result;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(17), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(17), arg0) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CC_SHA1_Init(x0); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_int(result, int);
}

static PyObject *
_cffi_f_CC_SHA1_Update(PyObject *self, PyObject *args)
{
  CC_SHA1_CTX * x0;
  void const * x1;
  uint32_t x2;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;

  if (!PyArg_ParseTuple(args, "OOO:CC_SHA1_Update", &arg0, &arg1, &arg2))
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(17), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(17), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(0), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = alloca(datasize);
    memset((void *)x1, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(0), arg1) < 0)
      return NULL;
  }

  x2 = _cffi_to_c_int(arg2, uint32_t);
  if (x2 == (uint32_t)-1 && PyErr_Occurred())
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CC_SHA1_Update(x0, x1, x2); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_int(result, int);
}

static PyObject *
_cffi_f_CC_SHA224_Final(PyObject *self, PyObject *args)
{
  unsigned char * x0;
  CC_SHA256_CTX * x1;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;

  if (!PyArg_ParseTuple(args, "OO:CC_SHA224_Final", &arg0, &arg1))
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(15), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(15), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(18), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = alloca(datasize);
    memset((void *)x1, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(18), arg1) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CC_SHA224_Final(x0, x1); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_int(result, int);
}

static PyObject *
_cffi_f_CC_SHA224_Init(PyObject *self, PyObject *arg0)
{
  CC_SHA256_CTX * x0;
  Py_ssize_t datasize;
  int result;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(18), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(18), arg0) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CC_SHA224_Init(x0); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_int(result, int);
}

static PyObject *
_cffi_f_CC_SHA224_Update(PyObject *self, PyObject *args)
{
  CC_SHA256_CTX * x0;
  void const * x1;
  uint32_t x2;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;

  if (!PyArg_ParseTuple(args, "OOO:CC_SHA224_Update", &arg0, &arg1, &arg2))
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(18), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(18), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(0), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = alloca(datasize);
    memset((void *)x1, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(0), arg1) < 0)
      return NULL;
  }

  x2 = _cffi_to_c_int(arg2, uint32_t);
  if (x2 == (uint32_t)-1 && PyErr_Occurred())
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CC_SHA224_Update(x0, x1, x2); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_int(result, int);
}

static PyObject *
_cffi_f_CC_SHA256_Final(PyObject *self, PyObject *args)
{
  unsigned char * x0;
  CC_SHA256_CTX * x1;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;

  if (!PyArg_ParseTuple(args, "OO:CC_SHA256_Final", &arg0, &arg1))
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(15), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(15), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(18), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = alloca(datasize);
    memset((void *)x1, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(18), arg1) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CC_SHA256_Final(x0, x1); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_int(result, int);
}

static PyObject *
_cffi_f_CC_SHA256_Init(PyObject *self, PyObject *arg0)
{
  CC_SHA256_CTX * x0;
  Py_ssize_t datasize;
  int result;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(18), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(18), arg0) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CC_SHA256_Init(x0); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_int(result, int);
}

static PyObject *
_cffi_f_CC_SHA256_Update(PyObject *self, PyObject *args)
{
  CC_SHA256_CTX * x0;
  void const * x1;
  uint32_t x2;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;

  if (!PyArg_ParseTuple(args, "OOO:CC_SHA256_Update", &arg0, &arg1, &arg2))
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(18), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(18), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(0), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = alloca(datasize);
    memset((void *)x1, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(0), arg1) < 0)
      return NULL;
  }

  x2 = _cffi_to_c_int(arg2, uint32_t);
  if (x2 == (uint32_t)-1 && PyErr_Occurred())
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CC_SHA256_Update(x0, x1, x2); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_int(result, int);
}

static PyObject *
_cffi_f_CC_SHA384_Final(PyObject *self, PyObject *args)
{
  unsigned char * x0;
  CC_SHA512_CTX * x1;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;

  if (!PyArg_ParseTuple(args, "OO:CC_SHA384_Final", &arg0, &arg1))
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(15), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(15), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(19), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = alloca(datasize);
    memset((void *)x1, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(19), arg1) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CC_SHA384_Final(x0, x1); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_int(result, int);
}

static PyObject *
_cffi_f_CC_SHA384_Init(PyObject *self, PyObject *arg0)
{
  CC_SHA512_CTX * x0;
  Py_ssize_t datasize;
  int result;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(19), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(19), arg0) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CC_SHA384_Init(x0); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_int(result, int);
}

static PyObject *
_cffi_f_CC_SHA384_Update(PyObject *self, PyObject *args)
{
  CC_SHA512_CTX * x0;
  void const * x1;
  uint32_t x2;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;

  if (!PyArg_ParseTuple(args, "OOO:CC_SHA384_Update", &arg0, &arg1, &arg2))
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(19), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(19), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(0), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = alloca(datasize);
    memset((void *)x1, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(0), arg1) < 0)
      return NULL;
  }

  x2 = _cffi_to_c_int(arg2, uint32_t);
  if (x2 == (uint32_t)-1 && PyErr_Occurred())
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CC_SHA384_Update(x0, x1, x2); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_int(result, int);
}

static PyObject *
_cffi_f_CC_SHA512_Final(PyObject *self, PyObject *args)
{
  unsigned char * x0;
  CC_SHA512_CTX * x1;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;

  if (!PyArg_ParseTuple(args, "OO:CC_SHA512_Final", &arg0, &arg1))
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(15), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(15), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(19), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = alloca(datasize);
    memset((void *)x1, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(19), arg1) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CC_SHA512_Final(x0, x1); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_int(result, int);
}

static PyObject *
_cffi_f_CC_SHA512_Init(PyObject *self, PyObject *arg0)
{
  CC_SHA512_CTX * x0;
  Py_ssize_t datasize;
  int result;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(19), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(19), arg0) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CC_SHA512_Init(x0); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_int(result, int);
}

static PyObject *
_cffi_f_CC_SHA512_Update(PyObject *self, PyObject *args)
{
  CC_SHA512_CTX * x0;
  void const * x1;
  uint32_t x2;
  Py_ssize_t datasize;
  int result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;

  if (!PyArg_ParseTuple(args, "OOO:CC_SHA512_Update", &arg0, &arg1, &arg2))
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(19), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(19), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(0), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = alloca(datasize);
    memset((void *)x1, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(0), arg1) < 0)
      return NULL;
  }

  x2 = _cffi_to_c_int(arg2, uint32_t);
  if (x2 == (uint32_t)-1 && PyErr_Occurred())
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CC_SHA512_Update(x0, x1, x2); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_int(result, int);
}

static PyObject *
_cffi_f_CFArrayGetCount(PyObject *self, PyObject *arg0)
{
  CFArrayRef x0;
  Py_ssize_t datasize;
  long long result;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(20), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(20), arg0) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CFArrayGetCount(x0); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_int(result, long long);
}

static PyObject *
_cffi_f_CFArrayGetValueAtIndex(PyObject *self, PyObject *args)
{
  CFArrayRef x0;
  long long x1;
  Py_ssize_t datasize;
  void const * result;
  PyObject *arg0;
  PyObject *arg1;

  if (!PyArg_ParseTuple(args, "OO:CFArrayGetValueAtIndex", &arg0, &arg1))
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(20), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(20), arg0) < 0)
      return NULL;
  }

  x1 = _cffi_to_c_int(arg1, long long);
  if (x1 == (long long)-1 && PyErr_Occurred())
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CFArrayGetValueAtIndex(x0, x1); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_pointer((char *)result, _cffi_type(0));
}

static PyObject *
_cffi_f_CFBooleanGetValue(PyObject *self, PyObject *arg0)
{
  CFBooleanRef x0;
  Py_ssize_t datasize;
  _Bool result;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(1), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(1), arg0) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CFBooleanGetValue(x0); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_int(result, _Bool);
}

static PyObject *
_cffi_f_CFDataCreate(PyObject *self, PyObject *args)
{
  void const * x0;
  unsigned char const * x1;
  long long x2;
  Py_ssize_t datasize;
  void const * result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;

  if (!PyArg_ParseTuple(args, "OOO:CFDataCreate", &arg0, &arg1, &arg2))
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(0), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(0), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(21), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = alloca(datasize);
    memset((void *)x1, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(21), arg1) < 0)
      return NULL;
  }

  x2 = _cffi_to_c_int(arg2, long long);
  if (x2 == (long long)-1 && PyErr_Occurred())
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CFDataCreate(x0, x1, x2); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_pointer((char *)result, _cffi_type(0));
}

static PyObject *
_cffi_f_CFDataGetBytes(PyObject *self, PyObject *args)
{
  void const * x0;
  CFRange x1;
  unsigned char * x2;
  Py_ssize_t datasize;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;

  if (!PyArg_ParseTuple(args, "OOO:CFDataGetBytes", &arg0, &arg1, &arg2))
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(0), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(0), arg0) < 0)
      return NULL;
  }

  if (_cffi_to_c((char *)&x1, _cffi_type(22), arg1) < 0)
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(15), arg2, (char **)&x2);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x2 = alloca(datasize);
    memset((void *)x2, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x2, _cffi_type(15), arg2) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { CFDataGetBytes(x0, x1, x2); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject *
_cffi_f_CFDataGetLength(PyObject *self, PyObject *arg0)
{
  void const * x0;
  Py_ssize_t datasize;
  long long result;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(0), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(0), arg0) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CFDataGetLength(x0); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_int(result, long long);
}

static PyObject *
_cffi_f_CFDictionaryCreate(PyObject *self, PyObject *args)
{
  void const * x0;
  void const * * x1;
  void const * * x2;
  long long x3;
  CFDictionaryKeyCallBacks const * x4;
  CFDictionaryValueCallBacks const * x5;
  Py_ssize_t datasize;
  CFDictionaryRef result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;
  PyObject *arg3;
  PyObject *arg4;
  PyObject *arg5;

  if (!PyArg_ParseTuple(args, "OOOOOO:CFDictionaryCreate", &arg0, &arg1, &arg2, &arg3, &arg4, &arg5))
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(0), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(0), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(23), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = alloca(datasize);
    memset((void *)x1, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(23), arg1) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(23), arg2, (char **)&x2);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x2 = alloca(datasize);
    memset((void *)x2, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x2, _cffi_type(23), arg2) < 0)
      return NULL;
  }

  x3 = _cffi_to_c_int(arg3, long long);
  if (x3 == (long long)-1 && PyErr_Occurred())
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(24), arg4, (char **)&x4);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x4 = alloca(datasize);
    memset((void *)x4, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x4, _cffi_type(24), arg4) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(25), arg5, (char **)&x5);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x5 = alloca(datasize);
    memset((void *)x5, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x5, _cffi_type(25), arg5) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CFDictionaryCreate(x0, x1, x2, x3, x4, x5); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_pointer((char *)result, _cffi_type(26));
}

static PyObject *
_cffi_f_CFDictionaryCreateMutable(PyObject *self, PyObject *args)
{
  void const * x0;
  long long x1;
  CFDictionaryKeyCallBacks const * x2;
  CFDictionaryValueCallBacks const * x3;
  Py_ssize_t datasize;
  CFMutableDictionaryRef result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;
  PyObject *arg3;

  if (!PyArg_ParseTuple(args, "OOOO:CFDictionaryCreateMutable", &arg0, &arg1, &arg2, &arg3))
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(0), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(0), arg0) < 0)
      return NULL;
  }

  x1 = _cffi_to_c_int(arg1, long long);
  if (x1 == (long long)-1 && PyErr_Occurred())
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(24), arg2, (char **)&x2);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x2 = alloca(datasize);
    memset((void *)x2, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x2, _cffi_type(24), arg2) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(25), arg3, (char **)&x3);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x3 = alloca(datasize);
    memset((void *)x3, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x3, _cffi_type(25), arg3) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CFDictionaryCreateMutable(x0, x1, x2, x3); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_pointer((char *)result, _cffi_type(27));
}

static PyObject *
_cffi_f_CFDictionarySetValue(PyObject *self, PyObject *args)
{
  CFMutableDictionaryRef x0;
  void const * x1;
  void const * x2;
  Py_ssize_t datasize;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;

  if (!PyArg_ParseTuple(args, "OOO:CFDictionarySetValue", &arg0, &arg1, &arg2))
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(27), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(27), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(0), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = alloca(datasize);
    memset((void *)x1, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(0), arg1) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(0), arg2, (char **)&x2);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x2 = alloca(datasize);
    memset((void *)x2, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x2, _cffi_type(0), arg2) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { CFDictionarySetValue(x0, x1, x2); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject *
_cffi_f_CFNumberCreate(PyObject *self, PyObject *args)
{
  void const * x0;
  int x1;
  void const * x2;
  Py_ssize_t datasize;
  CFNumberRef result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;

  if (!PyArg_ParseTuple(args, "OOO:CFNumberCreate", &arg0, &arg1, &arg2))
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(0), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(0), arg0) < 0)
      return NULL;
  }

  x1 = _cffi_to_c_int(arg1, int);
  if (x1 == (int)-1 && PyErr_Occurred())
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(0), arg2, (char **)&x2);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x2 = alloca(datasize);
    memset((void *)x2, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x2, _cffi_type(0), arg2) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CFNumberCreate(x0, x1, x2); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_pointer((char *)result, _cffi_type(28));
}

static PyObject *
_cffi_f_CFRangeMake(PyObject *self, PyObject *args)
{
  long long x0;
  long long x1;
  CFRange result;
  PyObject *arg0;
  PyObject *arg1;

  if (!PyArg_ParseTuple(args, "OO:CFRangeMake", &arg0, &arg1))
    return NULL;

  x0 = _cffi_to_c_int(arg0, long long);
  if (x0 == (long long)-1 && PyErr_Occurred())
    return NULL;

  x1 = _cffi_to_c_int(arg1, long long);
  if (x1 == (long long)-1 && PyErr_Occurred())
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CFRangeMake(x0, x1); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_struct((char *)&result, _cffi_type(22));
}

static PyObject *
_cffi_f_CFRelease(PyObject *self, PyObject *arg0)
{
  CFTypeRef x0;
  Py_ssize_t datasize;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(4), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(4), arg0) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { CFRelease(x0); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject *
_cffi_f_CFRetain(PyObject *self, PyObject *arg0)
{
  CFTypeRef x0;
  Py_ssize_t datasize;
  CFTypeRef result;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(4), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(4), arg0) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CFRetain(x0); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_pointer((char *)result, _cffi_type(4));
}

static PyObject *
_cffi_f_CFShow(PyObject *self, PyObject *arg0)
{
  CFTypeRef x0;
  Py_ssize_t datasize;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(4), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(4), arg0) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { CFShow(x0); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject *
_cffi_f_CFStringCreateWithCString(PyObject *self, PyObject *args)
{
  void const * x0;
  char const * x1;
  uint32_t x2;
  Py_ssize_t datasize;
  CFStringRef result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;

  if (!PyArg_ParseTuple(args, "OOO:CFStringCreateWithCString", &arg0, &arg1, &arg2))
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(0), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(0), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(12), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = alloca(datasize);
    memset((void *)x1, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(12), arg1) < 0)
      return NULL;
  }

  x2 = _cffi_to_c_int(arg2, uint32_t);
  if (x2 == (uint32_t)-1 && PyErr_Occurred())
    return NULL;

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = CFStringCreateWithCString(x0, x1, x2); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_pointer((char *)result, _cffi_type(5));
}

static PyObject *
_cffi_f_SecDecryptTransformCreate(PyObject *self, PyObject *args)
{
  SecKeyRef x0;
  CFErrorRef * x1;
  Py_ssize_t datasize;
  SecTransformRef result;
  PyObject *arg0;
  PyObject *arg1;

  if (!PyArg_ParseTuple(args, "OO:SecDecryptTransformCreate", &arg0, &arg1))
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(29), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(29), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(30), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = alloca(datasize);
    memset((void *)x1, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(30), arg1) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = SecDecryptTransformCreate(x0, x1); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_pointer((char *)result, _cffi_type(31));
}

static PyObject *
_cffi_f_SecEncryptTransformCreate(PyObject *self, PyObject *args)
{
  SecKeyRef x0;
  CFErrorRef * x1;
  Py_ssize_t datasize;
  SecTransformRef result;
  PyObject *arg0;
  PyObject *arg1;

  if (!PyArg_ParseTuple(args, "OO:SecEncryptTransformCreate", &arg0, &arg1))
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(29), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(29), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(30), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = alloca(datasize);
    memset((void *)x1, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(30), arg1) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = SecEncryptTransformCreate(x0, x1); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_pointer((char *)result, _cffi_type(31));
}

static PyObject *
_cffi_f_SecItemImport(PyObject *self, PyObject *args)
{
  void const * x0;
  CFStringRef x1;
  uint32_t * x2;
  uint32_t * x3;
  uint32_t x4;
  SecItemImportExportKeyParameters const * x5;
  SecKeychainRef x6;
  CFArrayRef * x7;
  Py_ssize_t datasize;
  long result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;
  PyObject *arg3;
  PyObject *arg4;
  PyObject *arg5;
  PyObject *arg6;
  PyObject *arg7;

  if (!PyArg_ParseTuple(args, "OOOOOOOO:SecItemImport", &arg0, &arg1, &arg2, &arg3, &arg4, &arg5, &arg6, &arg7))
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(0), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(0), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(5), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = alloca(datasize);
    memset((void *)x1, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(5), arg1) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(32), arg2, (char **)&x2);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x2 = alloca(datasize);
    memset((void *)x2, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x2, _cffi_type(32), arg2) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(32), arg3, (char **)&x3);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x3 = alloca(datasize);
    memset((void *)x3, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x3, _cffi_type(32), arg3) < 0)
      return NULL;
  }

  x4 = _cffi_to_c_int(arg4, uint32_t);
  if (x4 == (uint32_t)-1 && PyErr_Occurred())
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(33), arg5, (char **)&x5);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x5 = alloca(datasize);
    memset((void *)x5, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x5, _cffi_type(33), arg5) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(34), arg6, (char **)&x6);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x6 = alloca(datasize);
    memset((void *)x6, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x6, _cffi_type(34), arg6) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(35), arg7, (char **)&x7);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x7 = alloca(datasize);
    memset((void *)x7, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x7, _cffi_type(35), arg7) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = SecItemImport(x0, x1, x2, x3, x4, x5, x6, x7); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_int(result, long);
}

static PyObject *
_cffi_f_SecKeyGeneratePair(PyObject *self, PyObject *args)
{
  CFDictionaryRef x0;
  SecKeyRef * x1;
  SecKeyRef * x2;
  Py_ssize_t datasize;
  long result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;

  if (!PyArg_ParseTuple(args, "OOO:SecKeyGeneratePair", &arg0, &arg1, &arg2))
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(26), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(26), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(36), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = alloca(datasize);
    memset((void *)x1, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(36), arg1) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(36), arg2, (char **)&x2);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x2 = alloca(datasize);
    memset((void *)x2, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x2, _cffi_type(36), arg2) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = SecKeyGeneratePair(x0, x1, x2); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_int(result, long);
}

static PyObject *
_cffi_f_SecKeyGetBlockSize(PyObject *self, PyObject *arg0)
{
  SecKeyRef x0;
  Py_ssize_t datasize;
  size_t result;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(29), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(29), arg0) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = SecKeyGetBlockSize(x0); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_int(result, size_t);
}

static PyObject *
_cffi_f_SecKeychainCreate(PyObject *self, PyObject *args)
{
  char const * x0;
  uint32_t x1;
  void const * x2;
  _Bool x3;
  SecAccessRef x4;
  SecKeychainRef * x5;
  Py_ssize_t datasize;
  long result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;
  PyObject *arg3;
  PyObject *arg4;
  PyObject *arg5;

  if (!PyArg_ParseTuple(args, "OOOOOO:SecKeychainCreate", &arg0, &arg1, &arg2, &arg3, &arg4, &arg5))
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(12), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(12), arg0) < 0)
      return NULL;
  }

  x1 = _cffi_to_c_int(arg1, uint32_t);
  if (x1 == (uint32_t)-1 && PyErr_Occurred())
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(0), arg2, (char **)&x2);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x2 = alloca(datasize);
    memset((void *)x2, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x2, _cffi_type(0), arg2) < 0)
      return NULL;
  }

  x3 = _cffi_to_c__Bool(arg3);
  if (x3 == (_Bool)-1 && PyErr_Occurred())
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(37), arg4, (char **)&x4);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x4 = alloca(datasize);
    memset((void *)x4, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x4, _cffi_type(37), arg4) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(38), arg5, (char **)&x5);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x5 = alloca(datasize);
    memset((void *)x5, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x5, _cffi_type(38), arg5) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = SecKeychainCreate(x0, x1, x2, x3, x4, x5); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_int(result, long);
}

static PyObject *
_cffi_f_SecKeychainDelete(PyObject *self, PyObject *arg0)
{
  SecKeychainRef x0;
  Py_ssize_t datasize;
  long result;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(34), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(34), arg0) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = SecKeychainDelete(x0); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_int(result, long);
}

static PyObject *
_cffi_f_SecPKCS12Import(PyObject *self, PyObject *args)
{
  void const * x0;
  CFDictionaryRef x1;
  CFArrayRef * x2;
  Py_ssize_t datasize;
  long result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;

  if (!PyArg_ParseTuple(args, "OOO:SecPKCS12Import", &arg0, &arg1, &arg2))
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(0), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(0), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(26), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = alloca(datasize);
    memset((void *)x1, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(26), arg1) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(35), arg2, (char **)&x2);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x2 = alloca(datasize);
    memset((void *)x2, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x2, _cffi_type(35), arg2) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = SecPKCS12Import(x0, x1, x2); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_int(result, long);
}

static PyObject *
_cffi_f_SecSignTransformCreate(PyObject *self, PyObject *args)
{
  SecKeyRef x0;
  CFErrorRef * x1;
  Py_ssize_t datasize;
  SecTransformRef result;
  PyObject *arg0;
  PyObject *arg1;

  if (!PyArg_ParseTuple(args, "OO:SecSignTransformCreate", &arg0, &arg1))
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(29), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(29), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(30), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = alloca(datasize);
    memset((void *)x1, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(30), arg1) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = SecSignTransformCreate(x0, x1); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_pointer((char *)result, _cffi_type(31));
}

static PyObject *
_cffi_f_SecTransformExecute(PyObject *self, PyObject *args)
{
  SecTransformRef x0;
  CFErrorRef * x1;
  Py_ssize_t datasize;
  CFTypeRef result;
  PyObject *arg0;
  PyObject *arg1;

  if (!PyArg_ParseTuple(args, "OO:SecTransformExecute", &arg0, &arg1))
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(31), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(31), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(30), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = alloca(datasize);
    memset((void *)x1, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(30), arg1) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = SecTransformExecute(x0, x1); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_pointer((char *)result, _cffi_type(4));
}

static PyObject *
_cffi_f_SecTransformSetAttribute(PyObject *self, PyObject *args)
{
  SecTransformRef x0;
  CFStringRef x1;
  CFTypeRef x2;
  CFErrorRef * x3;
  Py_ssize_t datasize;
  _Bool result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;
  PyObject *arg3;

  if (!PyArg_ParseTuple(args, "OOOO:SecTransformSetAttribute", &arg0, &arg1, &arg2, &arg3))
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(31), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(31), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(5), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = alloca(datasize);
    memset((void *)x1, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(5), arg1) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(4), arg2, (char **)&x2);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x2 = alloca(datasize);
    memset((void *)x2, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x2, _cffi_type(4), arg2) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(30), arg3, (char **)&x3);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x3 = alloca(datasize);
    memset((void *)x3, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x3, _cffi_type(30), arg3) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = SecTransformSetAttribute(x0, x1, x2, x3); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_int(result, _Bool);
}

static PyObject *
_cffi_f_SecVerifyTransformCreate(PyObject *self, PyObject *args)
{
  SecKeyRef x0;
  void const * x1;
  CFErrorRef * x2;
  Py_ssize_t datasize;
  SecTransformRef result;
  PyObject *arg0;
  PyObject *arg1;
  PyObject *arg2;

  if (!PyArg_ParseTuple(args, "OOO:SecVerifyTransformCreate", &arg0, &arg1, &arg2))
    return NULL;

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(29), arg0, (char **)&x0);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x0 = alloca(datasize);
    memset((void *)x0, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x0, _cffi_type(29), arg0) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(0), arg1, (char **)&x1);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x1 = alloca(datasize);
    memset((void *)x1, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x1, _cffi_type(0), arg1) < 0)
      return NULL;
  }

  datasize = _cffi_prepare_pointer_call_argument(
      _cffi_type(30), arg2, (char **)&x2);
  if (datasize != 0) {
    if (datasize < 0)
      return NULL;
    x2 = alloca(datasize);
    memset((void *)x2, 0, datasize);
    if (_cffi_convert_array_from_object((char *)x2, _cffi_type(30), arg2) < 0)
      return NULL;
  }

  Py_BEGIN_ALLOW_THREADS
  _cffi_restore_errno();
  { result = SecVerifyTransformCreate(x0, x1, x2); }
  _cffi_save_errno();
  Py_END_ALLOW_THREADS

  return _cffi_from_c_pointer((char *)result, _cffi_type(31));
}

static void _cffi_check_struct_CC_MD5state_st(struct CC_MD5state_st *p)
{
  /* only to generate compile-time warnings or errors */
}
static PyObject *
_cffi_layout_struct_CC_MD5state_st(PyObject *self, PyObject *noarg)
{
  struct _cffi_aligncheck { char x; struct CC_MD5state_st y; };
  static Py_ssize_t nums[] = {
    sizeof(struct CC_MD5state_st),
    offsetof(struct _cffi_aligncheck, y),
    -1
  };
  return _cffi_get_struct_layout(nums);
  /* the next line is not executed, but compiled */
  _cffi_check_struct_CC_MD5state_st(0);
}

static void _cffi_check_struct_CC_SHA1state_st(struct CC_SHA1state_st *p)
{
  /* only to generate compile-time warnings or errors */
}
static PyObject *
_cffi_layout_struct_CC_SHA1state_st(PyObject *self, PyObject *noarg)
{
  struct _cffi_aligncheck { char x; struct CC_SHA1state_st y; };
  static Py_ssize_t nums[] = {
    sizeof(struct CC_SHA1state_st),
    offsetof(struct _cffi_aligncheck, y),
    -1
  };
  return _cffi_get_struct_layout(nums);
  /* the next line is not executed, but compiled */
  _cffi_check_struct_CC_SHA1state_st(0);
}

static void _cffi_check_struct_CC_SHA256state_st(struct CC_SHA256state_st *p)
{
  /* only to generate compile-time warnings or errors */
}
static PyObject *
_cffi_layout_struct_CC_SHA256state_st(PyObject *self, PyObject *noarg)
{
  struct _cffi_aligncheck { char x; struct CC_SHA256state_st y; };
  static Py_ssize_t nums[] = {
    sizeof(struct CC_SHA256state_st),
    offsetof(struct _cffi_aligncheck, y),
    -1
  };
  return _cffi_get_struct_layout(nums);
  /* the next line is not executed, but compiled */
  _cffi_check_struct_CC_SHA256state_st(0);
}

static void _cffi_check_struct_CC_SHA512state_st(struct CC_SHA512state_st *p)
{
  /* only to generate compile-time warnings or errors */
}
static PyObject *
_cffi_layout_struct_CC_SHA512state_st(PyObject *self, PyObject *noarg)
{
  struct _cffi_aligncheck { char x; struct CC_SHA512state_st y; };
  static Py_ssize_t nums[] = {
    sizeof(struct CC_SHA512state_st),
    offsetof(struct _cffi_aligncheck, y),
    -1
  };
  return _cffi_get_struct_layout(nums);
  /* the next line is not executed, but compiled */
  _cffi_check_struct_CC_SHA512state_st(0);
}

static int _cffi_var_kSecEncryptKey(PyObject *lib)
{
  PyObject *o;
  int res;
  CFStringRef * i;
  i = (&kSecEncryptKey);
  o = _cffi_from_c_pointer((char *)i, _cffi_type(39));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kSecEncryptKey", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_const_kSecUseKeychain(lib);
}

static int _cffi_var_kSecEncryptionMode(PyObject *lib)
{
  PyObject *o;
  int res;
  CFStringRef * i;
  i = (&kSecEncryptionMode);
  o = _cffi_from_c_pointer((char *)i, _cffi_type(39));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kSecEncryptionMode", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_var_kSecEncryptKey(lib);
}

static int _cffi_var_kSecIVKey(PyObject *lib)
{
  PyObject *o;
  int res;
  CFStringRef * i;
  i = (&kSecIVKey);
  o = _cffi_from_c_pointer((char *)i, _cffi_type(39));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kSecIVKey", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_var_kSecEncryptionMode(lib);
}

static int _cffi_var_kSecImportExportAccess(PyObject *lib)
{
  PyObject *o;
  int res;
  CFStringRef * i;
  i = (&kSecImportExportAccess);
  o = _cffi_from_c_pointer((char *)i, _cffi_type(39));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kSecImportExportAccess", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_var_kSecIVKey(lib);
}

static int _cffi_var_kSecImportExportKeychain(PyObject *lib)
{
  PyObject *o;
  int res;
  CFStringRef * i;
  i = (&kSecImportExportKeychain);
  o = _cffi_from_c_pointer((char *)i, _cffi_type(39));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kSecImportExportKeychain", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_var_kSecImportExportAccess(lib);
}

static int _cffi_var_kSecImportExportPassphrase(PyObject *lib)
{
  PyObject *o;
  int res;
  CFStringRef * i;
  i = (&kSecImportExportPassphrase);
  o = _cffi_from_c_pointer((char *)i, _cffi_type(39));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kSecImportExportPassphrase", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_var_kSecImportExportKeychain(lib);
}

static int _cffi_var_kSecInputIsAttributeName(PyObject *lib)
{
  PyObject *o;
  int res;
  CFStringRef * i;
  i = (&kSecInputIsAttributeName);
  o = _cffi_from_c_pointer((char *)i, _cffi_type(39));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kSecInputIsAttributeName", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_var_kSecImportExportPassphrase(lib);
}

static int _cffi_var_kSecInputIsDigest(PyObject *lib)
{
  PyObject *o;
  int res;
  CFStringRef * i;
  i = (&kSecInputIsDigest);
  o = _cffi_from_c_pointer((char *)i, _cffi_type(39));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kSecInputIsDigest", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_var_kSecInputIsAttributeName(lib);
}

static int _cffi_var_kSecInputIsPlainText(PyObject *lib)
{
  PyObject *o;
  int res;
  CFStringRef * i;
  i = (&kSecInputIsPlainText);
  o = _cffi_from_c_pointer((char *)i, _cffi_type(39));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kSecInputIsPlainText", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_var_kSecInputIsDigest(lib);
}

static int _cffi_var_kSecInputIsRaw(PyObject *lib)
{
  PyObject *o;
  int res;
  CFStringRef * i;
  i = (&kSecInputIsRaw);
  o = _cffi_from_c_pointer((char *)i, _cffi_type(39));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kSecInputIsRaw", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_var_kSecInputIsPlainText(lib);
}

static int _cffi_var_kSecModeCBCKey(PyObject *lib)
{
  PyObject *o;
  int res;
  CFStringRef * i;
  i = (&kSecModeCBCKey);
  o = _cffi_from_c_pointer((char *)i, _cffi_type(39));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kSecModeCBCKey", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_var_kSecInputIsRaw(lib);
}

static int _cffi_var_kSecModeCFBKey(PyObject *lib)
{
  PyObject *o;
  int res;
  CFStringRef * i;
  i = (&kSecModeCFBKey);
  o = _cffi_from_c_pointer((char *)i, _cffi_type(39));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kSecModeCFBKey", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_var_kSecModeCBCKey(lib);
}

static int _cffi_var_kSecModeECBKey(PyObject *lib)
{
  PyObject *o;
  int res;
  CFStringRef * i;
  i = (&kSecModeECBKey);
  o = _cffi_from_c_pointer((char *)i, _cffi_type(39));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kSecModeECBKey", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_var_kSecModeCFBKey(lib);
}

static int _cffi_var_kSecModeNoneKey(PyObject *lib)
{
  PyObject *o;
  int res;
  CFStringRef * i;
  i = (&kSecModeNoneKey);
  o = _cffi_from_c_pointer((char *)i, _cffi_type(39));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kSecModeNoneKey", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_var_kSecModeECBKey(lib);
}

static int _cffi_var_kSecModeOFBKey(PyObject *lib)
{
  PyObject *o;
  int res;
  CFStringRef * i;
  i = (&kSecModeOFBKey);
  o = _cffi_from_c_pointer((char *)i, _cffi_type(39));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kSecModeOFBKey", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_var_kSecModeNoneKey(lib);
}

static int _cffi_var_kSecOAEPEncodingParametersAttributeName(PyObject *lib)
{
  PyObject *o;
  int res;
  CFStringRef * i;
  i = (&kSecOAEPEncodingParametersAttributeName);
  o = _cffi_from_c_pointer((char *)i, _cffi_type(39));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kSecOAEPEncodingParametersAttributeName", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_var_kSecModeOFBKey(lib);
}

static int _cffi_var_kSecPaddingKey(PyObject *lib)
{
  PyObject *o;
  int res;
  CFStringRef * i;
  i = (&kSecPaddingKey);
  o = _cffi_from_c_pointer((char *)i, _cffi_type(39));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kSecPaddingKey", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_var_kSecOAEPEncodingParametersAttributeName(lib);
}

static int _cffi_var_kSecPaddingNoneKey(PyObject *lib)
{
  PyObject *o;
  int res;
  CFStringRef * i;
  i = (&kSecPaddingNoneKey);
  o = _cffi_from_c_pointer((char *)i, _cffi_type(39));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kSecPaddingNoneKey", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_var_kSecPaddingKey(lib);
}

static int _cffi_var_kSecPaddingOAEPKey(PyObject *lib)
{
  PyObject *o;
  int res;
  CFStringRef * i;
  i = (&kSecPaddingOAEPKey);
  o = _cffi_from_c_pointer((char *)i, _cffi_type(39));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kSecPaddingOAEPKey", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_var_kSecPaddingNoneKey(lib);
}

static int _cffi_var_kSecPaddingPKCS1Key(PyObject *lib)
{
  PyObject *o;
  int res;
  CFStringRef * i;
  i = (&kSecPaddingPKCS1Key);
  o = _cffi_from_c_pointer((char *)i, _cffi_type(39));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kSecPaddingPKCS1Key", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_var_kSecPaddingOAEPKey(lib);
}

static int _cffi_var_kSecPaddingPKCS5Key(PyObject *lib)
{
  PyObject *o;
  int res;
  CFStringRef * i;
  i = (&kSecPaddingPKCS5Key);
  o = _cffi_from_c_pointer((char *)i, _cffi_type(39));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kSecPaddingPKCS5Key", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_var_kSecPaddingPKCS1Key(lib);
}

static int _cffi_var_kSecPaddingPKCS7Key(PyObject *lib)
{
  PyObject *o;
  int res;
  CFStringRef * i;
  i = (&kSecPaddingPKCS7Key);
  o = _cffi_from_c_pointer((char *)i, _cffi_type(39));
  if (o == NULL)
    return -1;
  res = PyObject_SetAttrString(lib, "kSecPaddingPKCS7Key", o);
  Py_DECREF(o);
  if (res < 0)
    return -1;
  return _cffi_var_kSecPaddingPKCS5Key(lib);
}

static int _cffi_setup_custom(PyObject *lib)
{
  return _cffi_var_kSecPaddingPKCS7Key(lib);
}

static PyMethodDef _cffi_methods[] = {
  {"_cffi_layout__CCHmacContext", _cffi_layout__CCHmacContext, METH_NOARGS},
  {"_cffi_layout__CFDictionaryKeyCallBacks", _cffi_layout__CFDictionaryKeyCallBacks, METH_NOARGS},
  {"_cffi_layout__CFDictionaryValueCallBacks", _cffi_layout__CFDictionaryValueCallBacks, METH_NOARGS},
  {"_cffi_layout__CFRange", _cffi_layout__CFRange, METH_NOARGS},
  {"_cffi_layout__SecItemImportExportKeyParameters", _cffi_layout__SecItemImportExportKeyParameters, METH_NOARGS},
  {"CCCalibratePBKDF", _cffi_f_CCCalibratePBKDF, METH_VARARGS},
  {"CCCryptorCreate", _cffi_f_CCCryptorCreate, METH_VARARGS},
  {"CCCryptorCreateWithMode", _cffi_f_CCCryptorCreateWithMode, METH_VARARGS},
  {"CCCryptorFinal", _cffi_f_CCCryptorFinal, METH_VARARGS},
  {"CCCryptorGCMAddAAD", _cffi_f_CCCryptorGCMAddAAD, METH_VARARGS},
  {"CCCryptorGCMAddIV", _cffi_f_CCCryptorGCMAddIV, METH_VARARGS},
  {"CCCryptorGCMDecrypt", _cffi_f_CCCryptorGCMDecrypt, METH_VARARGS},
  {"CCCryptorGCMEncrypt", _cffi_f_CCCryptorGCMEncrypt, METH_VARARGS},
  {"CCCryptorGCMFinal", _cffi_f_CCCryptorGCMFinal, METH_VARARGS},
  {"CCCryptorGCMReset", _cffi_f_CCCryptorGCMReset, METH_O},
  {"CCCryptorRelease", _cffi_f_CCCryptorRelease, METH_O},
  {"CCCryptorUpdate", _cffi_f_CCCryptorUpdate, METH_VARARGS},
  {"CCHmacFinal", _cffi_f_CCHmacFinal, METH_VARARGS},
  {"CCHmacInit", _cffi_f_CCHmacInit, METH_VARARGS},
  {"CCHmacUpdate", _cffi_f_CCHmacUpdate, METH_VARARGS},
  {"CCKeyDerivationPBKDF", _cffi_f_CCKeyDerivationPBKDF, METH_VARARGS},
  {"CC_MD5_Final", _cffi_f_CC_MD5_Final, METH_VARARGS},
  {"CC_MD5_Init", _cffi_f_CC_MD5_Init, METH_O},
  {"CC_MD5_Update", _cffi_f_CC_MD5_Update, METH_VARARGS},
  {"CC_SHA1_Final", _cffi_f_CC_SHA1_Final, METH_VARARGS},
  {"CC_SHA1_Init", _cffi_f_CC_SHA1_Init, METH_O},
  {"CC_SHA1_Update", _cffi_f_CC_SHA1_Update, METH_VARARGS},
  {"CC_SHA224_Final", _cffi_f_CC_SHA224_Final, METH_VARARGS},
  {"CC_SHA224_Init", _cffi_f_CC_SHA224_Init, METH_O},
  {"CC_SHA224_Update", _cffi_f_CC_SHA224_Update, METH_VARARGS},
  {"CC_SHA256_Final", _cffi_f_CC_SHA256_Final, METH_VARARGS},
  {"CC_SHA256_Init", _cffi_f_CC_SHA256_Init, METH_O},
  {"CC_SHA256_Update", _cffi_f_CC_SHA256_Update, METH_VARARGS},
  {"CC_SHA384_Final", _cffi_f_CC_SHA384_Final, METH_VARARGS},
  {"CC_SHA384_Init", _cffi_f_CC_SHA384_Init, METH_O},
  {"CC_SHA384_Update", _cffi_f_CC_SHA384_Update, METH_VARARGS},
  {"CC_SHA512_Final", _cffi_f_CC_SHA512_Final, METH_VARARGS},
  {"CC_SHA512_Init", _cffi_f_CC_SHA512_Init, METH_O},
  {"CC_SHA512_Update", _cffi_f_CC_SHA512_Update, METH_VARARGS},
  {"CFArrayGetCount", _cffi_f_CFArrayGetCount, METH_O},
  {"CFArrayGetValueAtIndex", _cffi_f_CFArrayGetValueAtIndex, METH_VARARGS},
  {"CFBooleanGetValue", _cffi_f_CFBooleanGetValue, METH_O},
  {"CFDataCreate", _cffi_f_CFDataCreate, METH_VARARGS},
  {"CFDataGetBytes", _cffi_f_CFDataGetBytes, METH_VARARGS},
  {"CFDataGetLength", _cffi_f_CFDataGetLength, METH_O},
  {"CFDictionaryCreate", _cffi_f_CFDictionaryCreate, METH_VARARGS},
  {"CFDictionaryCreateMutable", _cffi_f_CFDictionaryCreateMutable, METH_VARARGS},
  {"CFDictionarySetValue", _cffi_f_CFDictionarySetValue, METH_VARARGS},
  {"CFNumberCreate", _cffi_f_CFNumberCreate, METH_VARARGS},
  {"CFRangeMake", _cffi_f_CFRangeMake, METH_VARARGS},
  {"CFRelease", _cffi_f_CFRelease, METH_O},
  {"CFRetain", _cffi_f_CFRetain, METH_O},
  {"CFShow", _cffi_f_CFShow, METH_O},
  {"CFStringCreateWithCString", _cffi_f_CFStringCreateWithCString, METH_VARARGS},
  {"SecDecryptTransformCreate", _cffi_f_SecDecryptTransformCreate, METH_VARARGS},
  {"SecEncryptTransformCreate", _cffi_f_SecEncryptTransformCreate, METH_VARARGS},
  {"SecItemImport", _cffi_f_SecItemImport, METH_VARARGS},
  {"SecKeyGeneratePair", _cffi_f_SecKeyGeneratePair, METH_VARARGS},
  {"SecKeyGetBlockSize", _cffi_f_SecKeyGetBlockSize, METH_O},
  {"SecKeychainCreate", _cffi_f_SecKeychainCreate, METH_VARARGS},
  {"SecKeychainDelete", _cffi_f_SecKeychainDelete, METH_O},
  {"SecPKCS12Import", _cffi_f_SecPKCS12Import, METH_VARARGS},
  {"SecSignTransformCreate", _cffi_f_SecSignTransformCreate, METH_VARARGS},
  {"SecTransformExecute", _cffi_f_SecTransformExecute, METH_VARARGS},
  {"SecTransformSetAttribute", _cffi_f_SecTransformSetAttribute, METH_VARARGS},
  {"SecVerifyTransformCreate", _cffi_f_SecVerifyTransformCreate, METH_VARARGS},
  {"_cffi_layout_struct_CC_MD5state_st", _cffi_layout_struct_CC_MD5state_st, METH_NOARGS},
  {"_cffi_layout_struct_CC_SHA1state_st", _cffi_layout_struct_CC_SHA1state_st, METH_NOARGS},
  {"_cffi_layout_struct_CC_SHA256state_st", _cffi_layout_struct_CC_SHA256state_st, METH_NOARGS},
  {"_cffi_layout_struct_CC_SHA512state_st", _cffi_layout_struct_CC_SHA512state_st, METH_NOARGS},
  {"_cffi_setup", _cffi_setup, METH_VARARGS},
  {NULL, NULL}    /* Sentinel */
};

PyMODINIT_FUNC
init_Cryptography_cffi_d62b3d91x972e1c0b(void)
{
  PyObject *lib;
  lib = Py_InitModule("_Cryptography_cffi_d62b3d91x972e1c0b", _cffi_methods);
  if (lib == NULL || 0 < 0)
    return;
  _cffi_init();
  return;
}
