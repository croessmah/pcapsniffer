#pragma once
#ifndef SNIFFER_SNIFFER_H
#define SNIFFER_SNIFFER_H
#include <stdint.h>


#ifdef BUILDING_SNIFFER_LIBRARY
#define DLL_EXPORT __declspec(dllexport)
#else
#define DLL_EXPORT __declspec(dllimport)
#endif //BUILDING_SNIFFER_LIBRARY


#ifdef __cplusplus
//C++ compiller
extern "C" {
#else
//not C++ compiller
#endif //__cplusplus


typedef struct sniffer sniffer_t;

enum eSnifferErrors
{
    eSE_SUCCESS,
    eSE_DEVICE_FIND_FAILED,
    eSE_INTERFACE_NOT_FOUND,
    eSE_OPEN_DEVICE_FAILURE,
    eSE_INVALID_ARGUMENT,
    eSE_CAPTURE_ERROR,
    eSE_MEMORY_ALLOCATE_ERROR
};


typedef void(*sniffer_callback)(unsigned char const * buffer, unsigned size, void * user_data);


DLL_EXPORT
struct sniffer *
sniffer_create(
    uint32_t if_ip
);


DLL_EXPORT
struct sniffer *
sniffer_destroy(
    struct sniffer * sniffer
);


DLL_EXPORT
struct sniffer *
sniffer_start(
    struct sniffer * sniffer,
    sniffer_callback callback,
    void * data
);


DLL_EXPORT
void
sniffer_stop(
    struct sniffer * sniffer
);


DLL_EXPORT
char const *
sniffer_error_message(
    struct sniffer * sniffer
);


DLL_EXPORT
int
sniffer_error_code(
    struct sniffer * sniffer
);


DLL_EXPORT
int
sniffer_current_device_name(
    struct sniffer * sniffer,
    char * destination,
    unsigned size
);


#ifdef __cplusplus
}
#endif //__cplusplus


#undef DLL_EXPORT

#endif //SNIFFER_SNIFFER_H
