/*
 *  TurnServer - TURN server implementation.
 *  Copyright (C) 2008-2013 Sebastien Vincent <sebastien.vincent@turnserver.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL.  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so.  If you
 *  do not wish to do so, delete this exception statement from your
 *  version.  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

/*
 * Copyright (C) 2006-2013 Sebastien Vincent.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/**
 * \file util_sys.h
 * \brief Some helper system functions.
 * \author Sebastien Vincent
 * \date 2006-2013
 */

#ifndef VSUTILS_UTIL_SYS
#define VSUTILS_UTIL_SYS

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include <stdint.h>

#ifndef _MSC_VER
#include <sys/types.h>
#else
typedef int mode_t;
typedef int ssize_t;
typedef int pid_t;
#define inline __inline
#endif

#if defined(_WIN32) || defined(_WIN64)
/* some unix types are not defined for Windows
 * (even with MinGW) so declare it here
 */
typedef int socklen_t;
typedef int uid_t;
typedef int gid_t;
#endif

/**
 * \def SYS_MAX
 * \brief Maximum number of the two arguments.
 */
#define SYS_MAX(a, b) ((a) > (b) ? (a) : (b))

/**
 * \def SYS_MIN
 * \brief Minimum number of the two arguments.
 */
#define SYS_MIN(a, b) ((a) < (b) ? (a) : (b))

#ifdef __cplusplus
extern "C"
{ /* } */
#endif

/**
 * \brief Sleep for usec microseconds.
 * \param usec number of microseconds.
 * \return 0 if success, -1 otherwise.
 */
int sys_microsleep(unsigned long usec);

/**
 * \brief The getdtablesize() function returning the limit of open file per
 * process. It is not defined by POSIX standard so define it here.
 * \return limit of open files per process.
 */
long sys_get_dtablesize(void);

/**
 * \brief Return if host machine is big endian.
 * \return 1 if big endian.
 */
int sys_is_big_endian(void);

/**
 * \brief Return if host machine is little endian.
 * \return 1 if little endian, 0 otherwise.
 */
int sys_is_little_endian(void);

/**
 * \brief Return the error which correspond to errnum.
 * \param errnum error number (i.e errno).
 * \param buf a buffer.
 * \param buflen size of buffer.
 * \return pointer on buf.
 * \note This function use strerror_r if available, and assume strerror() is
 * reentrant on systems which do not have strerror_r().
 * \warning If you do a multithreaded program, be sure strerror_r() is available
 * or strerror() is reentrant on your system.
 */
char* sys_get_error(int errnum, char* buf, size_t buflen);

/**
 * \brief Go in daemon mode.
 * \param dir change directory to this, default is /.
 * \param mask to fix permission: mask & 0777, default is 0.
 * \param cleanup cleanup function, if not NULL it is executed before father
 * _exit().
 * \param arg argument of cleanup function.
 * \return -1 if error.\n
 * In case of father, this function never returns (_exit).\n
 * If success 0 is returned in case of child.
 */
int sys_go_daemon(const char* dir, mode_t mask, void (*cleanup)(void* arg),
    void* arg);

/**
 * \brief Drop privileges.
 *
 * If the program is executed by setuid-root and the user_name
 * is NULL, change privileges to the real UID / GID.
 * Otherwise change privileges to the user_name account.
 * \param uid_real the real UID of the user.
 * \param gid_real the real GID of the user.
 * \param uid_eff the effective UID of the user.
 * \param gid_eff the effective GID of the user.
 * \param user_name user name of the account to witch.
 * \return 0 if success, -1 otherwise.
 * \note Should work on POSIX and *BSD systems.
 */
int sys_drop_privileges(uid_t uid_real, gid_t gid_real, uid_t uid_eff,
    gid_t gid_eff, const char* user_name);

/**
 * \brief Gain lost privileges.
 * \param uid_eff the effective UID of the user.
 * \param gid_eff the effective GID of the user.
 * \return 0 if success, -1 otherwise.
 * \note Should work on POSIX and *BSD systems.
 */
int sys_gain_privileges(uid_t uid_eff, gid_t gid_eff);

/**
 * \brief Convert a binary stream into hex value.
 * \param bin binary data.
 * \param bin_len data length.
 * \param hex buffer.
 * \param hex_len length of buffer.
 */
void sys_convert_to_hex(const unsigned char* bin, size_t bin_len,
    unsigned char* hex, size_t hex_len);

/**
 * \brief Convert a ascii stream into 32-bit unsigned integer value.
 * \param data ascii data.
 * \param data_len data length.
 * \param t a 32 bit unsigned integer.
 */
void sys_convert_to_uint32(const unsigned char* data, size_t data_len,
    uint32_t* t);

/**
 * \brief Convert a ascii stream into 64-bit unsigned integer value.
 * \param data ascii data.
 * \param data_len data length.
 * \param t a 64 bit unsigned integer.
 */
void sys_convert_to_uint64(const unsigned char* data, size_t data_len,
    uint64_t* t);

/**
 * \brief Secure version of strncpy.
 * \param dest destination buffer.
 * \param src source buffer to copy.
 * \param n maximum size to copy.
 * \return pointer on dest.
 */
char* sys_s_strncpy(char* dest, const char* src, size_t n);

/**
 * \brief Secure version of snprintf.
 * \param str buffer to copy.
 * \param size maximum size to copy.
 * \param format the format (see printf).
 * \param ... a list of arguments.
 * \return number of character written.
 */
int sys_s_snprintf(char* str, size_t size, const char* format, ...);

/**
 * \brief Secure version of memset that ensure doing its work even if the 
 * compiler aggressively optimizes the code.
 * \param src source pointer.
 * \param c set constant byte to set.
 * \param len length to set.
 * \return pointer to src.
 */
void* sys_s_memset(void* src, int c, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* VSUTILS_UTIL_SYS */

