/*
 * pam_check.c — verify a login password against PAM, non-interactively.
 *
 * Usage:   pam_check <user> [service]     password on stdin (one line)
 * Exit:    0 correct | 2 wrong | 3 unknown user | 4 PAM/system error
 *          5 bad usage
 * The password is only ever in this process memory; nothing is logged.
 * Build:   gcc -O2 -Wall -o pam_check pam_check.c -lpam
 * (libpam-dev needed to build; runtime only needs libc + libpam.)
 */
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EXIT_OK 0
#define EXIT_DENIED 2
#define EXIT_NOUSER 3
#define EXIT_PAM_ERR 4
#define EXIT_USAGE 5

static char g_password[1025];

static int conv_fn(int num_msg, const struct pam_message **msg,
                   struct pam_response **resp, void *appdata_ptr)
{
    struct pam_response *arr;
    int i;
    (void)appdata_ptr;
    arr = calloc((size_t)num_msg, sizeof(*arr));
    if (!arr)
        return PAM_BUF_ERR;
    for (i = 0; i < num_msg; i++) {
        if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF ||
            msg[i]->msg_style == PAM_PROMPT_ECHO_ON)
            arr[i].resp = strdup(g_password);
        if (!arr[i].resp &&
            (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF ||
             msg[i]->msg_style == PAM_PROMPT_ECHO_ON)) {
            int j;
            for (j = 0; j < i; j++)
                free(arr[j].resp);
            free(arr);
            return PAM_BUF_ERR;
        }
    }
    *resp = arr; /* libpam frees resp strings and the array */
    return PAM_SUCCESS;
}

int main(int argc, char **argv)
{
    struct pam_conv conv = { conv_fn, NULL };
    pam_handle_t *handle = NULL;
    int rc;

    if (argc < 2 || argc > 3)
        return EXIT_USAGE;
    if (!fgets(g_password, sizeof(g_password), stdin))
        return EXIT_USAGE;
    g_password[strcspn(g_password, "\r\n")] = '\0';
    if (g_password[0] == '\0' || strchr(g_password, ':'))
        return EXIT_USAGE;
    if (argv[1][0] == '\0' || strchr(argv[1], ':'))
        return EXIT_USAGE;

    rc = pam_start(argc == 3 ? argv[2] : "sudo", argv[1], &conv, &handle);
    if (rc != PAM_SUCCESS || !handle)
        return EXIT_PAM_ERR;
    rc = pam_authenticate(handle, 0);
    pam_end(handle, rc);

    if (rc == PAM_SUCCESS)
        return EXIT_OK;
    if (rc == PAM_AUTH_ERR || rc == PAM_MAXTRIES)
        return EXIT_DENIED;
    if (rc == PAM_USER_UNKNOWN)
        return EXIT_NOUSER;
    return EXIT_PAM_ERR;
}
