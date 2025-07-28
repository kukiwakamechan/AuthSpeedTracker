#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <time.h>

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	const char *password;
	const char *rhost = "unknown";
	int retval; 
	
	retval= pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL);

	pam_get_item(pamh, PAM_RHOST, (const void **)&rhost);
	if (!rhost)  {
		rhost = "unknown";
	}

	if (retval != PAM_SUCCESS) {
	}
    
	//時間取得
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
    
	struct tm *tm_info = localtime(&ts.tv_sec);
	char timebuf[64];
	strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%H:%M:%S", tm_info);
    
	FILE *log_file = fopen("/home/kaho/develop/AuthSpeedTracker/log/pamlog/pass.log", "a");
	if (log_file) {
		fprintf(log_file, "IP: %s | Time: %s.%09ld \n", rhost, timebuf, ts.tv_nsec);
		fclose(log_file);
	} else {
		pam_syslog(pamh, LOG_ERR, "Failed to open pass.log");
	}
    
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv){
	return PAM_SUCCESS;
}
